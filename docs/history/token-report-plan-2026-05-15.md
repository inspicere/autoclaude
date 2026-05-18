# Token-Consumption Optimization Analyzer — Implementation Plan

Status: Phase 1, 2, 3 COMPLETE — Phase 4 (renderers) next
Created: 2026-05-15
Updated: 2026-05-15
Owner: terrabot
Target file: `claude-approval-report.py` (single-file constraint preserved)

## 0. Design summary

Add a new analyzer mode `--token-report` (text) and `--token-report-json` (machine-readable) that ranks opportunities to reduce per-session token usage. It detects four patterns (repeated reads, repeated tool-call recipes, repeated user prose, large outputs that get re-summarized), discounts each by churn (so we don't recommend baking in volatile content), and emits a remediation suggestion (skill / slash command / CLAUDE.md addition / `.md` reference stub). It plugs into the existing pipeline at three points:

1. **Parsing** — extend `process_session` to also collect token-attribution data and user-prose blocks. Reuse `normalize_command`, `get_tool_display`, `_parse_ts`.
2. **Aggregation** — new pure module of functions on the records list (matches the existing pattern of pure functions tested in `tests/test_report.py`).
3. **Rendering** — new `render_token_report` and `render_token_report_json` functions, sibling to `render_trend` / `render_secrets`.

Architectural rule: **all new logic lives in `claude-approval-report.py`** (single-file constraint) and is pure-function-friendly so it can be unit tested without session fixtures.

---

## 1. Token accounting strategy (the trickiest part)

The `usage` block lives on the **assistant** record, *not* on the tool call. One assistant turn can fire 1..N tool_use blocks in parallel and reports a single `usage`. Strict per-tool attribution is therefore impossible; we must *estimate*. The plan uses a layered approach:

**A. Turn-level totals (authoritative).** For each assistant message, capture:
- `input_tokens`, `cache_read_input_tokens`, `cache_creation_input_tokens`, `output_tokens`
- "billable input" = `input_tokens + cache_creation_input_tokens` (cache reads are 10% cost; we keep them as a separate column so users can see cache effectiveness)

**B. Output-side attribution for tool results (next-turn delta).** The tokens a tool result *adds to the next turn's input* are the user-visible "cost" of that tool call. Strategy:
1. Sort assistant turns by timestamp within a session.
2. For turn N+1, compute `cache_creation_input_tokens` (new cacheable content added since N). Attribute that delta proportionally across the tool_use blocks that fired in turn N, weighted by the byte size of each tool_result's `stdout`/`content`.
3. Store an estimated `result_tokens` per record. Use `len(text) / 4` as a fallback estimator when no usage delta is available (last turn, malformed sessions). Mark fallback estimates with `_token_estimate_method = "char_div_4"` vs `"usage_delta"` so the UI can show a confidence flag.

**C. Output byte size (always available).** Record `result_bytes = len(stdout) + len(stderr)` (or `len(content)` for Read/WebFetch) regardless of token estimation success. This is the rock-solid fallback for ranking.

Outcome per record (added to the dict already returned by `process_session`):
- `_input_target` (file path, URL, or normalized command)
- `_result_bytes`
- `_result_tokens_est` (int)
- `_token_estimate_method` (`"usage_delta"` / `"char_div_4"`)
- `_turn_uuid`, `_turn_index` (so n-gram and recipe detection can sequence)
- `_user_prose` (only on the **user** record that *preceded* the assistant turn — captured separately, see §3)

**Decision:** ranking formula uses `result_tokens_est` when available, else `result_bytes / 4`. Always show both columns in the report.

---

## 2. Pattern detectors

### 2.1 Repeated file/URL reads (Pattern A)
- Group records where `tool_name in {"Read", "WebFetch"}` by normalized target:
  - Read: shorten via `shorten_path` then strip line ranges (`offset`/`limit`).
  - WebFetch: strip query strings + fragments, lowercase host.
- For each target compute: `occurrences`, `distinct_sessions`, `sum_tokens`, `avg_tokens`, `last_seen`.
- Threshold: `distinct_sessions >= 3` AND `sum_tokens >= 5_000`. Configurable via `--token-min-sessions` / `--token-min-tokens`.

### 2.2 Repeated tool-call recipes (Pattern B)
- Build a per-session sequence of `normalize_command(...)` (Bash) / `tool_name + ":" + suffix` for non-Bash, with idle-gap segmentation: split sequences when timestamp gap > 10 minutes (avoids merging unrelated work).
- Slide n-grams of size **n ∈ {3, 4, 5}**. Larger windows are more specific (good signal) but rarer — start at 3 and report the longest n-gram that contains each match (suppress sub-grams).
- Normalize each step further: drop arguments after the second token; collapse repeated identical steps (`A,A,A` → `A`).
- Hash the n-gram tuple. Aggregate by hash: `occurrences`, `distinct_sessions`, `total_token_cost = sum(result_tokens_est across the n steps)`.
- Dedupe overlapping shorter n-grams: if a 3-gram is fully contained inside a frequent 4-gram with comparable count (within 20%), drop the 3-gram.
- Threshold: `occurrences >= 5` AND `distinct_sessions >= 2`.
- Risk: false positives from generic recipes (`ls, cat, ls`). Mitigation: ignore n-grams whose distinct-step-count is <= 1, and ignore n-grams composed entirely of `BASELINE_SAFE_ALLOW` commands (already cheap).

### 2.3 Repeated user prose (Pattern C)
- During `process_session`, capture the *user* messages that are NOT tool results: `obj["type"] == "user" and "sourceToolAssistantUUID" not in obj` and `message.content` is a string (or list of `{type:"text"}`).
- Strip leading prompt boilerplate (`<system-reminder>`, `<command-name>` tags).
- Split into paragraphs (>= 200 chars). For each paragraph:
  - Compute SHA256 of normalized text (lowercased, whitespace collapsed, numeric tokens replaced with `<N>`).
  - Bucket by hash; also compute MinHash-lite (5 shingles of 50 chars hashed to 64-bit ints) for **near-duplicate** detection (within-edit-distance variants).
- Aggregate: `occurrences`, `distinct_sessions`, `avg_chars`, `est_tokens = chars / 4`.
- Threshold: `occurrences >= 3` AND `avg_chars >= 400`.

### 2.4 Large outputs that get re-summarized (Pattern D)
- For each record where `result_bytes >= 8_000`, look at the *next* assistant turn's tool calls and *output text*. Detect "narrowing" via two signals:
  1. Next assistant turn's tool calls re-process the same target with grep/jq/head/awk (`pipe-narrowing`).
  2. Next assistant turn's text output is < 25% the size of the tool result it followed (`summarization`).
- Aggregate by `normalize_command(originating_cmd)`. Track `occurrences`, `avg_input_bytes`, `avg_kept_bytes`, `narrow_ratio = avg_kept / avg_input`.
- Threshold: `occurrences >= 3` AND `narrow_ratio < 0.25`.

---

## 3. Stability weighting (was: churn weighting)

> **Implementation note (2026-05-15):** The original plan called this
> `churn_factor` and divided by it. That math actually *boosted* volatile
> items (low factor → small divisor → large score), the opposite of the
> stated intent. Renamed to `stability_factor` and switched to multiplication
> during Phase 3 implementation. Higher stability = safer to bake into a
> reference doc.

A new function `compute_stability_factor(target, kind) -> float` returning a value in `[0.1, 1.0]`:
- **Local files** (path resolves on disk):
  - If under a git tree: `git log --follow --since="180 days ago" --pretty=oneline -- <path> | wc -l`. Cache results per process. Map: 0 commits → 1.0 (stable), 1-3 → 0.8, 4-10 → 0.5, 11-30 → 0.25, >30 → 0.1.
  - If not under git: use `os.stat(path).st_mtime`. Recency under 7 days → 0.5; under 30 days → 0.7; older → 1.0.
  - Missing file → 0.7 (we can't verify; modest discount).
- **URLs** (`http://`, `https://`): always `0.7` and tag the finding `external — verify freshness`. v1 does not fetch.
- **Bash recipes** (Pattern B): always 1.0 (collapsed step tokens don't carry literal file args; future enhancement could re-introspect the underlying records).
- **User prose** (Pattern C): always 1.0 (text the user typed; not a moving target).

Caching: `functools.lru_cache(maxsize=2048)` on the path-keyed helper. Subprocess timeout 2s on `git log`; on timeout, fall back to mtime path. **Never** crash the report when git is unavailable.

**Ranking formula** (per finding):
`score = occurrences * avg_tokens * max(stability_factor, 0.1)`
Sort findings descending by score. Top-N (default 20, configurable via `--token-top N`).

---

## 4. Remediation suggestions

Each finding gets a structured `suggestion` dict:

| Pattern | Suggestion type | Rendered as |
|---|---|---|
| A — repeated read of large doc | `reference_md` or `claude_md_link` | "Add a `.claude/refs/<basename>.md` stub that summarizes key sections; link from CLAUDE.md." |
| A — repeated WebFetch | `reference_md_external` | "Cache a snapshot at `.claude/refs/<host>-<slug>.md`; mark with retrieval date; external content — verify periodically." |
| B — recipe | `slash_command` (if 3 steps) or `skill` (if 5+ steps) | "Create `.claude/commands/<name>.md` containing the normalized recipe; invoke as `/<name>`." |
| C — user prose | `claude_md_addition` | "Add the recurring block to `<project>/CLAUDE.md` under a new H2." |
| D — large output | `wrapper_script` | "Add `scripts/<name>.sh` that pre-narrows the output (e.g. `git log --since=... --author=... --pretty=...`)." |

The plan only **suggests** the remediation; v1 does not write any files (mirrors how `--generate-settings` emits JSON to stdout but `--apply` is a separate, explicit flag).

---

## 5. CLI surface

```bash
python3 claude-approval-report.py --token-report
python3 claude-approval-report.py --token-report --since 30d --project laima
python3 claude-approval-report.py --token-report --token-top 10
python3 claude-approval-report.py --token-report --token-min-sessions 5
python3 claude-approval-report.py --token-report-json | jq '.findings[0]'
```

Compatible with existing `--since`, `--project`, `--session`, `-o/--output`. Mutually exclusive with `--apply`, `--why`, `--trend`, `--summary`, `--secrets`, `--warns`, `--generate-settings` — enforce in `main()` with the same pattern used for the existing exclusivity checks.

---

## 6. Implementation phases

### Phase 1 — Token accounting foundation (no new mode yet)
**Scope:**
- Extend `process_session` to capture `usage` from each assistant message and compute next-turn-delta attribution.
- Add helper `_estimate_tool_result_tokens(records_in_session)` (pure, list in → list out).
- Add `result_bytes`, `_result_tokens_est`, `_token_estimate_method`, `_turn_uuid`, `_turn_index` to record dicts.
- Capture user-prose records (separate list returned alongside tool-call records, or same list with `_kind="prose"`).
- Add `_normalize_read_target`, `_normalize_url` helpers.

**Acceptance:**
- Existing 155 tests still pass (no behavior change to existing fields).
- New test file section "=== Token attribution ===" with ~20 tests covering: char/4 fallback, usage-delta proportional split across 2 parallel tool_use blocks, missing-usage handling, sessions with one assistant turn, unicode/byte-length parity.

### Phase 2 — Detectors (pure functions)
**Scope:**
- `find_repeated_reads(records, min_sessions, min_tokens)` → list[finding]
- `find_recipe_ngrams(records, ns=(3,4,5), min_occurrences, min_sessions)` → list[finding]
- `find_repeated_prose(prose_records, min_occurrences, min_chars)` → list[finding]
- `find_resummarized_outputs(records, min_bytes, max_narrow_ratio)` → list[finding]
- All return a uniform finding dict: `{kind, target, occurrences, distinct_sessions, avg_tokens, sum_tokens, sample_session_ids, _raw}`.

**Acceptance:**
- ~40 unit tests (10 per detector) using hand-built record lists. Mirrors the existing test pattern (no fixtures, just inline dict construction).
- Includes negative cases: single-session-only spam doesn't trigger Pattern A; n-gram of all-`ls` collapses to 1 step and is rejected.

### Phase 3 — Stability weighting
**Scope:**
- `_git_commit_count(path, since_days=180)` with subprocess timeout, lru_cache.
- `compute_stability_factor(target, kind)` dispatching by kind.
- `score_finding(finding, stability_factor)` — multiplicative, not divisive.
- `rank_findings(findings)` — annotates `_stability_factor` + `_score`, sorts.

**Acceptance:**
- Mock `subprocess.run` in tests; verify mapping table, URL → 0.7, missing-file → 0.7, mtime fallback. ~10 tests.
- One integration test: feed two findings (one local stable, one URL), assert ranking order.

### Phase 4 — Renderers
**Scope:**
- `render_token_report(all_records, prose_records, top=20, out=None)` — text table with columns: Rank, Kind, Target (truncated to 60), Occ, Sess, AvgTok, Score, Churn, Suggestion (1-line headline).
- After the table: a "DETAILS" section per top-5 finding with full target, all sample sessions, full suggestion body (the actual `.md` stub or recipe text the user can paste).
- `render_token_report_json(...)` — emits `{generated_at, filters, findings: [...]}` with all fields, suitable for downstream tooling / DefectDojo import.

**Acceptance:**
- Snapshot tests: feed a known fixture → assert exact table header + row count + ordering.
- JSON schema validation test (in-script: assert keys present, types correct).

### Phase 5 — CLI wiring + docs
**Scope:**
- argparse additions in `main()`: `--token-report`, `--token-report-json`, `--token-top`, `--token-min-sessions`, `--token-min-tokens`.
- Mutual-exclusion checks following the existing style.
- `-o/--output` integration following the `render_trend` precedent (auto-named `claude-token-report-<ISO>.txt|.json`).
- Update `docs/cli-reference.md` with a new "### Token report" section.
- Update `CLAUDE.md` Architecture pipeline (add bullet 8 "Token accounting") and the "Running" example block.
- Update `README.md` if it lists modes.

**Acceptance:**
- `--help` shows new flags grouped sensibly.
- Manual smoke test on `~/.claude/projects/-home-terrabot-autoclaude/*.jsonl`.
- All 802 existing tests still green; new tests bring suite to ~880.

---

## 7. Test strategy (matches existing pattern)

The existing `tests/test_report.py` is a flat, top-down script of `check(...)` assertions on **pure functions imported from the module**. New tests follow the exact same pattern:

```
=== Token attribution ===
=== Read target normalization ===
=== Repeated reads detector ===
=== Recipe n-gram detector ===
=== User prose detector ===
=== Re-summarization detector ===
=== Churn factor (mocked git) ===
=== Score formula ===
=== Token report rendering (smoke) ===
```

Detector tests build inline record dicts shaped like what `process_session` produces — no JSONL fixtures needed. Renderer tests use `io.StringIO()` (already used elsewhere in the file) and assert substring presence + row counts rather than full string equality, to stay resilient to formatting tweaks.

CI integration: no changes to `.forgejo/workflows/test.yml` needed — the new tests will be collected automatically since they're in the same file.

---

## 8. Out of scope for v1 (explicit boundaries)

- **Auto-applying suggestions.** No file writes. (A future `--token-apply` could write `.claude/refs/*.md` stubs, but v1 only emits suggested *content* to stdout/JSON.)
- **Automatic skill scaffolding** under `~/.claude/skills/`.
- **Live URL fetching** for churn measurement. URLs are always tagged "external — verify freshness."
- **Cross-project recipe consolidation.** v1 reports recipes per dataset; ranking is global but findings don't yet recommend "make this a global skill vs. project skill."
- **Embedding-based prose similarity.** v1 uses hash + 5-shingle MinHash-lite; no ML deps (Python 3.11 stdlib only constraint).
- **Cost-in-dollars conversion.** Tokens only. Pricing changes; out of scope.
- **Modifying `process_session`'s public contract.** New fields are additive; existing keys unchanged so all 155 existing tests continue to pass without modification.

---

## 9. Risks and mitigations

| Risk | Mitigation |
|---|---|
| **Token attribution wrong for parallel tool_use** (one assistant turn fires 5 tools, only one is large) | Proportional split by `result_bytes`; expose `_token_estimate_method` and surface a "estimate" badge in the report. Document the limitation in `cli-reference.md`. |
| **False-positive recipes** from generic chains (`ls,cat,ls`) | Reject n-grams with distinct-step-count <= 1; reject all-baseline-safe-allow n-grams; require 2+ distinct sessions. |
| **Churn measurement misses recently-deleted files** | `git log --follow` handles renames; if `os.path.exists()` is False, fall back to `git log -- <path>` (history-only). On total miss, stability = 0.7. |
| **Subprocess `git log` slow on huge repos** | 2s timeout per call, lru_cache by path, batched per-finding (not per-record). |
| **Prose detector flags `<system-reminder>` blocks injected by Claude Code itself** | Strip known boilerplate prefixes (`<system-reminder>`, `<command-name>`, `<command-message>`) before hashing; provide a `_PROSE_STRIP_PATTERNS` constant kept near the existing `NOISE_SUFFIXES`. |
| **MinHash-lite collisions on dissimilar prose** | Always confirm a near-duplicate cluster with a final character-level Jaccard >= 0.7 check before merging. |
| **Ranking dominated by one giant outlier** | Show top-N (default 20) with a "+M more" footer; `--token-top` lets users expand. |
| **Memory pressure on multi-GB transcript collections** | Parsing already streams session-by-session; new code holds only normalized findings (small dicts), not raw text. Prose detector keeps only hashes + one canonical exemplar per cluster. |
| **PII in prose findings** | Apply `redact_secrets` to prose snippets before rendering or emitting JSON. |

---

## 10. Sequencing recommendation

Phases 1-2 in one PR (foundation + detectors, no user-visible change). Phase 3 in a follow-up (churn). Phases 4-5 in the third PR (rendering + CLI + docs). Each PR keeps the test suite green and ships independently usable code.

---

## Critical files for implementation

- `claude-approval-report.py` — all detectors, renderers, CLI wiring
- `tests/test_report.py` — append new sections; preserve existing 155 tests
- `docs/cli-reference.md` — new "### Token report" section
- `CLAUDE.md` — add pipeline bullet 8 ("Token accounting") and a `--token-report` example
- `README.md` — add to mode list if applicable
