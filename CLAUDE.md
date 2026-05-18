# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## What this is

A single-file Python CLI (`claude-approval-report.py`) that analyzes Claude Code session transcripts (`~/.claude/projects/**/*.jsonl`) to report which tool calls required user approval, which were rejected, and what allowlist patterns would reduce friction. It also classifies every tool call by risk level and detects secret/key exposure.

## Running

```bash
python3 claude-approval-report.py              # full report to stdout
python3 claude-approval-report.py --summary    # compact dashboard
python3 claude-approval-report.py --why "git push"  # diagnose a specific command
python3 claude-approval-report.py --apply --dry-run  # preview allowlist changes
python3 claude-approval-report.py --apply --auto     # auto-apply read-only patterns (no prompt)
python3 claude-approval-report.py --apply mutating --min-approvals 10  # mutating, 10+ approvals
python3 claude-approval-report.py --json --since 7d --project laima  # filtered JSON
python3 claude-approval-report.py --generate-settings  # deny rules + hook config
python3 claude-approval-report.py --trend              # daily trend, all time
python3 claude-approval-report.py --trend 7d           # daily trend, last 7 days
python3 claude-approval-report.py --trend 90d          # auto-picks weekly buckets
python3 claude-approval-report.py --trend 30d --bucket week  # override auto bucket
python3 claude-approval-report.py --trend --bucket quarter   # quarterly, all time
python3 claude-approval-report.py --session current --summary  # latest session only
python3 claude-approval-report.py --warns              # hook warning events + user decisions
python3 claude-approval-report.py --warns --since 7d   # warns from the last week
python3 claude-approval-report.py --token-report       # token-consumption optimization report
python3 claude-approval-report.py --token-report-json --token-top 10  # JSON, top 10
python3 claude-approval-report.py -o           # write to auto-named timestamped file
```

No dependencies beyond Python 3.11+ stdlib. Test suites: `tests/test_report.py` (395 tests for the main script's pure functions), `hooks/test_block_secrets.py` (67 tests), `hooks/test_bypass_fixes.py` (110 tests), `hooks/test_round2_bypass_fixes.py` (50 tests), `hooks/test_round3_bypass_fixes.py` (82 tests), `hooks/test_analysis_fixes.py` (68 tests), `hooks/test_fp_fixes.py` (28 tests), `hooks/test_infra_usability.py` (139 tests), `hooks/test_warn_secrets.py` (15 tests), `hooks/test_warn_mode.py` (30 tests), `hooks/test_warn_output_adversarial.py` (48 tests), `hooks/test_phase1_audit_fixes.py` (31 tests), `hooks/test_round4_bypass_fixes.py` (26 tests), `hooks/test_phase3_audit_fixes.py` (20 tests), `scripts/check-pattern-sync.py` (10 checks) — 1119 total.

## Architecture

Everything lives in `claude-approval-report.py`. The processing pipeline:

1. **Allowlist loading** — reads `~/.claude/settings.json` (global) and per-project `settings.local.json` / `settings.json` to know which patterns are already auto-allowed
2. **Session parsing** (`process_session`) — reads JSONL files (using `**/*.jsonl` recursive glob to include subagent transcripts), correlates assistant tool_use blocks with user result records via `sourceToolAssistantUUID`/`toolUseID`, determines approval/rejection status
3. **Risk classification** (`classify_risk`) — categorizes each tool call as destructive/mutating/read-only. Bash commands get sub-command-aware logic for git, curl, find, sed, ansible-playbook. Secret detection runs 22 provider-specific token regexes plus Shannon entropy on base64 blobs (primary >= 3.5 threshold plus secondary unique-char-ratio check for 3.0-3.5 range to catch padding evasion)
4. **Command normalization** (`normalize_command`) — groups variants (e.g., all `git add` invocations, all `ssh` to the same host) for aggregation
5. **Token accounting** (`attribute_tool_result_tokens`, `annotate_next_turn_output`, `extract_user_prose`) — captures per-turn `usage` from assistant messages and attributes next-turn `cache_creation_input_tokens` proportionally to prior-turn tool_use blocks weighted by `result_bytes`, capped at `result_bytes/3`. Records get `_input_target`, `_result_bytes`, `_result_tokens_est`, `_token_estimate_method`, `_turn_uuid`, `_turn_index`, `_next_turn_output_tokens`. Used by the token-report detectors.
6. **Rendering** — nine output modes: full tables (`render_report`), compact dashboard (`render_summary`), JSON (`render_json`), single-command lookup (`render_why`), security settings generation (`render_generate_settings`), time-series trend (`render_trend`), hook warning audit (`render_warns`), token-consumption report (`render_token_report` / `render_token_report_json`)
7. **Apply** (`apply_suggestions`) — writes suggested patterns to project `settings.local.json` files
8. **Generate settings** (`render_generate_settings`) — emits deny rules + hook config as a mergeable JSON fragment, with data-driven analysis of actual secret exposures via `_find_secret_exposures`

## Token-consumption report (`--token-report`, `--token-report-json`)

Four detectors run over the parsed records + user prose, then are ranked by `occurrences * avg_tokens * stability_factor`:

- `find_repeated_reads` — Pattern A (Read/WebFetch targets across sessions)
- `find_recipe_ngrams` — Pattern B (recurring tool-call sequences, n ∈ {3,4,5}, idle-gap segmented at 10 min)
- `find_repeated_prose` — Pattern C (repeated paragraphs the user pastes into prompts)
- `find_resummarized_outputs` — Pattern D (≥8KB tool outputs followed by tiny next-turn output)

`compute_stability_factor(target, kind)` returns a value in `[0.1, 1.0]` — local files via `git log --follow --since="180 days ago"` (with 2s timeout + `lru_cache`), URLs always 0.7, recipes and prose always 1.0. Volatile files (>30 commits in window) are discounted 10×, so reference docs aren't recommended for moving targets. Per-finding suggestions: `reference_md` / `reference_md_external` / `slash_command` / `skill` / `claude_md_addition` / `wrapper_script`. Mode is read-only — no files are written. See `docs/cli-reference.md` for flag details and JSON schema.

Key design choices:
- `HOME_SLUG` is dynamically computed from `Path.home()` (e.g., `-home-terrabot` on this system) and maps between Claude's project directory names and actual filesystem paths. `project_settings_path` handles slug-to-path resolution including dot-to-dash normalization.
- Secret detection is intentionally aggressive — false positives are preferred over missed secrets. Grep-family commands are excluded from secret scanning since they search *for* patterns rather than *using* them.
- `suggest_pattern_applicable` returns a single pattern safe for JSON (choosing the second option from "or" suggestions like SSH patterns).

## PreToolUse hook (`hooks/block-secrets.py`)

A self-contained Python hook (no imports from the main script) that blocks tool calls containing secrets before execution. Uses the same 22 token regex patterns as the report script, duplicated intentionally so the hook works standalone when installed at `~/.claude/hooks/`. Blocks via exit code 2 (stderr shown to user). The `_GREP_FAMILY` exclusion set is a superset of the main script's approach — the hook additionally includes `sed` and `awk` to reduce false positives on stream-editing commands, while the main script's grep-family set does not include them.

The hook covers gaps that deny rules cannot:
1. Secrets embedded in Bash commands (`VAULT_TOKEN=hvs.xxx vault kv get`)
2. Sensitive file reads via Bash (`cat .env`) that bypass Read tool deny rules
3. Bypass vectors: subshell wrapping (`bash -c`), `eval`, interpreter file I/O (`python3 -c "open('.env')"`), file copy/move/link (`cp .env /tmp/x`), `dd if=`, stdin redirection (`< .env`), process substitution (`<()`), heredoc-to-interpreter, backtick substitution, pipe-to-shell (`echo cmd | bash`), subshell/brace grouping (`(cmd)`, `{ cmd; }`), variable assignment tracking, SSH remote commands, `xargs -a`/`--arg-file`, long-form file flags (`--from-file=`, `--files0-from=`), 45+ file-reading tools

Operational features: `HOOK_DEBUG=1` emits debug trace to stderr (tool routing, pattern matches, entropy scores, sensitive path checks). Audit logging is enabled by default (`HOOK_AUDIT=1`) and writes structured JSONL records to `~/.claude/hook-audit.jsonl` (timestamp, decision, tool, summary, reason, command). Set `HOOK_AUDIT=0` to disable. Debug is zero-cost when disabled. Fail-closed design: unknown tool types are blocked, malformed input is blocked. The `--warns` flag on the report script cross-references audit warn events with session data to show user approval decisions.

Warn-level confidence grading: `_classify_leak_confidence()` estimates whether a runtime-expanded secret is likely to appear in output. Commands with `echo`/`printf` get "high" confidence ("likely to expose"), while auth headers, password flags, and commands with `/dev/null` suppression get "low" ("may expose"). Confidence is recorded in the audit log for PostToolUse correlation.

## PostToolUse hook (`hooks/warn-secrets-output.py`)

A self-contained PostToolUse hook that scans tool output for leaked secrets (known token patterns, JWTs, private key headers). Cannot prevent the leak but emits `decision: "block"` with a warning to avoid using the values and advise credential rotation. Scans Bash command output, Read tool output, and Edit tool output. Exempts only known project script basenames (validated via `_is_exempt_command()` with `_EXEMPT_SCRIPT_NAMES` frozenset), project documentation files (via `_EXEMPT_READ_TARGETS` regex), and test file output (via `_RE_TEST_FILE_PATH` with path prefix validation). Grep-family and git diff/log/show output are now scanned for token patterns (blanket exemptions removed 2026-05-10).

PreToolUse correlation (`HOOK_CORRELATE=1`, on by default): after standard pattern scanning, reads recent warn entries from the PreToolUse audit log, extracts flagged variable names, and checks command output for high-entropy strings that could be expanded secret values. Triggers a stronger warning when a secret that was flagged before execution appears in output. Set `HOOK_CORRELATE=0` to disable.

## Reference settings (`settings/recommended-deny.json`)

10 safe-to-allow patterns (read-only Bash builtins + the built-in `Grep` tool), 60 deny patterns for Read/Write/Edit, plus a hook config template. The `BASELINE_SAFE_ALLOW` and `BASELINE_DENY_RULES` lists in the main script mirror this file and should be kept in sync.

## Documentation (`docs/`)

- **`cli-reference.md`** — full CLI flag documentation with all modes, filters, and examples
- **`hooks.md`** — hook detection reference with categorized tables of what is caught, allowed, and undetectable
- **`example-reports.md`** — real output samples from trend, summary, and secrets modes
- **`architecture.md`** — reference architecture showing how deny rules, the hook, and MCP servers form a layered defense, with homelab deployment diagrams and adaptation instructions
- **`auth-best-practices.md`** — index and quick reference for working with authenticated services when the hook and deny rules are active. Links to per-service guides:
  - `auth-vault.md`, `auth-api-services.md`, `auth-ansible.md`, `auth-ssh.md`, `auth-env-vars.md`, `auth-diskless-secrets.md`

Reference these docs when adding new secret patterns or modifying detection logic to ensure the documented workarounds remain valid.

## CI/CD (`scripts/ci-test-runner.py`, `.forgejo/workflows/`)

Two Forgejo Actions workflows run on push to `main` and on PRs:

1. **`test.yml`** — runs all 15 test suites (1119 tests). Results uploaded to DefectDojo as "Generic Findings Import" under engagement "CI Tests". Clean runs auto-close previous findings via `close_old_findings=true`.

2. **`security-scan.yml`** — runs gitleaks (secret detection), semgrep (Python SAST), and trivy (filesystem vuln scan). Each scanner's native JSON output is uploaded to DefectDojo under engagement "Security Scans" using the scanner-specific import type. Gitleaks failures block the build; semgrep/trivy are informational. Test files are allowlisted in `.gitleaks.toml` to avoid false positives on intentional test fixture patterns.

Both use `node:22-slim` image on the `docker` runner label. Product: `autoclaude`, Product Type: `Inspicere Projects`. The `DEFECTDOJO_API_TOKEN` secret is configured on the Forgejo repo. Scanner versions are pinned with SHA256 verification.

## Security hardening history

The hooks and main script have been through multiple rounds of adversarial review and structured audits. Resolved findings are archived under `docs/history/` so they don't bloat this file:

| Engagement | Date | Outcome | Archive |
|---|---|---|---|
| Adversarial audit (32 bypass vectors + 22 quality issues) | 2026-05-07 | All resolved | [`docs/history/audit-2026-05-07.md`](docs/history/audit-2026-05-07.md) |
| Red team rounds 1-2 (7 + 15 bypass classes, 10 agents) | 2026-05-08 | All fixable resolved | [`docs/history/red-team-2026-05-08.md`](docs/history/red-team-2026-05-08.md) |
| Red team round 3 (10 confirmed + 25 analysis-only) | 2026-05-10 | All confirmed fixed | [`docs/history/red-team-2026-05-10.md`](docs/history/red-team-2026-05-10.md) |
| 12-dimension project audit (2 H, 11 M, 13 L, 7 I) | 2026-05-16 | 13/14 closed | [`docs/history/audit-2026-05-16.md`](docs/history/audit-2026-05-16.md) |

Read the archives when planning new bypass-prevention work — every round teaches a pattern of attack the static analyzer didn't anticipate. Architectural gaps that remain unfixable by static analysis (shell function indirection, bash array expansion, runtime path construction, generic write-then-execute, symlink TOCTOU, MCP passthrough) are documented in [`docs/hooks.md`](docs/hooks.md). The Landlock sandbox prototype at `hooks/landlock-sandbox.py` addresses these at the kernel level.
