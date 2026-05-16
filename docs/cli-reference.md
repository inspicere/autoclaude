# CLI Reference

All commands use `python3 claude-approval-report.py`. Python 3.11+, no dependencies.

## Global filters

These compose with any output mode:

```bash
--since 7d          # relative: 7d, 2w, 1m, 3m
--since 2026-05-01  # absolute ISO date
--project laima     # substring match on project name
--session current   # most recent session only
--session 3a7b9c    # match by UUID or partial filename
```

## Output modes

### Default (full report)

```bash
python3 claude-approval-report.py
python3 claude-approval-report.py --since 7d --project laima
```

Renders ranked tables: most prompted commands, most rejected, risk breakdown, destructive approvals, auto-allowed risky commands, suggestions, per-project summary, and tool type breakdown.

### Summary

```bash
python3 claude-approval-report.py --summary
python3 claude-approval-report.py --brief          # alias
```

Compact ~12 line dashboard: call counts, risk breakdown, secret exposure count, top 5 prompted commands, top 3 suggestions.

### Trend

```bash
python3 claude-approval-report.py --trend          # daily, all time
python3 claude-approval-report.py --trend 7d       # daily, last 7 days
python3 claude-approval-report.py --trend 90d      # auto-picks weekly buckets
python3 claude-approval-report.py --trend --bucket quarter
```

Time-series table: Total, Auto, Prompted, Rejected, Auto%, 7-period rolling average, Destructive, Mutating, R/O, Secrets. Directional arrows show period-over-period changes.

Bucket auto-selection: day (<=31d), week (<=90d), month (<=730d), quarter (<=1825d), year (>5y). Override with `--bucket`.

### Secrets

```bash
python3 claude-approval-report.py --secrets
python3 claude-approval-report.py --secrets --since 7d
```

Every flagged command with exposure risk classification:

| Risk | Meaning |
|------|---------|
| EXPOSED | Literal secret in command text, already in transcript and API |
| RUNTIME | Secret fetched via `$()` at execution time, may appear in output |
| VARIABLE | Referenced via `$VAR`, value may be in output but not command text |
| PIPE-SAFE | Secret flows through pipe, never appears in transcript |
| FALSE-POS | Not actually a secret (git hash, SSH public key, test data, non-secret env var, dummy Basic auth) |

### Warns

```bash
python3 claude-approval-report.py --warns
python3 claude-approval-report.py --warns --since 7d
```

Reads `~/.claude/hook-audit.jsonl` for warn events, cross-references session data to show whether the user approved or rejected each flagged command.

### Why (command lookup)

```bash
python3 claude-approval-report.py --why "git push"
python3 claude-approval-report.py --why ssh
```

Shows risk level, prompt/auto/reject counts per project, allowlist status, and the exact pattern to add. Substring match on display name, falls back to full command text.

### Apply

```bash
python3 claude-approval-report.py --apply --dry-run           # preview
python3 claude-approval-report.py --apply                     # read-only patterns, per-project
python3 claude-approval-report.py --apply mutating            # include mutating
python3 claude-approval-report.py --apply --scope global      # patterns in 3+ projects -> global
python3 claude-approval-report.py --apply --scope both        # global + per-project remainder
```

Writes frequently-approved patterns to settings files. Never auto-applies destructive patterns. Shows confirmation prompt unless `--auto` is passed.

| Scope | Writes to | Use case |
|-------|-----------|----------|
| `project` (default) | Each project's `.claude/settings.local.json` | Per-project customization |
| `global` | `~/.claude/settings.json` | Patterns appearing in 3+ projects |
| `both` | Global + per-project remainder | Initial setup |

### Generate settings

```bash
python3 claude-approval-report.py --generate-settings
python3 claude-approval-report.py --generate-settings --since 30d
python3 claude-approval-report.py --generate-settings | jq '.permissions.deny'
```

Outputs JSON with deny rules and hook config ready to merge into `~/.claude/settings.json`. Commentary on stderr shows what's already configured vs. what's new.

### Token report

```bash
python3 claude-approval-report.py --token-report
python3 claude-approval-report.py --token-report --since 30d --project laima
python3 claude-approval-report.py --token-report --token-top 10
python3 claude-approval-report.py --token-report --token-min-sessions 5
python3 claude-approval-report.py --token-report-json | jq '.findings[0]'
python3 claude-approval-report.py --token-report --output /tmp/        # auto-named .txt
python3 claude-approval-report.py --token-report-json --output         # auto-named .json
```

Surfaces opportunities to reduce per-session token consumption by detecting commonly repeated work and suggesting reference docs, slash commands, skills, or wrapper scripts. Read-only — no files are written by this mode.

Four detectors run; findings are ranked by `occurrences * avg_tokens * stability_factor` (stability ∈ [0.1, 1.0], 1.0 = stable, 0.1 = >30 commits in 180 days):

| Detector | Triggers when | Suggestion |
|---|---|---|
| `repeated_read` | Same `Read` target hit in ≥3 sessions with ≥5K total tokens | `.claude/refs/<name>.md` digest, link from CLAUDE.md |
| `repeated_webfetch` | Same URL fetched in ≥3 sessions with ≥5K tokens | Cached `.claude/refs/<host>-<slug>.md` snapshot |
| `recipe_ngram` | Same tool-call sequence (n ∈ {3,4,5}) ≥5 times across ≥2 sessions, idle-gap segmented at 10 min | Slash command (n≤4) or skill (n≥5) |
| `repeated_prose` | User pastes the same paragraph (≥400 chars) ≥3 times across sessions | `CLAUDE.md` addition |
| `resummarized_output` | Tool output ≥8KB followed by an assistant turn whose `output_tokens < 0.25 * result_tokens_est` | Wrapper script under `scripts/` that pre-narrows the output |

**Token attribution.** The `usage` block lives on the assistant message, not per `tool_use`. The analyzer attributes next-turn `cache_creation_input_tokens` proportionally to the prior turn's tool_use blocks weighted by `result_bytes`, then caps each estimate at `result_bytes/3` (an upper bound on chars-per-token). Records expose `_token_estimate_method` as one of `usage_delta`, `usage_delta_capped`, or `char_div_4` (fallback when no delta is available).

**Thresholds.** `--token-min-sessions` and `--token-min-tokens` adjust the Pattern A (repeated-read) cutoffs only; other detectors keep built-in defaults. `--token-top` controls how many findings appear in the table (default 20); the DETAILS section always covers the top 5.

**JSON shape.** `--token-report-json` emits `{generated_at, filters, summary, findings: [...]}` where each finding carries `{rank, kind, target, occurrences, distinct_sessions, avg_tokens, sum_tokens, stability_factor, score, sample_session_ids, suggestion: {type, headline, body}, raw}`.

### JSON output

```bash
python3 claude-approval-report.py --json
python3 claude-approval-report.py --json --since 7d | jq '.risk'
```

Status messages go to stderr; JSON is clean for piping.

## Output control

```bash
python3 claude-approval-report.py -o                    # auto-named timestamped file
python3 claude-approval-report.py --output /tmp/        # auto-named in specific dir
python3 claude-approval-report.py --output report.txt   # specific filename
python3 claude-approval-report.py --json --output       # uses .json extension
```
