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
python3 claude-approval-report.py -o           # write to auto-named timestamped file
```

No dependencies beyond Python 3.11+ stdlib. Test suites: `tests/test_report.py` (155 tests for the main script's pure functions), `hooks/test_block_secrets.py` (67 tests), `hooks/test_bypass_fixes.py` (110 tests), `hooks/test_round2_bypass_fixes.py` (50 tests), `hooks/test_fp_fixes.py` (28 tests), `hooks/test_infra_usability.py` (136 tests), `hooks/test_warn_secrets.py` (15 tests), `hooks/test_warn_mode.py` (30 tests) — 591 total.

## Architecture

Everything lives in `claude-approval-report.py`. The processing pipeline:

1. **Allowlist loading** — reads `~/.claude/settings.json` (global) and per-project `settings.local.json` / `settings.json` to know which patterns are already auto-allowed
2. **Session parsing** (`process_session`) — reads JSONL files (using `**/*.jsonl` recursive glob to include subagent transcripts), correlates assistant tool_use blocks with user result records via `sourceToolAssistantUUID`/`toolUseID`, determines approval/rejection status
3. **Risk classification** (`classify_risk`) — categorizes each tool call as destructive/mutating/read-only. Bash commands get sub-command-aware logic for git, curl, find, sed, ansible-playbook. Secret detection runs 22 provider-specific token regexes plus Shannon entropy on base64 blobs (primary >= 3.5 threshold plus secondary unique-char-ratio check for 3.0-3.5 range to catch padding evasion)
4. **Command normalization** (`normalize_command`) — groups variants (e.g., all `git add` invocations, all `ssh` to the same host) for aggregation
5. **Rendering** — seven output modes: full tables (`render_report`), compact dashboard (`render_summary`), JSON (`render_json`), single-command lookup (`render_why`), security settings generation (`render_generate_settings`), time-series trend (`render_trend`), hook warning audit (`render_warns`)
6. **Apply** (`apply_suggestions`) — writes suggested patterns to project `settings.local.json` files
7. **Generate settings** (`render_generate_settings`) — emits deny rules + hook config as a mergeable JSON fragment, with data-driven analysis of actual secret exposures via `_find_secret_exposures`

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

A self-contained PostToolUse hook that scans tool output for leaked secrets (known token patterns, JWTs, private key headers). Cannot prevent the leak but emits `decision: "block"` with a warning to avoid using the values and advise credential rotation. Scans Bash command output, Read tool output, and Edit tool output. Exempts grep-family commands, git diff/log/show output, and Python/test script output (running the hook's own test suite).

PreToolUse correlation (`HOOK_CORRELATE=1`, on by default): after standard pattern scanning, reads recent warn entries from the PreToolUse audit log, extracts flagged variable names, and checks command output for high-entropy strings that could be expanded secret values. Triggers a stronger warning when a secret that was flagged before execution appears in output. Set `HOOK_CORRELATE=0` to disable.

## Reference settings (`settings/recommended-deny.json`)

60 baseline deny patterns for Read/Write/Edit plus a hook config template. The `BASELINE_DENY_RULES` list in the main script mirrors this file — they should be kept in sync.

## Documentation (`docs/`)

- **`cli-reference.md`** — full CLI flag documentation with all modes, filters, and examples
- **`hooks.md`** — hook detection reference with categorized tables of what is caught, allowed, and undetectable
- **`example-reports.md`** — real output samples from trend, summary, and secrets modes
- **`architecture.md`** — reference architecture showing how deny rules, the hook, and MCP servers form a layered defense, with homelab deployment diagrams and adaptation instructions
- **`auth-best-practices.md`** — index and quick reference for working with authenticated services when the hook and deny rules are active. Links to per-service guides:
  - `auth-vault.md`, `auth-api-services.md`, `auth-ansible.md`, `auth-ssh.md`, `auth-env-vars.md`, `auth-diskless-secrets.md`

Reference these docs when adding new secret patterns or modifying detection logic to ensure the documented workarounds remain valid.

## CI/CD (`scripts/ci-test-runner.py`, `.forgejo/workflows/test.yml`)

Forgejo Actions workflow runs all 8 test suites (591 tests) on push to `main` and on PRs. Uses `node:22-slim` image on the `docker` runner label, installs Python via apt. Results are uploaded to DefectDojo as "Generic Findings Import" — test failures become findings, clean runs auto-close previous findings via `close_old_findings=true`. Product: `autoclaude` (ID 21), Engagement: `CI Tests` (ID 36), Product Type: `Inspicere Projects`. The `DEFECTDOJO_API_TOKEN` secret is configured on the Forgejo repo.

## Known Issues (from 2026-05-08 red team engagement) — ALL FIXABLE ISSUES RESOLVED

A two-round multi-agent red team engagement on 2026-05-08 targeted the hooks with a planted fake secret in `~/autoclaude_engagement_target/.env`. Round 1: 5 parallel agents (Opus + Sonnet) found 7 bypass classes with 30+ working vectors. Round 2: 5 more agents targeted the hardened hook and found 15 additional bypass classes. All fixable issues were remediated. 117 tests total (67 round 1 + 50 round 2), 0 failures. Hook grew from ~504 to ~830 lines.

### Round 1 (commit `5856065`) — ALL FIXED

#### Critical (2)
1. ~~**Quoted path bypass**~~ — `_strip_quotes()` added to `_is_sensitive_path()` to remove quotes before matching.
2. ~~**Glob/wildcard bypass**~~ — `_could_glob_match_sensitive()` uses `fnmatch` to detect globs that could expand to sensitive filenames.

#### High (4)
3. ~~**15+ unmonitored file-reading tools**~~ — Added `sort`, `paste`, `cut`, `fmt`, `fold`, `expand`, `pr`, `column`, `jq`, `diff`, `cmp`, `comm`, `csplit`, `split`, `join`, `uniq`, `iconv`, `yq`, `xq`, `script` to `_FILE_READERS`.
4. ~~**Process substitution `<()` not parsed**~~ — Added `_RE_PROC_SUBST` regex, extracted commands checked alongside `$()`.
5. ~~**Write-then-execute**~~ — Write/Edit tool content now scanned for file-reading/copying commands targeting sensitive paths.
6. ~~**Heredoc-to-interpreter**~~ — `_RE_HEREDOC` detects heredoc syntax; body scanned via `_check_sensitive_paths_in_text()` when interpreter is the base command.

#### Medium (2)
7. ~~**curl `@file` exfiltration**~~ — Added `@file`, `=@file`, `-T`/`--upload-file`, and `wget --post-file`/`--body-file` detection.
8. **Variable/runtime indirection** — `xargs` with file-reading commands blocked (round 1). Variable assignment tracking added in round 2 (see below). Shell function indirection and bash array expansion remain undetectable.

#### Additional round 1 fixes
- `command` and `busybox` added to `_COMMAND_WRAPPERS`
- `script -c` wrapper detection added
- Interpreter script file arguments checked against `_is_sensitive_path`
- `bash -c` inner commands now split and checked individually
- `make` with sensitive file arguments detected

### Round 2 (commit `074615f`) — ALL FIXABLE ISSUES RESOLVED

#### Critical (1)
9. ~~**bash/sh/zsh heredoc**~~ — shells weren't in `_INTERPRETERS` for heredoc check. Added `_HEREDOC_SHELLS` set.

#### High (8)
10. ~~**Backtick substitution**~~ — no regex existed for `` `cmd` ``. Added `_RE_BACKTICK_SUBST`.
11. ~~**stdbuf/ionice/numactl/taskset/chrt wrappers**~~ — not in `_COMMAND_WRAPPERS`. Added with proper flag stripping.
12. ~~**xargs -a/--arg-file**~~ — xargs handler only checked command target. Added arg-file flag detection.
13. ~~**bash -c positional args**~~ — `bash -c 'cat "$1"' _ .env` positional args after `-c` string not checked. Added shell positional arg scanning.
14. ~~**Subshell `(cmd)` unwrapping**~~ — bare `(...)` not parsed. Added `_unwrap_grouping()` with `&` trailing strip.
15. ~~**Curly-brace `{ cmd; }` grouping**~~ — `{` as first token not handled. Added to `_unwrap_grouping()`.
16. ~~**Variable indirection tracking**~~ — `F=.env; cat $F` not followed. Added `_RE_VAR_ASSIGN` variable assignment tracking in `main()`.
17. ~~**echo|bash pipe injection**~~ — `echo cmd | bash` not detected. Added post-processing in `_split_shell_commands`.

#### Medium (6)
18. ~~**node --eval long-form interpreter flags**~~ — only `-c`/`-e`/`-r` checked. Added `--eval`, `--exec`, `--print`, `--require`, `--command`.
19. ~~**SSH remote command execution**~~ — ssh not in any detection list. Added SSH remote command arg scanning.
20. ~~**while-read loop tracking**~~ — loop variable flow not tracked. Added `SENSITIVE_VAR_LOOP:` sentinel.
21. ~~**--from-file=/--files0-from= long flags**~~ — `_LONG_FILE_FLAGS` set added.
22. ~~**openssl -in flag scanning**~~ — `_FILE_FLAG_ARGS` dict added.
23. ~~**14 additional file readers**~~ — shuf, unexpand, colrm, look, tsort, ptx, nkf, uuencode, base32, zcat, bzcat, xzcat, lz4, vidir added to `_FILE_READERS`.

### Remaining architectural gaps (unfixable by static analysis)
- **Shell function indirection**: `r() { cat "$1"; }; r .env` — function definitions create opaque indirection
- **Bash array expansion**: `a=(cat .env); "${a[@]}"` — array content not trackable
- **Runtime path construction**: `os.listdir()` in scripts — no .env reference in args
- **Generic write-then-execute**: script content has no sensitive path reference
- **Symlink TOCTOU**: `_is_sensitive_path` calls `os.path.realpath()` which resolves symlinks at check time; a symlink could be repointed between the hook's check and command execution. Mitigation: the hook runs in the same process tick as tool dispatch, making the race window extremely small, but it is theoretically exploitable with a pre-positioned symlink and a concurrent process.

### Usability testing (2026-05-08) — 2 false positives found and fixed

150+ common workflow commands tested across git/dev, infrastructure, edge cases, and Write/Edit content. Two false positive categories discovered and fixed:

1. ~~**`find -name` false positive**~~ — `find -name '.git*'` incorrectly blocked because the grep-family handler passed `-name` value tokens to `_is_sensitive_path`, and `_could_glob_match_sensitive` treated bare `*` basename as matching everything. Fixed: grep-family handler now skips `-name`/`-iname`/`-path`/`-ipath`/`-regex`/`-wholename` value tokens; `_could_glob_match_sensitive` returns False for bare `*`/`?`/`**` basenames.
2. ~~**Write/Edit content scanner false positives on docs**~~ — markdown/YAML/text files with prose like "cat server.pem to check certificate details" triggered the content scanner. Fixed: content scanning now gated on file extension — only scans executable script files (`.sh`, `.bash`, `.py`, `.rb`, `.pl`, `.js`, etc.) and extensionless files, skips `.md`, `.txt`, `.yml`, `.json`, `.html`, `.rst`, etc.

## Known Issues (from 2026-05-07 adversarial audit) — ALL RESOLVED

A comprehensive adversarial audit on 2026-05-07 identified 32 bypass vectors and 22 code quality issues. All findings were remediated same-day in commits `275ee75` (hooks), `7f271f4` (main script), `20bdfb1` (docs). Test suites added: `test_block_secrets.py` (59 tests), `test_warn_secrets.py` (12 tests).

### Critical (4) — FIXED in commit `275ee75`
1. ~~`_RE_SECRET_ASSIGN` regex catastrophic backtracking~~ — atomic-group-style rewrite
2. ~~Multi-statement command bypass~~ — splits on `;`, `&&`, `||`, `|` and checks each segment
3. ~~Pipe-based bypass~~ — same fix as #2
4. ~~grep-family reads entire files undetected~~ — detects `grep . ~/.env` style file reads

### High (9) — FIXED in commits `275ee75`, `7f271f4`
5. ~~Write tool completely unprotected~~ — added to hook matcher and code paths
6. ~~PostToolUse exempts `.py`/`.md`/`.json`~~ — exemptions removed
7. ~~PostToolUse ignores Read/Edit tool output~~ — now scans all tool output
8. ~~`curl file://`, `wget file://` bypass~~ — local file access blocked
9. ~~`tar`/`zip`/`scp` exfiltration~~ — detected
10. ~~`sudo cat` bypass~~ — `sudo`/`env`/`time` prefixes stripped
11. ~~Subshell/command substitution bypass~~ — `$(...)` and backtick extraction
12. ~~`docker run -v` mount bypass~~ — detected
13. ~~`command_matches_pattern` cd prefix stripping~~ — fixed

### Medium (10) — FIXED in commits `275ee75`, `7f271f4`, `20bdfb1`
14-23. All resolved: sensitive paths added to deny rules (26->60), placeholder filtering, Read double-counting fix, timestamp normalization, grep-family alignment, curl compact flags, Write/Edit deny symmetry

### Documentation Discrepancies (7) — ALL FIXED in commits `ae0ea5b`, `20bdfb1`
- All discrepancies resolved including README updates, grep-family description, deny count
