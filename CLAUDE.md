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
python3 claude-approval-report.py --json --since 7d --project laima  # filtered JSON
python3 claude-approval-report.py --generate-settings  # deny rules + hook config
python3 claude-approval-report.py --session current --summary  # latest session only
python3 claude-approval-report.py -o           # write to auto-named timestamped file
```

No dependencies beyond Python 3.8+ stdlib. No test suite — verify changes by running the script against live session data in `~/.claude/projects/`.

## Architecture

Everything lives in `claude-approval-report.py`. The processing pipeline:

1. **Allowlist loading** — reads `~/.claude/settings.json` (global) and per-project `settings.local.json` / `settings.json` to know which patterns are already auto-allowed
2. **Session parsing** (`process_session`) — reads JSONL files, correlates assistant tool_use blocks with user result records via `sourceToolAssistantUUID`/`toolUseID`, determines approval/rejection status
3. **Risk classification** (`classify_risk`) — categorizes each tool call as destructive/mutating/read-only. Bash commands get sub-command-aware logic for git, curl, find, sed, ansible-playbook. Secret detection runs 22 provider-specific token regexes plus Shannon entropy on base64 blobs
4. **Command normalization** (`normalize_command`) — groups variants (e.g., all `git add` invocations, all `ssh` to the same host) for aggregation
5. **Rendering** — five output modes: full tables (`render_report`), compact dashboard (`render_summary`), JSON (`render_json`), single-command lookup (`render_why`), security settings generation (`render_generate_settings`)
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
3. Bypass vectors: subshell wrapping (`bash -c`), `eval`, interpreter file I/O (`python3 -c "open('.env')"`), file copy/move/link (`cp .env /tmp/x`), `dd if=`, stdin redirection (`< .env`)

## PostToolUse hook (`hooks/warn-secrets-output.py`)

A self-contained PostToolUse hook that scans tool output for leaked secrets (known token patterns, JWTs, private key headers). Cannot prevent the leak but emits `decision: "block"` with a warning to avoid using the values and advise credential rotation. Scans Bash command output, Read tool output, and Edit tool output. Exempts grep-family commands, git diff/log/show output, and Python/test script output (running the hook's own test suite).

## Vault token renewal (`scripts/vault-token-renew.sh`)

Weekly cron job that runs `vault token renew` to extend the terrabot CLI token. Logs to `/var/log/laima/vault-renew.log`. The token has a 768h TTL and is renewable.

## Reference settings (`settings/recommended-deny.json`)

60 baseline deny patterns for Read/Write/Edit plus a hook config template. The `BASELINE_DENY_RULES` list in the main script mirrors this file — they should be kept in sync.

## Documentation (`docs/`)

- **`auth-best-practices.md`** — index and quick reference for working with authenticated services when the hook and deny rules are active. Links to per-service guides:
  - `auth-vault.md`, `auth-api-services.md`, `auth-ansible.md`, `auth-ssh.md`, `auth-env-vars.md`, `auth-diskless-secrets.md`
- **`architecture.md`** — reference architecture showing how deny rules, the hook, and MCP servers form a layered defense, with homelab deployment diagrams and adaptation instructions.

Reference these docs when adding new secret patterns or modifying detection logic to ensure the documented workarounds remain valid.

## Known Issues (from 2026-05-07 adversarial audit) — ALL RESOLVED

A comprehensive adversarial audit on 2026-05-07 identified 32 bypass vectors and 22 code quality issues. All findings were remediated same-day in commits `275ee75` (hooks), `7f271f4` (main script), `20bdfb1` (docs). Test suites added: `test_block_secrets.py` (48 tests), `test_warn_secrets.py` (12 tests).

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
