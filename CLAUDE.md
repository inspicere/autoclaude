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

A self-contained PostToolUse hook that scans Bash command output for leaked secrets (known token patterns, JWTs, private key headers). Cannot prevent the leak but emits `decision: "block"` with a warning to avoid using the values and advise credential rotation. Exempts grep-family commands, git diff/log/show output, Python/test script output (running the hook's own test suite), and files ending in `.py`, `.md`, or `.json` to avoid false positives on code/config containing pattern definitions.

## Vault token renewal (`scripts/vault-token-renew.sh`)

Weekly cron job that runs `vault token renew` to extend the terrabot CLI token. Logs to `/var/log/laima/vault-renew.log`. The token has a 768h TTL and is renewable.

## Reference settings (`settings/recommended-deny.json`)

26 baseline deny patterns for Read/Write/Edit plus a hook config template. The `BASELINE_DENY_RULES` list in the main script mirrors this file — they should be kept in sync.

## Documentation (`docs/`)

- **`auth-best-practices.md`** — index and quick reference for working with authenticated services when the hook and deny rules are active. Links to per-service guides:
  - `auth-vault.md`, `auth-api-services.md`, `auth-ansible.md`, `auth-ssh.md`, `auth-env-vars.md`, `auth-diskless-secrets.md`
- **`architecture.md`** — reference architecture showing how deny rules, the hook, and MCP servers form a layered defense, with homelab deployment diagrams and adaptation instructions.

Reference these docs when adding new secret patterns or modifying detection logic to ensure the documented workarounds remain valid.

## Known Issues (from 2026-05-07 adversarial audit)

A comprehensive adversarial audit on 2026-05-07 identified 32 bypass vectors and 22 code quality issues. No code changes were made — this was a read-only assessment. Key findings by severity:

### Critical (4)
1. `_RE_SECRET_ASSIGN` regex catastrophic backtracking in `block-secrets.py` — 50k-char input causes timeout, hook fails open
2. Multi-statement command bypass (`echo hello; cat ~/.vault-token`) — only first command in chain parsed
3. Pipe-based bypass (`echo x | cat ~/.env`) — same root cause as #2
4. grep-family reads entire files undetected (`grep . ~/.env`, `awk '{print}' ~/.ssh/id_rsa`)

### High (9)
5. Write tool completely unprotected by hook (not in matcher, no code path handling)
6. PostToolUse exempts `.py`/`.md`/`.json` files from output scanning (too broad)
7. PostToolUse ignores Read/Edit tool output entirely
8. `curl file://`, `wget file://` bypass file access checks
9. `tar`/`zip`/`scp` exfiltration not detected
10. `sudo cat` bypass (sudo not stripped as prefix)
11. Subshell/command substitution bypass (`$(which cat) ~/.env`, `TOKEN=$(cat ~/.vault-token)`)
12. `docker run -v` mount bypass
13. `command_matches_pattern` doesn't strip `cd` prefixes in main script (inaccurate reporting)

### Medium (10)
14-23. Missing sensitive paths, missing token patterns, heredoc false positive, `classify_risk` lacks placeholder filtering, Read tool double-counting, timezone comparison bug, grep-family set inconsistency between hook and main script, `generate_settings` merge risk, curl compact flag forms missed, Write/Edit deny rule asymmetry

### Documentation Discrepancies (7)
- `_GREP_FAMILY` "mirrors" claim corrected (hook has `sed`/`awk`, main script does not)
- PostToolUse exemption list was incomplete in CLAUDE.md (now fixed above)
- Architecture diagram deny/allow counts outdated (now fixed in `docs/architecture.md`)
- Architecture files table missing `warn-secrets-output.py` and `scripts/` (now fixed)
- "20+ others" token count should be "17 others" in README grep-family description
- `.env.example` allowed mechanism different than documented
- README missing `sed`/`awk` from grep-family description
