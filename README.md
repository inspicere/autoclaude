# autoclaude

Analyzes Claude Code session data to show which tool calls required the most user approval prompts, which were rejected, and suggests allowlist additions to reduce friction. Each tool call is also risk-classified as destructive, mutating, or read-only.

## How it works

Claude Code stores session transcripts as JSONL files under `~/.claude/projects/`. Each file contains interleaved assistant and user records — when the assistant makes a tool call (`Bash`, `Edit`, `Write`, etc.), the user record that follows contains the result and whether the call was approved or rejected.

### Data sources

- **Session data**: `~/.claude/projects/<project>/*.jsonl` — one JSONL file per conversation session, containing all tool calls and results
- **Global allowlist**: `~/.claude/settings.json` — permissions that apply to all projects
- **Per-project allowlists**: derived from the project directory name (e.g. `-home-user-myproject` maps to `/home/user/myproject/.claude/settings.local.json`) and from `~/.claude/projects/<project>/settings.json`

### What the script does

1. Loads permission allowlists from global and per-project settings
2. Parses every session JSONL file across all projects in `~/.claude/projects/`
3. Classifies each tool call as **auto-allowed** (matched an allowlist pattern), **prompted & approved**, or **rejected**
4. Classifies each tool call by **risk level** — destructive, mutating, or read-only — using curated command lists with flag-aware logic for git, curl, find, sed, and ansible-playbook; detects secret/key material exposure via 22 provider-specific token patterns (GitHub, AWS, Vault, Slack, Anthropic, etc.), JWT detection, curl auth headers, and Shannon entropy-gated base64 blob detection
5. Groups commands by normalized prefix (e.g. all `git add` variants together, all `ssh` to the same host together)
6. Filters noise entries (shell syntax fragments, comment/shebang lines, IP addresses, flags) from prompted commands report
7. Renders ranked tables: most prompted, most rejected, risk breakdown, destructive approvals, auto-allowed risky commands, suggested allowlist additions, per-project summary, and tool type breakdown

## Requirements

Python 3.11+ (stdlib only, no dependencies).

## Usage

```
# Print report to terminal
python3 claude-approval-report.py

# Write to auto-named file in current directory (ISO 8601 timestamp)
python3 claude-approval-report.py --output

# Write to auto-named file in a specific directory
python3 claude-approval-report.py --output /tmp/

# Write to a specific file
python3 claude-approval-report.py --output my-report.txt
```

### Filtering

```
# Only analyze the last 7 days
python3 claude-approval-report.py --since 7d

# Only analyze a specific project
python3 claude-approval-report.py --project laima

# Combine filters
python3 claude-approval-report.py --since 2w --project laima
```

The `--since` flag accepts relative times (`7d`, `2w`, `1m`) or ISO dates (`2026-05-01`).

### Applying suggestions

```
# Preview what would be added (dry run)
python3 claude-approval-report.py --apply --dry-run

# Apply read-only suggestions to per-project settings.local.json files
python3 claude-approval-report.py --apply

# Consolidate common patterns (3+ projects) into global ~/.claude/settings.json
python3 claude-approval-report.py --apply --scope global

# Global + project-specific remainder (recommended for initial setup)
python3 claude-approval-report.py --apply --scope both --dry-run

# Also apply mutating suggestions (never applies destructive)
python3 claude-approval-report.py --apply mutating

# Combine with filters
python3 claude-approval-report.py --apply --since 7d --project laima --dry-run
```

The `--apply` flag writes frequently-approved patterns to settings files. The `--scope` flag controls where:

| Scope | Writes to | Use case |
|-------|-----------|----------|
| `project` (default) | Each project's `.claude/settings.local.json` | Per-project customization |
| `global` | `~/.claude/settings.json` | Patterns appearing in 3+ projects |
| `both` | Global + per-project remainder | Initial setup — consolidates common patterns globally, keeps project-specific ones local |

By default only read-only commands are applied. Destructive patterns are never auto-applied. Without `--dry-run`, a confirmation prompt is shown before changes are written.

### Summary mode

```
# Compact ~12 line dashboard (useful as Claude Code skill output)
python3 claude-approval-report.py --summary

# Also available as --brief
python3 claude-approval-report.py --brief
```

Shows call counts, risk breakdown, secret exposure count, top 5 prompted commands, and top 3 suggestions. When secrets are detected, a warning is displayed advising rotation (secrets are persisted in JSONL files and were sent to the Claude API). Composes with `--since`, `--project`, and `--session`.

### Command lookup

```
# Diagnose why a specific command gets prompted
python3 claude-approval-report.py --why "git push"

# Shows risk level, prompt/auto/reject counts, allowlist status per project,
# and the exact pattern to add
python3 claude-approval-report.py --why ssh
```

Substring match on display name, falls back to full command text.

### Session filtering

```
# Analyze only the most recently modified session
python3 claude-approval-report.py --session current

# Analyze a specific session by UUID or partial filename
python3 claude-approval-report.py --session 3a7b9c
```

Composes with `--since`, `--project`, `--summary`, and `--why`.

### JSON output

```
# Print JSON to terminal
python3 claude-approval-report.py --json

# Write JSON to auto-named file (uses .json extension)
python3 claude-approval-report.py --json --output

# Combine with filters and pipe
python3 claude-approval-report.py --json --since 7d --project laima | jq '.risk'
```

Status messages go to stderr, so JSON output is clean for piping.

### Security settings generation

```
# Generate recommended deny rules + hook config (JSON to stdout, commentary to stderr)
python3 claude-approval-report.py --generate-settings

# Save to file
python3 claude-approval-report.py --generate-settings --output security-settings.json

# Data-driven: analyze recent sessions to quantify secret exposures
python3 claude-approval-report.py --generate-settings --since 30d

# Pipe JSON directly (stderr commentary doesn't interfere)
python3 claude-approval-report.py --generate-settings | jq '.permissions.deny'
```

Outputs a JSON fragment with deny rules and hook configuration ready to merge into `~/.claude/settings.json`. The stderr commentary shows which rules are already configured, what's new, and how many secret exposures the hook would have blocked.

### Trend analysis

```
# Daily approval rate trend, all time
python3 claude-approval-report.py --trend

# Daily trend for last 7 days
python3 claude-approval-report.py --trend 7d

# Auto-picks weekly buckets for 90-day window
python3 claude-approval-report.py --trend 90d

# Override auto bucket size
python3 claude-approval-report.py --trend 30d --bucket week

# Quarterly trend, all time
python3 claude-approval-report.py --trend --bucket quarter
```

Shows a time-series table with columns: Total, Auto, Prompted, Rejected, Auto%, Destructive, Mutating, R/O, Secrets. Directional arrows indicate period-over-period changes. Bucket size is auto-selected based on window duration (day for <=31d, week for <=90d, month for <=730d, quarter for <=1825d, year for >5y), or can be overridden with `--bucket`. Composes with `--since` and `--project`. Warns when output exceeds 100 rows.

### Hook warning audit

```
# Show all hook warning events and whether the user approved or rejected them
python3 claude-approval-report.py --warns

# Warnings from the last week only
python3 claude-approval-report.py --warns --since 7d
```

Reads `~/.claude/hook-audit.jsonl` for `decision: "warn"` records from the PostToolUse hook, cross-references with session JSONL data to determine whether the user approved or rejected each warning. Displays a table with timestamp, command, reason, and user decision (APPROVED/REJECTED/no session match). Composes with `--since`.

### Secret exposure analysis

```
# Detailed report of all detected secret exposures with risk classification
python3 claude-approval-report.py --secrets

# Combine with time filter
python3 claude-approval-report.py --secrets --since 7d
```

Shows each flagged command with exposure risk classification: **exposed** (literal secret in command text), **runtime** (secret expanded at execution time), **variable** (variable reference that may contain a secret), or **pipe-safe** (secret passed through a pipe and not exposed in session). Composes with `--since` and `--project`.

## CI/CD

A Forgejo Actions workflow (`.forgejo/workflows/test.yml`) runs all 8 test suites (582 tests) on every push to `main` and on pull requests. Results are uploaded to DefectDojo as "Generic Findings Import" — test failures become findings, clean runs auto-close previous findings. The test runner (`scripts/ci-test-runner.py`) handles multi-suite execution and result conversion.

## PreToolUse hook: block-secrets.py

The `hooks/block-secrets.py` script is a Claude Code PreToolUse hook that blocks commands before execution. It catches two classes of leaks that deny rules alone cannot prevent:

1. **Embedded secrets in Bash commands** — API tokens, JWTs, private keys, auth headers, high-entropy blobs
2. **Sensitive file reads via Bash** — `cat .env`, `head ~/.ssh/id_rsa`, etc. that bypass Read deny rules

### Install

Add to `hooks` in `~/.claude/settings.json`:

```json
{
  "hooks": {
    "PreToolUse": [
      {
        "matcher": "Bash|Read|Edit|Write",
        "hooks": [
          {
            "type": "command",
            "command": "python3 /path/to/autoclaude/hooks/block-secrets.py"
          }
        ]
      }
    ]
  }
}
```

### What it detects

- 22 provider-specific token patterns (GitHub, AWS, Vault, Anthropic, Slack, Stripe, etc.)
- JWT tokens, private key headers, curl Authorization headers
- Secret variable assignments (`VAULT_TOKEN=s.xxx`) with smart filtering to avoid false positives on variable references and URLs
- High-entropy base64 blobs (Shannon entropy >= 3.5, with secondary unique-char-ratio check for 3.0-3.5 range to catch padding evasion)
- 45+ file-reading commands (`cat`, `head`, `tail`, `base64`, `sort`, `cut`, `jq`, `shuf`, `zcat`, `bzcat`, etc.) targeting sensitive paths (`.env*`, `.ssh/id_*`, `.aws/credentials`, `/etc/shadow`, etc.)
- Subshell wrapping (`bash -c 'cat .env'`, `sh -c`, `zsh -c`) — unwraps and recursively re-checks
- Eval wrapping (`eval 'cat .env'`) — unwraps and recursively re-checks
- Interpreter file I/O (`python3 -c "open('.env').read()"`, `perl -e`, `ruby -e`, `node -e`, `node --eval`) — detects `open()`, `File.read()`, and sensitive path references in inline scripts
- File copy/move/link commands (`cp .env /tmp/x`, `mv`, `ln`, `install`, `rsync`) — blocks when source is a sensitive path
- `dd if=<sensitive-path>` — parses the `if=` parameter
- Shell stdin redirection (`< .env`, `while read line; do ...; done < .env`)
- Read/Edit tool calls targeting the same sensitive paths
- Process substitution (`<(cat .env)`) — extracts and checks inner commands
- Heredoc-to-interpreter (`python3 <<EOF ... open('.env') ... EOF`) — scans heredoc body
- Backtick command substitution (`` `cat .env` ``) — extracts and checks inner commands
- Pipe-to-shell injection (`echo 'cat .env' | bash`) — detects piped shell execution
- Subshell `(cmd)` and brace group `{ cmd; }` unwrapping
- Variable assignment tracking (`F=.env; cat $F`) — follows variable values to detect indirect references
- SSH remote command execution (`ssh host cat .env`) — scans remote command arguments
- `xargs -a`/`--arg-file` flag detection for sensitive file arguments
- Shell positional args after `bash -c` (`bash -c 'cat "$1"' _ .env`)
- Long-form file flags (`--from-file=`, `--files0-from=`, `openssl -in`)
- While-read loop variable tracking (`while read F; do cat $F; done`)
- Command wrappers (`sudo`, `env`, `time`, `command`, `busybox`, `stdbuf`, `ionice`, `numactl`, `taskset`, `chrt`, `script -c`)

### What it allows

- Grep-family commands including sed/awk (searching for patterns, not using secrets) — though file arguments are still checked against sensitive paths
- Variable references (`export TOKEN=$TOKEN`)
- URLs in assignments (`CALLBACK=https://example.com`)
- Short/placeholder values (`PASSWORD=changeme`)
- Normal file operations on non-sensitive paths

### Known limitations and mitigations

- **Copy-then-read**: The hook blocks `cp`, `mv`, `ln`, `install`, and `rsync` when the source is a sensitive path, preventing the first step of a copy-then-read chain. However, if a sensitive file was copied to a non-sensitive path *before* the hook was installed, the copy is not tracked. For defense in depth, use filesystem-level controls (mandatory access control, audit logging) on sensitive files.
- **Output capture**: The PreToolUse hook inspects commands *before* execution but cannot inspect command *output*. A `vault kv get` that prints secrets to stdout will not be blocked by it. **Mitigation:** The `warn-secrets-output.py` PostToolUse hook scans Bash output for known token patterns, JWTs, and private key material, then warns Claude not to use the values and advises the user to rotate. MCP servers remain the preferred path — auth stays server-side and secrets never enter the session.
- **Encoded payloads**: Base64-encoded or obfuscated secrets that don't match known token patterns and fall below the entropy threshold will pass through. The primary threshold is Shannon entropy >= 3.5 on 32+ char strings. A secondary check catches padding evasion attempts in the 3.0-3.5 range using unique character ratio (>= 0.4) and max character frequency (<= 0.15). Strings below 3.0 bits/char or failing the secondary check will pass through. **Mitigation:** The dual-threshold approach catches most real secrets while minimizing false positives.
- **Variable/runtime indirection** (2026-05-08): Simple variable assignment tracking was added (`F=.env; cat $F` is now detected), along with while-read loop variable tracking and `xargs -a`/`--arg-file` detection. However, shell function indirection (`r() { cat "$1"; }; r .env`), bash array expansion (`a=(cat .env); "${a[@]}"`), and runtime path construction in scripts remain undetectable — fundamental limitations of pre-execution static analysis.

## PostToolUse hook: warn-secrets-output.py

The `hooks/warn-secrets-output.py` script is a PostToolUse hook that scans Bash command output for leaked secrets. It cannot prevent the leak (the command already ran) but blocks Claude from using the exposed values and warns about rotation.

### Install

Add to `hooks` in `~/.claude/settings.json` alongside the PreToolUse hook:

```json
{
  "hooks": {
    "PostToolUse": [
      {
        "matcher": "Bash|Read|Edit",
        "hooks": [
          {
            "type": "command",
            "command": "python3 /path/to/autoclaude/hooks/warn-secrets-output.py"
          }
        ]
      }
    ]
  }
}
```

### What it detects

- 22 provider-specific token patterns (same as the PreToolUse hook)
- JWT tokens, private key headers
- Scans Bash command output, Read tool results, and Edit tool results

### What it exempts

- Grep-family command output (searching for patterns, not leaking secrets)
- Git diff/log/show output (reviewing code that contains pattern definitions)
- Reading known project files (block-secrets.py, claude-approval-report.py, warn-secrets-output.py, README, CLAUDE.md) which contain token patterns as part of their regex definitions

## Recommended deny rules

`settings/recommended-deny.json` contains a reference set of 60 deny patterns covering Read/Write/Edit access to sensitive file types. Use `--generate-settings` to see which ones are already in your config and what's missing.

Deny rules protect the Read/Write/Edit tools. The hook protects Bash commands. Together they form a layered defense:

| Layer | Protects against | Limitation |
|-------|-----------------|------------|
| Deny rules | `Read .env`, `Edit ~/.ssh/id_rsa` | Cannot inspect Bash commands |
| Hook | `cat .env`, `VAULT_TOKEN=hvs.xxx ...` | Only runs on tool calls, not manual shell |

## Example output

Report from a homelab infrastructure project (~12.6k tool calls across 10 projects, April-May 2026):

```
======================================================================
  CLAUDE CODE APPROVAL ANALYSIS
======================================================================

  Total tool calls analyzed:  12,628
  Auto-allowed (no prompt):   5,240
  User prompted & approved:   7,334
  User rejected:              80

======================================================================
  MOST PROMPTED COMMANDS (top 25)
  Commands that required user approval most often
======================================================================
  Rank   Count    Command
  ----   -----    -------
  1      378      Bash: tail
  2      349      Bash: ssh 192.168.86.122
  3      260      Bash: ls
  4      250      Bash: grep
  5      217      TaskUpdate
  6      211      Agent
  7      171      Bash: cat
  8      161      Bash: find
  9      146      ToolSearch
  10     137      Bash: sleep
  11     131      Bash: git diff
  12     127      Bash: ssh
  13     108      TaskCreate
  14     107      Bash: git
  15     100      Bash: git status
  16     94       Bash: git add
  17     91       Bash: sudo
  18     87       Bash: wc
  19     86       Bash: python3
  20     86       Edit: ~/laima/docs/laima-project-tracker.md
  21     82       Bash: git log
  22     81       Bash: ssh 192.168.86.125
  23     70       Bash: mkdir
  24     62       Edit: ~/laima-titan/.titan/STATE.md
  25     62       Bash: head

======================================================================
  MOST REJECTED COMMANDS (top 15)
  Commands the user denied
======================================================================
  Rank   Count    Command
  ----   -----    -------
  1      9        Bash: git push
  2      4        Bash: git add
  3      4        ExitPlanMode
  4      4        Bash: curl
  5      3        Bash: ssh 192.168.86.127
  6      2        AskUserQuestion
  7      2        Bash: ssh 192.168.86.122
  8      2        Bash: python3
  9      2        Bash: git branch
  10     2        Bash: git

======================================================================
  SUGGESTED ALLOWLIST ADDITIONS
  Frequently approved commands that could be auto-allowed
======================================================================
  Count    Project                        Suggested Pattern
  -----    -------                        -----------------
  365      bench                          Bash(tail *)
  349      cli                            Bash(ssh *@192.168.86.122 *) or Bash(ssh 192.168.86.122 *)
  122      laima                          Bash(ls *)
  119      laima                          Bash(sleep *)
  90       laima                          Bash(git diff *)
  90       laima                          Bash(grep *)
  87       laima                          Bash(cat *)
  85       bench                          Bash(ssh *)
  83       bench                          Bash(wc *)

======================================================================
  RISK BREAKDOWN
======================================================================
  destructive          301  (  2.4%)
  mutating           6,977  ( 55.3%)
  read-only          5,343  ( 42.3%)
  unknown                7  (  0.1%)

======================================================================
  DESTRUCTIVE COMMANDS APPROVED (all)
  Commands classified as destructive that were approved
======================================================================
  Rank   Count    Command
  ----   -----    -------
  1      25       Bash: rm
  2      4        Bash: git push
  3      2        Bash: curl
  4      2        Bash: git branch

======================================================================
  AUTO-ALLOWED RISKY COMMANDS
  Mutating/destructive commands that bypassed approval prompts
======================================================================
  Count    Risk           Command
  -----    ----           -------
  343      mutating       Bash: ssh 192.168.86.122
  340      mutating       Bash: ssh
  203      mutating       Bash: git add
  129      mutating       Bash: ansible openclaw-01
  126      mutating       Bash: python
  124      mutating       Bash: ssh 192.168.86.127
  101      mutating       MCP vault: vault_write
  96       mutating       MCP vault: vault_read
  89       mutating       Bash: ssh 192.168.86.121

======================================================================
  PER-PROJECT SUMMARY
======================================================================
  Project                                Total     Auto Prompted Rejected
  -----------------------------------    -----     ---- -------- --------
  (home)                                   137       23      113        1
  app-security-scanning                    240       58      176        6
  claude-mod                               170       39      130        1
  laima                                   5900     2753     3120       44
  laima-ansible                             16        8        8        0
  laima-hermes-cli                        1448      220     1220        9
  laima-inference-bench                   1079      131      942        6
  laima-titan                             2219     1183     1032        9
  mcp-defectdojo                           211      138       73        0
  vsdx-forge                              1208      687      520        4

======================================================================
  TOOL TYPE BREAKDOWN (prompted only)
======================================================================
  Tool                            Prompted Count
  ------------------------------ ---------------
  Bash                                      4308
  Edit                                      1622
  Write                                      634
  TaskUpdate                                 217
  Agent                                      211
  ToolSearch                                 146
  TaskCreate                                 108
```
