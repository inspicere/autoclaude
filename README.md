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
4. Classifies each tool call by **risk level** — destructive, mutating, or read-only — using curated command lists with flag-aware logic for git, curl, find, sed, and ansible-playbook; detects secret/key material exposure in command arguments
5. Groups commands by normalized prefix (e.g. all `git add` variants together, all `ssh` to the same host together)
6. Filters noise entries (shell syntax fragments, comment/shebang lines, IP addresses, flags) from prompted commands report
7. Renders ranked tables: most prompted, most rejected, risk breakdown, destructive approvals, auto-allowed risky commands, suggested allowlist additions, per-project summary, and tool type breakdown

## Requirements

Python 3.8+ (stdlib only, no dependencies).

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

# Apply read-only suggestions to settings.local.json files
python3 claude-approval-report.py --apply

# Also apply mutating suggestions (never applies destructive)
python3 claude-approval-report.py --apply mutating

# Combine with filters
python3 claude-approval-report.py --apply --since 7d --project laima --dry-run
```

The `--apply` flag writes frequently-approved patterns directly to each project's `.claude/settings.local.json`. By default only read-only commands are applied. Destructive patterns are never auto-applied.

### Summary mode

```
# Compact ~12 line dashboard (useful as Claude Code skill output)
python3 claude-approval-report.py --summary

# Also available as --brief
python3 claude-approval-report.py --brief
```

Shows call counts, risk breakdown, secret exposure count, top 5 prompted commands, and top 3 suggestions. Composes with `--since`, `--project`, and `--session`.

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
