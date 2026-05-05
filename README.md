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
4. Classifies each tool call by **risk level** — destructive, mutating, or read-only — using curated command lists with flag-aware logic for git, curl, find, sed, and ansible-playbook
5. Groups commands by normalized prefix (e.g. all `git add` variants together, all `ssh` to the same host together)
6. Renders ranked tables: most prompted, most rejected, risk breakdown, destructive approvals, auto-allowed risky commands, suggested allowlist additions, per-project summary, and tool type breakdown

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
  3      268      Bash: (comment/shebang)
  4      260      Bash: ls
  5      250      Bash: grep
  6      217      TaskUpdate
  7      211      Agent
  8      171      Bash: cat
  9      161      Bash: find
  10     146      ToolSearch
  11     137      Bash: sleep
  12     131      Bash: git diff
  13     127      Bash: ssh
  14     108      TaskCreate
  15     107      Bash: git
  16     100      Bash: git status
  17     94       Bash: git add
  18     91       Bash: sudo
  19     87       Bash: wc
  20     86       Bash: python3
  21     86       Edit: ~/laima/docs/laima-project-tracker.md
  22     82       Bash: git log
  23     81       Bash: ssh 192.168.86.125
  24     70       Bash: mkdir
  25     62       Edit: ~/laima-titan/.titan/STATE.md

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
  destructive           34  (  0.3%)
  mutating           6,977  ( 55.3%)
  read-only          5,307  ( 42.0%)
  unknown              310  (  2.5%)

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
