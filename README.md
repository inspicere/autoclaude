# autoclaude

Analyzes Claude Code session data to show which tool calls required the most user approval prompts, which were rejected, and suggests allowlist additions to reduce friction.

## How it works

Claude Code stores session transcripts as JSONL files under `~/.claude/projects/`. Each file contains interleaved assistant and user records — when the assistant makes a tool call (`Bash`, `Edit`, `Write`, etc.), the user record that follows contains the result and whether the call was approved or rejected.

### Data sources

- **Session data**: `~/.claude/projects/<project>/*.jsonl` — one JSONL file per conversation session, containing all tool calls and results
- **Global allowlist**: `~/.claude/settings.json` — permissions that apply to all projects
- **Per-project allowlists**: derived from the project directory name (e.g. `-home-terrabot-laima` maps to `/home/terrabot/laima/.claude/settings.local.json`) and from `~/.claude/projects/<project>/settings.json`

### What the script does

1. Loads permission allowlists from global and per-project settings
2. Parses every session JSONL file across all projects in `~/.claude/projects/`
3. Classifies each tool call as **auto-allowed** (matched an allowlist pattern), **prompted & approved**, or **rejected**
4. Groups commands by normalized prefix (e.g. all `git add` variants together, all `ssh` to the same host together)
5. Renders ranked tables: most prompted, most rejected, suggested allowlist additions, per-project breakdown, and tool type breakdown

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

## Example output

Report from a homelab infrastructure project (~12.5k tool calls across 10 projects, April-May 2026):

```
======================================================================
  CLAUDE CODE APPROVAL ANALYSIS
======================================================================

  Total tool calls analyzed:  12,548
  Auto-allowed (no prompt):   4,211
  User prompted & approved:   8,276
  User rejected:              79

======================================================================
  MOST PROMPTED COMMANDS (top 25)
  Commands that required user approval most often
======================================================================
  Rank   Count    Command
  ----   -----    -------
  1      483      Bash: ssh 192.168.86.122
  2      378      Bash: tail
  3      289      Bash: ls
  4      272      Bash: grep
  5      268      Bash: (comment/shebang)
  6      217      TaskUpdate
  7      205      Agent
  8      203      Bash: git add
  9      202      Bash: git diff
  10     177      Bash: find
  11     171      Bash: cat
  12     149      Bash: git
  13     146      Bash: python
  14     145      ToolSearch
  15     141      Bash: git status
  16     140      Bash: python3
  17     137      Bash: sleep
  18     133      Bash: ssh
  19     127      Bash: git log
  20     108      TaskCreate
  21     93       Bash: ssh 192.168.86.125
  22     91       Bash: sudo
  23     87       Bash: wc
  24     86       Edit: ~/laima/docs/laima-project-tracker.md
  25     70       Bash: mkdir

======================================================================
  MOST REJECTED COMMANDS (top 15)
  Commands the user denied
======================================================================
  Rank   Count    Command
  ----   -----    -------
  1      9        Bash: git push
  2      4        ExitPlanMode
  3      4        Bash: curl
  4      3        Bash: git add
  5      3        Bash: ssh 192.168.86.127
  6      2        AskUserQuestion
  7      2        Bash: ssh 192.168.86.122
  8      2        Bash: python3
  9      2        Bash: git branch
  10     2        Bash: git
  11     2        Bash: ls
  12     1        Bash: git remote
  13     1        Bash: git init
  14     1        Skill
  15     1        Bash: git clone

======================================================================
  SUGGESTED ALLOWLIST ADDITIONS
  Frequently approved commands that could be auto-allowed
======================================================================
  Count    Project                        Suggested Pattern
  -----    -------                        -----------------
  365      bench                          Bash(tail *)
  349      cli                            Bash(ssh *@192.168.86.122 *) or Bash(ssh 192.168.86.122 *)
  128      forge                          Bash(python *)
  121      laima                          Bash(ls *)
  119      laima                          Bash(sleep *)
  102      defectdojo                     Bash(ssh *@192.168.86.122 *) or Bash(ssh 192.168.86.122 *)
  90       laima                          Bash(git diff *)
  90       laima                          Bash(grep *)
  87       laima                          Bash(cat *)
  85       bench                          Bash(ssh *)
  83       bench                          Bash(wc *)

======================================================================
  PER-PROJECT SUMMARY
======================================================================
  Project                                Total     Auto Prompted Rejected
  -----------------------------------    -----     ---- -------- --------
  (home)                                   110       19       90        1
  app-security-scanning                    233       54      174        5
  claude-mod                               170       39      130        1
  laima                                   5877     2741     3109       44
  laima-ansible                             16        8        8        0
  laima-hermes-cli                        1448      220     1220        9
  laima-inference-bench                   1079      131      942        6
  laima-titan                             2210      716     1485        9
  mcp-defectdojo                           197       10      187        0
  vsdx-forge                              1208      273      931        4

======================================================================
  TOOL TYPE BREAKDOWN (prompted only)
======================================================================
  Tool                            Prompted Count
  ------------------------------ ---------------
  Bash                                      5276
  Edit                                      1608
  Write                                      629
  TaskUpdate                                 217
  Agent                                      205
  ToolSearch                                 145
  TaskCreate                                 108
```
