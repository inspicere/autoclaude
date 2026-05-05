# autoclaude: Claude Code Approval Analyzer

## Goal
Script that parses Claude Code session data to show which commands required the most user approval prompts, which were rejected most, and suggest allowlist additions to reduce friction.

## Data Sources
- **Session JSONL files**: `~/.claude/projects/*/*.jsonl` (291 files, 153MB, 64K lines)
- **Global settings**: `~/.claude/settings.json` — global permission allowlist/denylist
- **Per-project settings**: `<project>/.claude/settings.local.json` — project-level allowlists
- **Project-level hooks settings**: `~/.claude/projects/<project>/settings.json` — hooks and per-project overrides

## Session Data Format

Each `.jsonl` file contains interleaved records. Tool call flow:

1. `type: "assistant"` — `message.content[]` has `type: "tool_use"` entries with `name`, `input`, `id`
2. `type: "user"` — follows with result:
   - **Approved**: `toolUseResult` is dict (file/stdout) or string with output
   - **Error (but ran)**: `toolUseResult` starts with `"Error: ..."`
   - **Rejected**: `toolUseResult` = `"User rejected tool use"`, `message.content[].is_error=true`
3. `sourceToolAssistantUUID` on user records links back to assistant record `uuid`

## Implementation Steps

1. **Parse allowlists** — Load `~/.claude/settings.json` global allow patterns + each project's `settings.local.json`. Build pattern matchers.
2. **Index sessions** — Walk every `.jsonl`, index assistant records by UUID for tool_use lookups.
3. **Classify tool calls** — For each user record with `sourceToolAssistantUUID`:
   - Look up originating tool call (name + input)
   - Match against allowlist patterns → auto-allowed vs prompted
   - Check toolUseResult for rejection → rejected
4. **Normalize commands** — For Bash calls, extract command prefix for grouping. For other tools, use tool name + key args.
5. **Aggregate & render** — Top-N tables for prompts, rejections, and suggested allowlist additions.

## Allowlist Pattern Matching

Patterns use Claude Code format:
- `Bash(git add:*)` or `Bash(git add *)` — matches Bash commands starting with `git add`
- `mcp__vault__vault_read` — exact tool name match
- `Read(**/.env.example)` — glob on file path argument
- `WebFetch(domain:example.com)` — domain-scoped web fetch

## Output

Terminal report with ranked tables:

```
=== Most Prompted Commands (top 20) ===
  Rank  Count  Tool / Command Pattern
  1     47     Bash: ansible-playbook *
  2     31     Bash: git commit *

=== Most Rejected (top 10) ===
  Rank  Count  Tool / Command
  1     5      Bash: cd /home/terrabot/laima && git log ...

=== Suggested Allowlist Additions ===
  Pattern                          Approvals   Project
  Bash(find *)                     23          laima

=== Per-Project Summary ===
  Project       Total Calls  Prompted  Rejected  Auto-Allowed
  laima         5432         312       12        5108
```
