# autoclaude

A CLI tool that tells you where you're spending approval clicks in Claude Code — and what to do about it. It also catches secret leaks in your session history and provides hooks to prevent them in real time.

## Quick start

```bash
# See where your approval friction is
python3 claude-approval-report.py --summary

# See what's trending over the last week
python3 claude-approval-report.py --trend 7d

# Check for leaked secrets
python3 claude-approval-report.py --secrets
```

Python 3.11+, stdlib only, no dependencies.

## Install the hooks

The two hooks form a layered defense against secret exposure in Claude Code sessions:

| Hook | Event | Purpose |
|------|-------|---------|
| `block-secrets.py` | PreToolUse | Blocks commands that would leak secrets *before* they run |
| `warn-secrets-output.py` | PostToolUse | Warns when command *output* contains secrets (can't undo, advises rotation) |

Add both to `~/.claude/settings.json`:

```json
{
  "hooks": {
    "PreToolUse": [{
      "matcher": "Bash|Read|Edit|Write",
      "hooks": [{"type": "command", "command": "python3 /path/to/autoclaude/hooks/block-secrets.py"}]
    }],
    "PostToolUse": [{
      "matcher": "Bash|Read|Edit",
      "hooks": [{"type": "command", "command": "python3 /path/to/autoclaude/hooks/warn-secrets-output.py"}]
    }]
  }
}
```

Then add deny rules for Read/Write/Edit access to sensitive files:

```bash
python3 claude-approval-report.py --generate-settings
```

See [docs/hooks.md](docs/hooks.md) for detection details, limitations, and configuration.

## Report modes

| Flag | What it shows |
|------|---------------|
| *(none)* | Full ranked tables — most prompted, rejected, risk breakdown, suggestions |
| `--summary` | 12-line dashboard with counts, risk, top commands |
| `--trend [window]` | Time-series table of approval rates, risk, and secrets per day/week/month |
| `--secrets` | Every detected secret exposure with risk classification (exposed/runtime/variable/pipe-safe) |
| `--warns` | Hook warning events cross-referenced with user approval decisions |
| `--why "cmd"` | Diagnose why a specific command gets prompted |
| `--apply` | Write suggested allowlist patterns to settings files |
| `--generate-settings` | Emit deny rules + hook config as mergeable JSON |
| `--json` | Machine-readable output for all modes |

All modes accept `--since` (e.g. `7d`, `2w`, `2026-05-01`), `--project`, and `--session` filters.

See [docs/cli-reference.md](docs/cli-reference.md) for full usage and examples.

## How it works

Claude Code stores session transcripts as JSONL under `~/.claude/projects/`. This script parses them to correlate tool calls with approval decisions:

1. Loads allowlists from `~/.claude/settings.json` and per-project `settings.local.json`
2. Parses all session JSONL files (including subagent transcripts)
3. Classifies each call as auto-allowed, prompted, or rejected
4. Classifies risk: destructive, mutating, or read-only (flag-aware for git, curl, ansible, etc.)
5. Detects secrets via 22 provider-specific token patterns, JWT detection, entropy analysis
6. Groups by normalized command prefix for aggregation
7. Renders the selected output mode

## CI/CD

Forgejo Actions runs 591 tests across 8 suites on every push. Failures are reported to DefectDojo. See `.forgejo/workflows/test.yml`.

## Docs

- [CLI reference](docs/cli-reference.md) — all flags, filters, output modes, and examples
- [Hook detection reference](docs/hooks.md) — what the hooks catch, allow, and can't detect
- [Architecture](docs/architecture.md) — layered defense model and deployment diagrams
- [Auth best practices](docs/auth-best-practices.md) — working with secrets when the hooks are active
