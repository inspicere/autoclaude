# autoclaude

A CLI tool for shifting friction where it matters. autoclaude identifies where your agent spends time waiting for you to hit enter and what to do about it, while increasing friction when handling secrets. Less clicking, fewer leaks, speed and safety balanced.

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

## Results

Over 33 days and ~39k tool calls across 10 projects:

- **7-day rolling auto-allow rate climbed from 71% to 85.5%**, a 14pp increase as allowlist patterns were tuned with `--apply`
- **84.8% overall auto-allow rate**, up from 63% in the first days of use
- **384 genuine secret exposures identified** in session history (auth headers, high-entropy blobs, known token patterns), with 27 false positives automatically filtered
- **Only 1 rejection** out of nearly 6,000 prompted commands, meaning approval friction is the main cost, not blocked work

See [docs/example-reports.md](docs/example-reports.md) for full sample output from `--trend`, `--summary`, and `--secrets`.

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

### Landlock kernel sandbox (prototype)

The static-analysis hooks can't catch runtime indirection: shell function calls (`r() { cat "$1"; }; r .env`), bash array expansion, or interpreter path construction. The Landlock sandbox solves this at the kernel level — it restricts `open()` syscalls regardless of how the path was derived.

```bash
# Run a command with Landlock restrictions (denies read on sensitive files)
python3 hooks/landlock-sandbox.py -c "r() { cat \"\$1\"; }; r ~/.env"
# cat: /home/user/.env: Permission denied

# Safe commands work normally
python3 hooks/landlock-sandbox.py -c "echo hello && ls /tmp"
# hello
# ...
```

Requires Linux 5.13+ with Landlock enabled (kernel 6.1+ recommended for ABI v4+). No privileges needed. Currently a standalone prototype — see [the upstream proposal](https://github.com/anthropics/claude-code/issues/57901) for integrating this as a hook sandbox directive.

## Report modes

| Flag | What it shows |
|------|---------------|
| *(none)* | Full ranked tables: most prompted, rejected, risk breakdown, suggestions |
| `--summary` | 12-line dashboard with counts, risk, top commands |
| `--trend [window]` | Time-series table of approval rates, risk, and secrets per day/week/month |
| `--secrets` | Every detected secret exposure with risk classification (exposed/runtime/variable/pipe-safe/false-pos) |
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

## Red team results

Three rounds of multi-agent adversarial testing (8 parallel agents per round, mixed Opus/Sonnet) found 33 bypass vectors — all remediated. The hooks grew from ~500 to ~1450 lines. 15 remaining gaps are either unfixable by static analysis (solved by Landlock) or architectural (MCP passthrough).

## CI/CD

Forgejo Actions runs 789 tests across 11 suites on every push. Failures are reported to DefectDojo. See `.forgejo/workflows/test.yml`.

## Docs

- [CLI reference](docs/cli-reference.md) - all flags, filters, output modes, and examples
- [Example reports](docs/example-reports.md) - sample output from trend, summary, and secrets modes
- [Hook detection reference](docs/hooks.md) - what the hooks catch, allow, and can't detect
- [Architecture](docs/architecture.md) - layered defense model and deployment diagrams
- [Auth best practices](docs/auth-best-practices.md) - working with secrets when the hooks are active
