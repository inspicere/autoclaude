# Reference Architecture: Secret Protection for Claude Code

This document shows how the protection layers in this project fit together, using the Laima homelab as a concrete example. The same layered model applies to any environment — swap the services and hostnames for your own.

## Overview

```
┌─────────────────────────────────────────────────────────────┐
│                     Claude Code Session                      │
│                                                             │
│  Tool calls: Bash, Read, Write, Edit, MCP, Agent, ...       │
└──────────────┬──────────────────────────────────┬───────────┘
               │                                  │
               ▼                                  ▼
┌──────────────────────────┐    ┌──────────────────────────────┐
│   Layer 1: Deny Rules    │    │   Layer 3: MCP Servers       │
│   (~/.claude/settings)   │    │   (auth handled server-side) │
│                          │    │                              │
│ Blocks Read/Write/Edit   │    │ vault    → Vault :8200       │
│ of sensitive file globs: │    │ forgejo  → Forgejo :3000     │
│  .env*, .pem, .key,      │    │ vikunja  → Vikunja API       │
│  .ssh/**, .aws/**,       │    │                              │
│  credentials/**, etc.    │    │ Tokens live in the MCP       │
│                          │    │ server config, never in      │
│ ✗ Cannot inspect Bash    │    │ Claude's tool calls.         │
│   command content        │    │                              │
└──────────────┬───────────┘    └──────────────────────────────┘
               │
               ▼
┌──────────────────────────┐
│  Layer 2: PreToolUse     │
│  Hook (block-secrets.py) │
│                          │
│ Inspects Bash commands,  │
│ Read paths, Edit paths   │
│ BEFORE execution.        │
│                          │
│ Blocks:                  │
│  • 22 token prefixes     │
│    (ghp_, hvs., AKIA,    │
│     sk-ant-, xoxb-, ...) │
│  • JWTs (eyJ...)         │
│  • Private key headers   │
│  • curl auth headers     │
│  • Secret var assigns    │
│  • High-entropy blobs    │
│  • Bash file reads of    │
│    sensitive paths       │
│  • File copy/move/link   │
│    of sensitive paths    │
│  • Subshell/eval/interp  │
│    unwrap + re-check     │
│  • Stdin redirection     │
│                          │
│ Exempts:                 │
│  • grep/rg/ag/ack/find   │
│  • Variable references   │
│    ($TOKEN, ${SECRET})   │
│  • URLs in assignments   │
│  • Placeholder values    │
└──────────────────────────┘
```

## What each layer protects against

| Scenario | Deny Rules | Hook | MCP Servers |
|----------|:----------:|:----:|:-----------:|
| `Read .env` | **blocks** | — | — |
| `Edit ~/.ssh/id_rsa` | **blocks** | — | — |
| `cat .env` (via Bash) | — | **blocks** | — |
| `cp .env /tmp/x` (via Bash) | — | **blocks** | — |
| `bash -c 'cat .env'` (subshell) | — | **blocks** | — |
| `python3 -c "open('.env').read()"` | — | **blocks** | — |
| `VAULT_TOKEN=hvs.xxx vault kv get` | — | **blocks** | — |
| `curl -H "Authorization: Bearer <literal>"` | — | **blocks** | — |
| Need to read a Vault secret | — | — | **safe path** |
| Need to query Forgejo API | — | — | **safe path** |
| `grep PASSWORD .env` | allowed | exempt | — |
| `$TOKEN` variable reference | allowed | exempt | — |
| `vault kv get` (output has secrets) | — | not covered | **safe path** |

## Homelab deployment

```
┌─────────────────────────────────┐
│  ansible (192.168.86.78)        │
│  VM 200 — Claude Code host      │
│                                 │
│  ~/.claude/settings.json        │
│    ├─ permissions.deny (15)     │
│    ├─ permissions.allow (29)    │
│    └─ hooks[] → block-secrets   │
│                                 │
│  ~/.mcp.json                    │
│    ├─ vault   → mcp-01:3100    │
│    ├─ forgejo → mcp-01:3200    │
│    └─ vikunja → mcp-01:3300    │
└───────────────┬─────────────────┘
                │
     ┌──────────┼──────────────────────┐
     │          │                      │
     ▼          ▼                      ▼
┌─────────┐ ┌──────────────┐  ┌──────────────┐
│vault-01 │ │   mcp-01     │  │   git-01     │
│ .130    │ │   .127       │  │   .124       │
│         │ │              │  │              │
│ Vault   │ │ vault-mcp    │  │ Forgejo      │
│ :8200   │ │ :3100        │  │ :3000/:222   │
│         │ │ forgejo-mcp  │  │              │
│         │ │ :3200        │  │              │
│         │ │ vikunja-mcp  │  │              │
│         │ │ :3300        │  │              │
└─────────┘ └──────────────┘  └──────────────┘
```

### Secret flow: the safe path

When Claude needs a secret (e.g., a database password):

```
Claude Code                MCP Server (mcp-01)         Vault (vault-01)
    │                           │                           │
    │  mcp__vault__vault_read   │                           │
    │  path="secret/db"         │                           │
    │ ─────────────────────────►│                           │
    │                           │  GET /v1/secret/data/db   │
    │                           │  X-Vault-Token: <token>   │
    │                           │ ─────────────────────────►│
    │                           │                           │
    │                           │  {"data": {"password":... │
    │                           │◄─────────────────────────│
    │  {"password": "..."}      │                           │
    │◄─────────────────────────│                           │
    │                           │                           │
```

The Vault token lives in the MCP server's config on mcp-01. It never appears in Claude's tool calls, session JSONL, or conversation context.

### Secret flow: what gets blocked

When Claude tries to use a literal token:

```
Claude Code              Hook (block-secrets.py)
    │                           │
    │  Bash: VAULT_TOKEN=hvs.   │
    │  CAESILzf... vault kv get │
    │ ─────────────────────────►│
    │                           │  Regex match: hvs.[\w-]{90,120}
    │                           │
    │  exit(2) + stderr:        │
    │  "BLOCKED: Command        │
    │   contains a known API    │
    │   token/key pattern"      │
    │◄─────────────────────────│
    │                           │
    │  (command never executes) │
```

## Adapting to your environment

To deploy this in a different environment:

1. **Deny rules** — Copy from `settings/recommended-deny.json` into your `~/.claude/settings.json`. Add allow rules for `.env.example` or other safe patterns you need.

2. **Hook** — Install `hooks/block-secrets.py` and add the hook entry to `~/.claude/settings.json`:
   ```json
   {
     "hooks": {
       "PreToolUse": [{
         "matcher": "Bash|Read|Edit",
         "hooks": [{"type": "command", "command": "python3 /path/to/hooks/block-secrets.py"}]
       }]
     }
   }
   ```

3. **MCP servers** — Optional but recommended. Any MCP server that handles auth server-side keeps tokens out of Claude's context entirely. The pattern works with any secret backend, not just Vault.

4. **Report** — Run `python3 claude-approval-report.py --generate-settings` to get a combined settings fragment with deny rules and hook config tailored to your session data.

## Files in this project

| File | Role in the architecture |
|------|-------------------------|
| `hooks/block-secrets.py` | Layer 2 — the PreToolUse hook |
| `settings/recommended-deny.json` | Layer 1 — reference deny rules |
| `claude-approval-report.py` | Analysis — reports what got through, suggests improvements |
| `docs/auth-best-practices.md` | Index of safe patterns for working within the layers |
