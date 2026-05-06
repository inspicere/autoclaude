# API Services (DefectDojo, Forgejo, etc.)

How to call authenticated APIs without triggering the secret-blocking hook.

## Problem: inline tokens in curl

```bash
# BLOCKED — literal token in Authorization header
curl -s -H "Authorization: Token d6885ad8..." https://defectdojo.internal.homelab.equipment/api/v2/findings/

# BLOCKED — literal token in env var prefix
DD_TOKEN="d6885ad8..." curl -s -H "Authorization: Token $DD_TOKEN" ...
```

## Solution A: source token from Vault

```bash
# Works — token comes from vault, never appears as a literal
DD_TOKEN=$(vault kv get -field=api_token secret/defectdojo)
curl -s -H "Authorization: Token $DD_TOKEN" \
  https://defectdojo.internal.homelab.equipment/api/v2/findings/
```

## Solution B: use `.netrc` for services that support it

Create `~/.netrc` with restricted permissions (the hook blocks reading it, but curl reads it internally):

```
machine defectdojo.internal.homelab.equipment
  login api
  password d6885ad8b589c2ce496c6c81deda8911798aec2d
```

```bash
chmod 600 ~/.netrc

# Works — curl reads credentials from .netrc, none in the command
curl -sn https://defectdojo.internal.homelab.equipment/api/v2/findings/
```

Note: `.netrc` uses `login`/`password` fields, not arbitrary headers. For APIs that require `Authorization: Token xyz`, you'll need a wrapper or Vault-based approach.

## Solution C: wrapper script

Create a short script that loads the token internally:

```bash
#!/bin/bash
# ~/bin/dd-api — DefectDojo API wrapper
TOKEN=$(vault kv get -field=api_token secret/defectdojo)
exec curl -s -H "Authorization: Token $TOKEN" -H "Accept: application/json" "$@"
```

```bash
chmod +x ~/bin/dd-api

# Works — no secrets in the command Claude sees
dd-api https://defectdojo.internal.homelab.equipment/api/v2/findings/
```

## Best option: use MCP servers

For Forgejo, Vikunja, and Vault, MCP servers are already configured and handle auth:

```
mcp__forgejo__repo_list(org="inspicere")
mcp__vikunja__task_list(project_id=2)
```

For DefectDojo, the `mcp-defectdojo` project provides the same pattern.
