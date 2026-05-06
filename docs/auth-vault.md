# HashiCorp Vault

How to use the Vault CLI and MCP server without triggering the secret-blocking hook.

## Problem: inline tokens

```bash
# BLOCKED — literal hvs. token in command
VAULT_TOKEN=hvs.CAESILzf... vault kv get secret/db

# BLOCKED — export with literal value
export VAULT_TOKEN="hvs.7wblICSnSPjPWeODAg4rIXCw"
```

## Solution: file-based or agent token

The Vault CLI reads `~/.vault-token` automatically. If a valid token exists there, no env var is needed:

```bash
# Works — no token in command, Vault reads ~/.vault-token
vault kv get secret/db

# Works — token comes from a variable, not a literal
vault kv get -field=password secret/db/postgres
```

If you need to set the token explicitly, source it from Vault's own token file or from a prior login:

```bash
# Works — variable reference, not a literal
export VAULT_TOKEN=$(cat ~/.vault-token)
vault kv get secret/db

# Works — vault login stores token in ~/.vault-token for subsequent commands
vault login -method=userpass username=terrabot
vault kv get secret/db
```

## Best option: use the Vault MCP server

The `vault` MCP server (mcp-01:3100) is already configured and handles auth internally:

```
# No token management needed — MCP server authenticates to Vault directly
mcp__vault__vault_read(path="secret/db/postgres")
```
