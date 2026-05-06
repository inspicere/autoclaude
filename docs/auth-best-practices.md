# Auth Best Practices for Claude Code with Secret Blocking

This guide covers how to work with authenticated services when the `block-secrets.py` PreToolUse hook and deny rules are active. Every pattern below has been tested against the hook's detection logic.

> **Note for external users:** The examples use a specific homelab environment (HashiCorp Vault, Forgejo, DefectDojo, internal IPs). Substitute your own services and hostnames — the patterns and security properties are the same regardless of environment.

## What gets blocked

The hook blocks Bash commands containing:
- **Known token prefixes**: `ghp_`, `hvs.`, `sk-ant-`, `AKIA`, `xoxb-`, 20+ others
- **JWTs**: the `eyJ...` three-part pattern
- **Inline secret assignments**: `VAULT_TOKEN=actualvalue` (but not `VAULT_TOKEN=$VAULT_TOKEN`)
- **Auth headers in curl**: `curl -H "Authorization: Bearer <token>"`
- **High-entropy strings**: 32+ char base64 blobs with Shannon entropy >= 3.5
- **Sensitive file reads**: `cat .env`, `head ~/.ssh/id_rsa`, etc.

The deny rules block Read/Write/Edit of `.env*`, `.pem`, `.key`, `.ssh/id_*`, `.vault-token`, `credentials.json`, and similar files.

## Quick reference

| Blocked | Use instead |
|---------|-------------|
| `VAULT_TOKEN=hvs.xxx vault kv get secret/db` | `vault kv get secret/db` (agent/file token) |
| `curl -H "Authorization: Token abc123..."` | `curl -n` with `.netrc`, or wrapper script |
| `curl -H "Authorization: Bearer $TOKEN"` | This is fine — variable reference, not a literal |
| `cat .env` | `grep SPECIFIC_VAR .env` (grep is exempt) |
| `export API_KEY=sk-ant-api03-...` | `export API_KEY=$(vault kv get -field=key secret/api)` |
| `DD_TOKEN="d688..." curl ...` | Source from file or Vault, use MCP server |
| `ansible-vault view file.yml --vault-password-file ~/.ansible-vault-password` | This works — the flag points to a file path |

## Guides by service

- [HashiCorp Vault](auth-vault.md) — file-based tokens, vault login, MCP server
- [API services](auth-api-services.md) — curl with Vault, `.netrc`, wrapper scripts, MCP servers
- [Ansible Vault](auth-ansible.md) — `--vault-password-file`, subshell captures, variable chaining
- [SSH](auth-ssh.md) — key paths, `ssh-agent`, what's blocked
- [Environment variables and `.env` files](auth-env-vars.md) — shell profile setup, grep exemption, Vault-populated dotenv

## Reference

- [Architecture overview](architecture.md) — how deny rules, the hook, and MCP servers form a layered defense
- [Secrets without writing to disk](auth-diskless-secrets.md) — process substitution, env injection tools, kernel keyring, agent sockets, tmpfs

## Summary of safe patterns

1. **Never inline literal tokens** — use `$VAR` references or subshell captures
2. **Use Vault** as the secret source — `$(vault kv get -field=x secret/path)`
3. **Use MCP servers** for services that have them (Vault, Forgejo, Vikunja, DefectDojo)
4. **Use file-based auth** — `~/.vault-token`, `~/.netrc`, `--vault-password-file`
5. **Use `grep`** to inspect secret files — it's exempt from both file-read and secret-content blocking
6. **Use wrapper scripts** for frequently-called APIs to keep tokens out of command history
7. **Set secrets in your shell profile** before launching Claude Code, then reference them as `$VARS`
