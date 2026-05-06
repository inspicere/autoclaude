# Auth Best Practices for Claude Code with Secret Blocking

This guide covers how to work with authenticated services when the `block-secrets.py` PreToolUse hook and deny rules are active. Every pattern below has been tested against the hook's detection logic.

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

## HashiCorp Vault

### Problem: inline tokens

```bash
# BLOCKED — literal hvs. token in command
VAULT_TOKEN=hvs.CAESILzf... vault kv get secret/db

# BLOCKED — export with literal value
export VAULT_TOKEN="hvs.7wblICSnSPjPWeODAg4rIXCw"
```

### Solution: file-based or agent token

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

### Best option: use the Vault MCP server

The `vault` MCP server (mcp-01:3100) is already configured and handles auth internally:

```
# No token management needed — MCP server authenticates to Vault directly
mcp__vault__vault_read(path="secret/db/postgres")
```

## API services (DefectDojo, Forgejo, etc.)

### Problem: inline tokens in curl

```bash
# BLOCKED — literal token in Authorization header
curl -s -H "Authorization: Token d6885ad8..." https://defectdojo.internal.homelab.equipment/api/v2/findings/

# BLOCKED — literal token in env var prefix
DD_TOKEN="d6885ad8..." curl -s -H "Authorization: Token $DD_TOKEN" ...
```

### Solution A: source token from Vault

```bash
# Works — token comes from vault, never appears as a literal
DD_TOKEN=$(vault kv get -field=api_token secret/defectdojo)
curl -s -H "Authorization: Token $DD_TOKEN" \
  https://defectdojo.internal.homelab.equipment/api/v2/findings/
```

### Solution B: use `.netrc` for services that support it

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

### Solution C: wrapper script

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

### Best option: use MCP servers

For Forgejo, Vikunja, and Vault, MCP servers are already configured and handle auth:

```
mcp__forgejo__repo_list(org="inspicere")
mcp__vikunja__task_list(project_id=2)
```

For DefectDojo, the `mcp-defectdojo` project provides the same pattern.

## Ansible Vault

### What works

```bash
# Works — --vault-password-file points to a file, no inline secret
ansible-playbook playbooks/deploy.yml \
  --vault-password-file ~/.ansible-vault-password

# Works — ansible-vault view with file-based password
ansible-vault view group_vars/vault/vault.yml \
  --vault-password-file ~/.ansible-vault-password

# Works — the venv python path is fine
~/.ansible-venv/bin/python3 -m ansible playbook playbooks/vault.yml \
  --vault-password-file ~/.ansible-vault-password
```

### What breaks

```bash
# BLOCKED — piping a decrypted vault value into an env var with a literal
export VAULT_ROOT=$(ansible-vault view ... | grep root_token | awk '{print $2}')
# This actually works — the literal token doesn't appear in the command.
# It would only break if the subshell output were then used inline.

# BLOCKED — pasting a decrypted value into a command
VAULT_TOKEN=hvs.decryptedvalue vault kv put secret/new key=value
```

### Safe pattern: chain through variables

```bash
# Works — variable assignment from subshell, then reference
ROOT_TOKEN=$(ansible-vault view group_vars/vault/vault.yml \
  --vault-password-file ~/.ansible-vault-password \
  | python3 -c "import yaml,sys; print(yaml.safe_load(sys.stdin.read())['vault_root_token'])")

# Works — $ROOT_TOKEN is a reference, not a literal
VAULT_TOKEN=$ROOT_TOKEN vault kv put secret/new key=value
```

## SSH

### What works

```bash
# Works — key-based auth uses the agent, no key content in command
ssh terrabot@192.168.86.122 hostname

# Works — specifying a key file by path is fine
ssh -i ~/.ssh/deploy_key terrabot@192.168.86.122 hostname

# Works — reading the public key is not blocked
cat ~/.ssh/id_ed25519.pub
```

### What breaks

```bash
# BLOCKED — reading the private key
cat ~/.ssh/id_ed25519

# BLOCKED — base64 encoding a private key (high-entropy output)
base64 ~/.ssh/id_rsa

# BLOCKED — the Read tool on private keys
Read(file_path="/home/terrabot/.ssh/id_ed25519")
```

### Best approach

Never read private key contents. Use `ssh-agent` and key paths:

```bash
# Add key to agent (prompts for passphrase interactively, not in command)
ssh-add ~/.ssh/id_ed25519

# Verify which keys are loaded
ssh-add -l

# All subsequent ssh/scp/rsync uses the agent
ssh terrabot@192.168.86.122
```

## Environment variables

### Pattern: source from file at shell level, reference in commands

The hook blocks literal secret values but allows variable references. Set secrets in your shell profile or source them before starting Claude Code:

```bash
# In ~/.bashrc or before launching claude (outside Claude's view):
export VAULT_ADDR=http://192.168.86.130:8200
export VAULT_TOKEN=$(cat ~/.vault-token)
```

Then in Claude Code sessions:

```bash
# Works — all variable references
vault kv get -address=$VAULT_ADDR secret/db
curl -H "Authorization: Token $DD_TOKEN" https://defectdojo.internal.homelab.equipment/api/v2/
```

### Pattern: load secrets inside a subshell or script

```bash
# Works — the literal never appears in the outer command
python3 -c "
import os, subprocess
token = subprocess.check_output(['vault', 'kv', 'get', '-field=token', 'secret/api']).decode().strip()
# use token...
"
```

## `.env` files

### What works

```bash
# Works — grep is exempt from secret scanning, shows only the line you need
grep DATABASE_URL .env

# Works — checking which variables are defined (names only)
grep -oP '^\w+(?==)' .env

# Works — .env.example files are explicitly allowed in the global settings
cat .env.example

# Works — creating a new .env from example
cp .env.example .env
```

### What breaks

```bash
# BLOCKED — full file read
cat .env
head .env
source .env

# BLOCKED — Read tool
Read(file_path=".env")
```

### Best approach

Use `.env.example` as the template (allowed by deny rules). Load actual values from Vault:

```bash
# Populate .env from Vault, without secrets passing through Claude
python3 -c "
import subprocess, json
data = json.loads(subprocess.check_output(
    ['vault', 'kv', 'get', '-format=json', 'secret/myapp']
).decode())['data']['data']
with open('.env', 'w') as f:
    for k, v in data.items():
        f.write(f'{k}={v}\n')
print('Wrote', len(data), 'vars to .env')
"
```

## Secrets without writing to disk

Beyond the Claude-specific patterns above, several tools and OS primitives handle secrets entirely in memory. These are useful when building wrapper scripts or configuring services in the homelab.

### Process substitution and file descriptors

Bash `<()` creates a `/dev/fd/N` pipe — no file touches persistent storage:

```bash
# Feed a Vault secret as a "file" without writing it anywhere
my-app --config <(vault kv get -format=json secret/config)

# Pass a passphrase via fd instead of a flag
gpg --batch --passphrase-fd 3 --decrypt file.gpg 3<<<"$PASSPHRASE"

# Ansible vault password from a pipe
ansible-playbook site.yml --vault-password-file <(cat <<< "$VAULT_PASS")
```

The secret lives in kernel pipe buffers and is freed when the pipe closes. Note: `/proc/<pid>/fd/` exposes descriptors to root and same-UID processes, and some tools that call `lseek()` will fail on non-seekable fds.

### Environment injection tools

These fetch secrets from a remote store and inject them as env vars into a subprocess. The secret exists only in process memory:

| Tool | Example |
|------|---------|
| `aws-vault` | `aws-vault exec prod -- aws s3 ls` |
| `sops exec-env` | `sops exec-env secrets.enc.yaml 'echo $DB_PASSWORD'` |
| `op run` (1Password) | `op run --env-file=.env.tpl -- ./my-app` |
| `doppler run` | `doppler run -- node server.js` |

When the subprocess exits, the env vars die with it. Caveat: `/proc/<pid>/environ` is readable by root and same-UID processes, and core dumps can capture env vars (disable with `ulimit -c 0`).

### Linux kernel keyring

The kernel keyring stores secrets in kernel memory, inaccessible to user-space memory scanners:

```bash
# Store with auto-expiry (300 seconds)
keyctl add user myapp-db-pass "$(vault kv get -field=password secret/db)" @s
keyctl timeout $(keyctl search @s user myapp-db-pass) 300

# Retrieve
keyctl print $(keyctl search @s user myapp-db-pass)
```

`git-credential-cache` uses a similar approach — a daemon holds credentials in memory via a Unix socket, unlike `credential-store` which writes to `~/.git-credentials`.

### Agent sockets

Agent processes hold key material in memory and perform operations on behalf of clients via a Unix socket. The private key never leaves the agent:

```bash
# SSH — key loaded into agent, auto-expires after 1 hour
ssh-add -t 3600 ~/.ssh/id_ed25519

# Vault agent — caches tokens in memory, apps hit the local socket
vault agent -config=agent.hcl
```

Avoid `ssh -A` (agent forwarding) to untrusted hosts — anyone with access to the forwarded socket can use your keys for signing.

### tmpfs for ephemeral files

`/run` is already tmpfs on Debian/systemd. For scripts that must write a secret to a file path:

```bash
install -m 0700 -d /run/secrets/myapp
vault kv get -field=cert secret/tls > /run/secrets/myapp/cert.pem
# Use it, then clean up
rm /run/secrets/myapp/cert.pem
```

Under memory pressure, tmpfs pages can be swapped to disk. If that matters, disable swap or use `ramfs` (which is never swapped but has no size limit — use with caution).

## Summary of safe patterns

1. **Never inline literal tokens** — use `$VAR` references or subshell captures
2. **Use Vault** as the secret source — `$(vault kv get -field=x secret/path)`
3. **Use MCP servers** for services that have them (Vault, Forgejo, Vikunja, DefectDojo)
4. **Use file-based auth** — `~/.vault-token`, `~/.netrc`, `--vault-password-file`
5. **Use `grep`** to inspect secret files — it's exempt from both file-read and secret-content blocking
6. **Use wrapper scripts** for frequently-called APIs to keep tokens out of command history
7. **Set secrets in your shell profile** before launching Claude Code, then reference them as `$VARS`
