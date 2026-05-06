# Environment Variables and `.env` Files

How to handle env vars and dotenv files without triggering the secret-blocking hook.

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
