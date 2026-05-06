# Ansible Vault

How to use Ansible Vault without triggering the secret-blocking hook.

## What works

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

## What breaks

```bash
# BLOCKED — pasting a decrypted value into a command
VAULT_TOKEN=hvs.decryptedvalue vault kv put secret/new key=value
```

Subshell captures are fine — the literal token never appears in the command text:

```bash
# Works — the secret stays inside the subshell, Claude only sees the outer command
export VAULT_ROOT=$(ansible-vault view group_vars/vault/vault.yml \
  --vault-password-file ~/.ansible-vault-password | grep root_token | awk '{print $2}')
```

## Safe pattern: chain through variables

```bash
# Works — variable assignment from subshell, then reference
ROOT_TOKEN=$(ansible-vault view group_vars/vault/vault.yml \
  --vault-password-file ~/.ansible-vault-password \
  | python3 -c "import yaml,sys; print(yaml.safe_load(sys.stdin.read())['vault_root_token'])")

# Works — $ROOT_TOKEN is a reference, not a literal
VAULT_TOKEN=$ROOT_TOKEN vault kv put secret/new key=value
```
