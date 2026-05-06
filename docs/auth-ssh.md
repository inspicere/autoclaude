# SSH

How to use SSH keys without triggering the secret-blocking hook.

## What works

```bash
# Works — key-based auth uses the agent, no key content in command
ssh terrabot@192.168.86.122 hostname

# Works — specifying a key file by path is fine
ssh -i ~/.ssh/deploy_key terrabot@192.168.86.122 hostname

# Works — reading the public key is not blocked
cat ~/.ssh/id_ed25519.pub
```

## What breaks

```bash
# BLOCKED — reading the private key
cat ~/.ssh/id_ed25519

# BLOCKED — base64 encoding a private key (high-entropy output)
base64 ~/.ssh/id_rsa

# BLOCKED — the Read tool on private keys
Read(file_path="/home/terrabot/.ssh/id_ed25519")
```

## Best approach

Never read private key contents. Use `ssh-agent` and key paths:

```bash
# Add key to agent (prompts for passphrase interactively, not in command)
ssh-add ~/.ssh/id_ed25519

# Verify which keys are loaded
ssh-add -l

# All subsequent ssh/scp/rsync uses the agent
ssh terrabot@192.168.86.122
```
