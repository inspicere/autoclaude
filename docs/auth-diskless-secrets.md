# Secrets Without Writing to Disk

Tools and OS primitives that handle secrets entirely in memory. Useful when building wrapper scripts or configuring services.

## Process substitution and file descriptors

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

## Environment injection tools

These fetch secrets from a remote store and inject them as env vars into a subprocess. The secret exists only in process memory:

| Tool | Example |
|------|---------|
| `aws-vault` | `aws-vault exec prod -- aws s3 ls` |
| `sops exec-env` | `sops exec-env secrets.enc.yaml 'echo $DB_PASSWORD'` |
| `op run` (1Password) | `op run --env-file=.env.tpl -- ./my-app` |
| `doppler run` | `doppler run -- node server.js` |

When the subprocess exits, the env vars die with it. Caveat: `/proc/<pid>/environ` is readable by root and same-UID processes, and core dumps can capture env vars (disable with `ulimit -c 0`).

## Linux kernel keyring

The kernel keyring stores secrets in kernel memory, inaccessible to user-space memory scanners:

```bash
# Store with auto-expiry (300 seconds)
keyctl add user myapp-db-pass "$(vault kv get -field=password secret/db)" @s
keyctl timeout $(keyctl search @s user myapp-db-pass) 300

# Retrieve
keyctl print $(keyctl search @s user myapp-db-pass)
```

`git-credential-cache` uses a similar approach — a daemon holds credentials in memory via a Unix socket, unlike `credential-store` which writes to `~/.git-credentials`.

## Agent sockets

Agent processes hold key material in memory and perform operations on behalf of clients via a Unix socket. The private key never leaves the agent:

```bash
# SSH — key loaded into agent, auto-expires after 1 hour
ssh-add -t 3600 ~/.ssh/id_ed25519

# Vault agent — caches tokens in memory, apps hit the local socket
vault agent -config=agent.hcl
```

Avoid `ssh -A` (agent forwarding) to untrusted hosts — anyone with access to the forwarded socket can use your keys for signing.

## tmpfs for ephemeral files

`/run` is already tmpfs on Debian/systemd. For scripts that must write a secret to a file path:

```bash
install -m 0700 -d /run/secrets/myapp
vault kv get -field=cert secret/tls > /run/secrets/myapp/cert.pem
# Use it, then clean up
rm /run/secrets/myapp/cert.pem
```

Under memory pressure, tmpfs pages can be swapped to disk. If that matters, disable swap or use `ramfs` (which is never swapped but has no size limit — use with caution).
