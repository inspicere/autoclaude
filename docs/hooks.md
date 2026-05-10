# Hook Detection Reference

Two hooks protect Claude Code sessions from secret exposure. They work independently — neither imports from the other or from the main script.

## PreToolUse: block-secrets.py

Inspects commands **before execution**. Exits with code 2 to block, 0 to allow. Covers Bash, Read, Edit, and Write tool calls.

### Detection categories

**Known token patterns (22 providers)**

GitHub (PAT, fine-grained, app), GitLab, Anthropic, OpenAI, AWS (access key), Google (API key), HashiCorp Vault, Slack, SendGrid, Stripe, npm, Hugging Face, Perplexity, DigitalOcean, Notion, Grafana, PyPI, Heroku.

**Structural patterns**

- JWT tokens (`eyJ...`)
- Private key headers (`-----BEGIN ... PRIVATE KEY-----`)
- Curl Authorization headers (Bearer, Token, Basic)
- Secret variable assignments (`VAULT_TOKEN=hvs.xxx`)

**Entropy analysis**

- Primary: Shannon entropy >= 3.5 on 32+ char strings
- Secondary: 3.0-3.5 range with unique-char-ratio >= 0.4 and max-char-frequency <= 0.15 (catches padding evasion)

**Sensitive file access (45+ tools)**

Blocks commands that read sensitive paths (`.env*`, `.ssh/id_*`, `.aws/credentials`, `/etc/shadow`, `*.vault-token`, etc.) via any of:

- Direct readers: `cat`, `head`, `tail`, `less`, `more`, `base64`, `sort`, `cut`, `paste`, `fmt`, `fold`, `expand`, `pr`, `column`, `jq`, `yq`, `diff`, `cmp`, `comm`, `csplit`, `split`, `join`, `uniq`, `iconv`, `shuf`, `unexpand`, `colrm`, `look`, `tsort`, `ptx`, `nkf`, `uuencode`, `base32`, `zcat`, `bzcat`, `xzcat`, `lz4`, `vidir`
- Copy/move/link: `cp`, `mv`, `ln`, `install`, `rsync`
- Archive/upload: `tar`, `zip`, `scp`, `curl @file`, `wget --post-file`, `dd if=`

**Bypass prevention**

| Vector | Detection |
|--------|-----------|
| Subshell wrapping (`bash -c`, `sh -c`, `zsh -c`) | Unwraps and recursively checks |
| Eval (`eval 'cmd'`) | Unwraps and recursively checks |
| Interpreter I/O (`python3 -c "open('.env')"`) | Detects file ops in inline scripts |
| Process substitution (`<(cat .env)`) | Extracts inner commands |
| Heredoc-to-interpreter | Scans body for sensitive paths |
| Backtick substitution (`` `cat .env` ``) | Extracts inner commands |
| Pipe-to-shell (`echo cmd \| bash`) | Detects piped shell execution |
| Subshell/brace groups (`(cmd)`, `{ cmd; }`) | Unwraps grouping |
| Variable tracking (`F=.env; cat $F`) | Follows assignments |
| SSH remote commands | Scans remote args |
| `xargs -a`/`--arg-file` | Checks file arguments |
| Shell positional args (`bash -c 'cat "$1"' _ .env`) | Scans positional args |
| Long-form file flags (`--from-file=`, `-in`) | Checks flag values |
| Command wrappers (`sudo`, `env`, `stdbuf`, etc.) | Strips and re-checks |

### What passes through

- Grep-family commands (searching for patterns, not using secrets)
- Variable *references* (`$TOKEN`, `${VAR}`) without literal values
- URLs in assignments (`CALLBACK=https://...`)
- Short/placeholder values (`PASSWORD=changeme`)
- Normal file operations on non-sensitive paths

### Configuration

| Env var | Default | Effect |
|---------|---------|--------|
| `HOOK_DEBUG` | `0` | `1` = emit debug trace to stderr |
| `HOOK_AUDIT` | `1` | `1` = write JSONL to `~/.claude/hook-audit.jsonl` |

Audit log: structured JSONL with timestamp, decision, tool, summary, reason, command. Atomic appends (O_APPEND), 0600 permissions, auto-rotates at 5MB. Secrets are redacted in block-event entries.

### Warn mode

Some commands get `decision: "warn"` instead of block — the user sees a warning but can still approve. This applies to:

- Secret variable assignments where the value comes from a subshell (`TOKEN=$(vault kv get ...)`)
- Password flags (`-p`) on commands like `mysql`, `htpasswd`
- Commands where the secret reference is indirect but suspicious

Warn confidence grading (`high`/`low`) is recorded in the audit log for PostToolUse correlation.

## PostToolUse: warn-secrets-output.py

Scans command **output** after execution. Cannot block (command already ran). Emits `decision: "warn"` with instructions not to use exposed values.

### What it detects

- Same 22 token patterns as the PreToolUse hook
- JWT tokens
- Private key headers

### Pre/Post correlation

When `HOOK_CORRELATE=1` (default): after standard pattern scanning, reads recent PreToolUse warn entries from the audit log, extracts flagged variable names, and checks output for high-entropy strings that could be expanded secrets. Triggers a stronger warning when correlation succeeds.

### Exemptions

- Grep-family commands (pattern definitions in output)
- `git diff`/`log`/`show` (reviewing code with regex patterns)
- Reading project files that contain pattern definitions (this hook, block-secrets.py, README, etc.)

## Known limitations

These are fundamental to pre-execution static analysis and cannot be fully resolved:

| Limitation | Why | Mitigation |
|------------|-----|------------|
| Shell function indirection (`r() { cat "$1"; }; r .env`) | Function bodies create opaque indirection | None — architectural gap |
| Bash array expansion (`a=(cat .env); "${a[@]}"`) | Array content not trackable | None — architectural gap |
| Runtime path construction (`os.listdir()` in scripts) | No sensitive path in args | None |
| Symlink TOCTOU | `realpath()` resolves at check time; symlink can be repointed before execution | Race window is sub-millisecond; requires pre-positioned symlink + concurrent process |
| Encoded/obfuscated secrets below entropy threshold | Static analysis can't decode arbitrary encoding | Dual-threshold catches most real secrets |
| Command output leaks | PreToolUse can't see output | PostToolUse hook + MCP servers (auth stays server-side) |

## Deny rules

`settings/recommended-deny.json` has 60 baseline deny patterns for Read/Write/Edit. These complement the hooks:

| Layer | Protects against | Limitation |
|-------|-----------------|------------|
| Deny rules | `Read .env`, `Edit ~/.ssh/id_rsa` | Can't inspect Bash commands |
| PreToolUse hook | `cat .env`, `VAULT_TOKEN=hvs.xxx ...` | Only runs on tool calls |
| PostToolUse hook | Secrets in command output | Can't undo execution |
