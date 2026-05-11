# Hook Detection Reference

Two hooks protect Claude Code sessions from secret exposure. They work independently and neither imports from the other or from the main script.

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

### Quoted heredoc handling

Heredoc bodies with quoted delimiters (`<< 'EOF'` or `<< "EOF"`) are stripped before secret scanning. The shell does not expand variables inside these bodies, so `TOKEN=$(vault kv get ...)` in a quoted heredoc is a literal string written to a file, not a secret exposure.

Unquoted heredocs (`<< EOF`) still trigger detection because the shell expands variables in them at runtime.

### False-positive filtering

The report script's `--secrets` mode classifies flagged commands through `_classify_exposure_risk()`, which identifies false positives:

- Git object hashes (7-40 hex chars in git commands)
- SSH public keys (`ssh-ed25519 AAAA...`)
- Non-secret variable assignments (`GIT_AUTHOR_NAME`, `HOME`, `PATH`, etc.)
- Git ref paths (`refs/original/`, `refs/heads/`)
- Test/dummy Basic auth credentials (base64-decoded value contains `test`, `dummy`, `wrong`, `changeme`)
- Test payload patterns (`json.dumps`, `tool_result`, `echo ... tool_name`)

These appear as `FALSE-POS` in the secrets report and are excluded from the Sec count in trend output.

### What passes through

- Grep-family commands (searching for patterns, not using secrets)
- Variable *references* (`$TOKEN`, `${VAR}`) without literal values
- URLs in assignments (`CALLBACK=https://...`)
- Short/placeholder values (`PASSWORD=changeme`)
- Quoted heredoc bodies (no variable expansion)
- Normal file operations on non-sensitive paths

### Configuration

| Env var | Default | Effect |
|---------|---------|--------|
| `HOOK_DEBUG` | `0` | `1` = emit debug trace to stderr |
| `HOOK_AUDIT` | `1` | `1` = write JSONL to `~/.claude/hook-audit.jsonl` |

Audit log: structured JSONL with timestamp, decision, tool, summary, reason, command. Atomic appends (O_APPEND), 0600 permissions, auto-rotates at 5MB. Secrets are redacted in block-event entries.

#### Audit log data surface and retention

**Location:** `~/.claude/hook-audit.jsonl` (mode 0600, owner-only read/write).

**Fields recorded per event:**

| Field | Content | Privacy note |
|-------|---------|-------------|
| `ts` | ISO 8601 timestamp | Session timing |
| `decision` | `block`, `warn`, or `allow` | — |
| `tool` | Tool name (Bash, Read, etc.) | — |
| `summary` | Short description of action | May contain file paths |
| `reason` | Why the decision was made | May contain partial command text |
| `command` | Full Bash command (block/warn only) | **May contain sensitive args** (passwords, file paths, hostnames) |

**What is NOT logged:** tool output, file contents, Read/Edit results. Only the command (input side) is captured, and only for block/warn events. Allow events log summary only, not the full command.

**Secret redaction:** Known token patterns are replaced with `<REDACTED>` in the `command` field before writing. However, secrets that don't match a known pattern (e.g., short passwords, custom tokens) may appear unredacted.

**Retention:** The log auto-rotates at 5MB (renamed to `.1` backup). No automatic deletion or expiry. On a typical workstation with moderate Claude Code usage, this reaches 5MB in weeks to months.

**Recommendations:**
- Do not include `hook-audit.jsonl` in backups sent to untrusted storage
- Periodically delete old logs: `rm ~/.claude/hook-audit.jsonl.1`
- In shared environments, verify the file mode remains 0600
- The `--warns` flag on `claude-approval-report.py` reads this log for analysis; it does not copy or transmit the data

### Warn mode

Some commands get `decision: "warn"` instead of block. The user sees a warning but can still approve. This applies to:

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

- Reading known project files (block-secrets.py, warn-secrets-output.py, claude-approval-report.py, test suites) -- validated by script basename against `_EXEMPT_SCRIPT_NAMES` frozenset, not substring matching
- Reading project documentation files (README, CLAUDE.md, hooks.md) -- validated by `_EXEMPT_READ_TARGETS` regex matching full file path
- Test file output -- validated by `_RE_TEST_FILE_PATH` regex requiring `hooks/` or `tests/` path prefix

**No longer exempted (as of 2026-05-10):**
- Grep-family commands -- output is now scanned for token patterns (grep may dump file contents via `grep . file`)
- `git diff`/`log`/`show` -- output is now scanned for known token patterns

## Known bypasses (Round 3 red team, 2026-05-10) — ALL FIXED

10 confirmed bypasses found by 8 parallel agents (4 Opus, 4 Sonnet). All remediated. 25 analysis-only findings identified, 10 fixed, 15 remaining (architectural gaps).

| ID | Severity | Vector | Fix |
|----|----------|--------|-----|
| C1 | ~~Critical~~ | `git diff --no-index /dev/null <target>` | Added git handler for `diff --no-index`, `hash-object`, `add`, `archive` |
| C2 | ~~Critical~~ | `BASH_ENV=<target> bash -c 'echo $VAR'` | Added `_DANGEROUS_ENV_VARS` set + `_check_dangerous_env_prefixes()` |
| C3 | ~~Critical~~ | `env --split-string='cat <target>'` | Added `_check_env_split_string()` with 6 regex patterns |
| H1 | ~~High~~ | `setsid cat <target>` | Added to `_COMMAND_WRAPPERS` |
| H2 | ~~High~~ | `flock /tmp/x cat <target>` | Added to `_COMMAND_WRAPPERS` with `_FLOCK_VALUE_FLAGS` |
| H3 | ~~High~~ | `unshare --map-root-user cat <target>` | Added to `_COMMAND_WRAPPERS` |
| H4 | ~~High~~ | `find <dir> -name ".env" -exec cat {} \;` | Rewrote find handler with `in_exec` state tracking |
| H5 | ~~High~~ | `coproc cat <target>` | Added `coproc` to `_COMMAND_WRAPPERS` |
| H6 | ~~High~~ | `echo <target> \| xargs -I{} sh -c 'cat "{}"'` | Extended xargs to detect shell interpreters |
| H7 | ~~High~~ | `for f in <target>; do cat "$f"; done` | Added `_RE_FOR_LOOP` + for-loop variable tracking |

## 2026-05-10 project audit findings -- BOTH HIGH FINDINGS FIXED

A 12-dimension project audit identified 2 High, 5 Medium, 6 Low, 5 Info findings. Both High findings have been remediated (commit `079ba26`):

1. ~~**PostToolUse exempt pattern bypass** (High)~~: Replaced `_EXEMPT_COMMANDS` substring-matching regex with `_is_exempt_command()` function that validates script path basename against `_EXEMPT_SCRIPT_NAMES` frozenset. Grep-family blanket exemption removed -- output now scanned for token patterns.
2. ~~**No negative tests for PostToolUse exempt bypass** (High)~~: Added `hooks/test_warn_output_adversarial.py` with 48 adversarial tests in 6 categories (exempt bypass, grep bypass, legitimate exemptions, secret detection, no false positives, edge cases).

Additional Medium findings addressed:
3. ~~**Python version runtime check** (Medium)~~: Added `sys.version_info < (3, 11)` guard to all three scripts (main, PreToolUse, PostToolUse) with clear error message.
4. ~~**Shared sensitive path regex CI cross-check** (Medium)~~: Added `scripts/check-pattern-sync.py` that extracts and compares `_PREFIXED_TOKEN_PATTERNS` and `_RE_JWT` across all three files. Integrated into CI runner.
5. ~~**Audit log data surface documentation** (Medium)~~: Added data surface and retention section to this file documenting fields, privacy notes, redaction behavior, and retention recommendations.

6. ~~**settings.local.json cleanup** (Low)~~: Removed overly broad allow patterns (`Bash(python3 *)`, `Bash(git *)`, `Bash(bash *)`, red team artifacts). Replaced with specific test runner and hook patterns.
7. ~~**Landlock _SENSITIVE_PATH_RE divergence** (Medium, DefectDojo #2061)~~: Widened `.aws/` pattern in block-secrets.py to match landlock-sandbox.py; added `_SENSITIVE_PATH_RE` to CI pattern sync checker.

All audit findings resolved.

## Known limitations

These are fundamental to pre-execution static analysis and cannot be fully resolved:

| Limitation | Why | Mitigation |
|------------|-----|------------|
| Shell function indirection (`r() { cat "$1"; }; r .env`) | Function bodies create opaque indirection | None (architectural gap) |
| Bash array expansion (`a=(cat .env); "${a[@]}"`) | Array content not trackable | None (architectural gap) |
| Runtime path construction (`os.listdir()` in scripts) | No sensitive path in args | None |
| Symlink TOCTOU | `realpath()` resolves at check time; symlink can be repointed before execution | Race window is sub-millisecond; requires pre-positioned symlink + concurrent process |
| Encoded/obfuscated secrets below entropy threshold | Static analysis can't decode arbitrary encoding | Dual-threshold catches most real secrets |
| Command output leaks | PreToolUse can't see output | PostToolUse hook + MCP servers (auth stays server-side) |

## Allow and deny rules

`settings/recommended-deny.json` has 10 safe-to-allow patterns and 60 deny patterns. The allow list covers read-only Bash builtins (`cat`, `grep`, `ls`, `find`, etc.) and the built-in `Grep` tool. Note that `Bash(grep *)` and `Grep` are separate -- the former covers grep run via Bash, the latter covers Claude Code's native Grep tool (used for brace expansion, multi-file search). Both need entries to avoid approval prompts.

These complement the hooks:

| Layer | Protects against | Limitation |
|-------|-----------------|------------|
| Deny rules | `Read .env`, `Edit ~/.ssh/id_rsa` | Can't inspect Bash commands |
| PreToolUse hook | `cat .env`, `VAULT_TOKEN=hvs.xxx ...` | Only runs on tool calls |
| PostToolUse hook | Secrets in command output | Can't undo execution |
