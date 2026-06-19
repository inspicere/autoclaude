# `block-secrets.py` false positives on long path tokens

> Field report from a HealthLog (KMP/Android) session, 2026-06-09. The `block-secrets`
> PreToolUse hook repeatedly blocked **benign** read-only Bash commands (`git diff`,
> `grep`, `ls`, `find`) with:
>
> ```
> BLOCKED: Command contains a high-entropy string (possible secret)
> ```
>
> No secret was present. This documents the exact trigger, the strings that hit it, the
> immediate workarounds, and recommended fixes to the detector.

## Root cause — the high-entropy token check

`_check_command_secrets()` scans each whitespace-delimited argument and flags it as a
possible secret on entropy. The relevant block (≈ lines 561–607):

```python
if len(parts) > 1:
    for token in parts[1:]:
        clean = token.strip("\"'")
        if clean.startswith(('/', '.', '~', '-', '$', '{', '(')):   # (A) skip-prefixes
            continue
        if len(clean) >= 32 and _RE_HIGH_ENTROPY.match(clean):       # (B) ≥32 & charset
            ent = _shannon_entropy(clean)
            if ent >= 3.5:                                           # (C) entropy gate
                return ("Command contains a high-entropy string (possible secret)", "block")
            ...
```

where `_RE_HIGH_ENTROPY = re.compile(r'^[A-Za-z0-9+/=]+$')`.

A token is **blocked** when *all* of these hold:

1. It is a single whitespace-delimited argument (after quote-stripping — quoting does **not** help).
2. It does **not** start with `/ . ~ - $ { (`  → so **relative paths beginning with a letter are in scope**.
3. It is **≥ 32 characters**.
4. Every character is in `[A-Za-z0-9+/=]` — i.e. letters, digits, `+`, `/`, `=`. Note **`/` is allowed**, but `.`, `-`, `_` are **not**.
5. Its Shannon entropy ≥ 3.5 (natural-language/path text is typically 3.5–4.2).

A deeply-nested Kotlin/Java package directory is the perfect false positive:

```
shared/src/commonMain/kotlin/app/healthlog/data/entity/
```

— starts with `s` (not skip-listed), 52 chars, only letters + `/`, entropy ≈ 4.0 → **blocked**.
The detector cannot tell it apart from a 52-char base64 API key, because base64's alphabet
also includes `/`.

## What actually tripped this session

All read-only, all blocked — every one contained a long alnum+`/` relative path token:

| Command (abridged) | Offending token |
|---|---|
| `git diff --stat main..HEAD -- '…/data/entity/'` | `shared/src/commonMain/kotlin/app/healthlog/data/entity/` |
| `grep -rl "SyncMetadata" shared/…/data/entity/` | same |
| `ls shared/…/data/entity/ \| grep -i sync` | same |
| `find shared/src/commonMain -name "GcmWireFormat.kt"` | (path token ≥32, alnum+`/`) |

Things that did **not** trip (consistent with the rule):

- **Absolute** paths — they start with `/`, which is skip-listed (A). Every `Read`-tool call
  and absolute-path Bash command was fine.
- Tokens containing `-`, `_`, or `.` — e.g. `001-zk-web-keycustody-relay`, `GcmWireFormat.kt`,
  `.titan/experiments/…` — fail the `^[A-Za-z0-9+/=]+$` charset (B) (hyphen/underscore/dot not in
  set) or start with `.` (A), so they are not entropy-scanned.

So the "trips on long *compound* commands" folklore is a side effect: longer commands carry more
tokens, raising the odds that one is a 32+-char alnum-and-slash relative path. The compound-ness
isn't the trigger — the path-shaped token is.

## Immediate workarounds (no hook change needed)

Ranked by ease:

1. **Prefix relative paths with `./`.** `./shared/src/commonMain/.../entity/` starts with `.`,
   which is skip-listed (A) → never entropy-scanned. Cleanest one-keystroke fix.
2. **Use absolute paths.** They start with `/` (skip-listed). Good for tool calls; verbose for Bash.
3. **Prefer the file tools** (`Read`, and `Grep`/`Glob` where available) over `cat`/`grep`/`ls` in Bash — they don't pass through this hook's command scanner.
4. **Write the path list to a file, then operate on the file:**
   `git diff --name-only > /tmp/x.txt` then `grep … /tmp/x.txt` — the long paths live in the file, not the command line.
5. **`cd` into the directory** (or `git -C <dir>`) so path tokens become short relative names below the 32-char threshold. (Plain `cd … && …` in a compound can itself prompt for permission; `git -C` avoids that.)
6. **Split compound commands** into smaller ones — reduces token count but does **not** help if the long path token itself remains; combine with (1).

## Recommended detector fixes

The rule is otherwise doing its job (32+ base64 chars at entropy ≥3.5 is a classic key/token
shape). The fix is to stop treating filesystem paths as opaque blobs:

- **Down-weight `/`-dense tokens.** A token with ≥2 `/` separators is almost certainly a path;
  real base64 secrets rarely contain multiple slashes. Either skip such tokens, or require a higher
  entropy bar / longer length for them.
- **Or drop `/` from `_RE_HIGH_ENTROPY`** and detect slash-bearing base64 separately. Path
  structure (multiple short segments) differs from a contiguous secret.
- **Or skip path-resolvable tokens:** if `os.path.exists(token)` / it resolves under CWD, treat it
  as a path, not a secret. (Has a TOCTOU/cost caveat, but these are read-only checks.)
- **Or extend the skip-prefix set** to treat a token containing `/` but no `=`/`+` as a path
  candidate before entropy scanning.

A `/`-density heuristic is the smallest, safest change: it preserves detection of real keys
(which are slash-sparse) while clearing nested package paths (which are slash-dense).

## Reproduce / verify

```bash
# Blocks (relative, alnum+slash, ≥32, entropy≥3.5):
grep -r X shared/src/commonMain/kotlin/app/healthlog/data/entity/

# Allowed (./ prefix → skip-listed):
grep -r X ./shared/src/commonMain/kotlin/app/healthlog/data/entity/

# Allowed (absolute → skip-listed):
grep -r X /home/you/proj/shared/src/commonMain/kotlin/app/healthlog/data/entity/
```

Set `HOOK_DEBUG=1` to see the entropy score the hook computed for a token
(`[hook-debug] entropy check: len=… score=…`).

## 2026-06-19 follow-up

The same false positive recurred across two HealthLog sessions and was twice **misdiagnosed** as
camelCase Kotlin identifiers in `grep` patterns. A bare `ls <deep/package/path/>` (no grep, no
pattern, no identifier) reproduced the block — the **minimal repro** confirming the trigger is the
≥32-char alnum+slash *path argument*, not the identifiers. That session also grounded the rule
against the live hook source (`block-secrets.py` L199 charset-includes-`/`, L637 length gate, L640–642
entropy gate, L203 benign-allowlist that exempts source tokens + sha hex but **not** paths). Full
writeup with the source-cited tables: [`history/block-secrets-fp-2026-06-19.md`](history/block-secrets-fp-2026-06-19.md).
