# `block-secrets.py` false positives — 2026-06-19 follow-up

Follow-up to [`../block-secrets-false-positives.md`](../block-secrets-false-positives.md) (the
2026-06-09 root-cause writeup). The same false positive recurred across two HealthLog (KMP/Android)
sessions and produced the **minimal repro** that settles the diagnosis: the trigger is a
**≥32-char letters-and-slashes package-path argument**, *not* camelCase Kotlin identifiers.

## The "camelCase identifier" misdiagnosis

The block was repeatedly **misattributed** to camelCase Kotlin identifiers in `grep` patterns
(`CaseDeadline`, `WorkSchedule`, `upcomingDeadlineReminders`, `DbPassphraseProvider`, `FieldCipher`).
That diagnosis is wrong, and acting on it (rewording grep patterns to avoid camelCase) does **not**
help.

The blocked commands were multi-pattern greps whose path arguments were long Kotlin package dirs —
e.g. patterns like `"class WorkSchedule\|fun scheduledHours"` over
`shared/src/commonMain/kotlin/app/healthlog/domain` and `app/src/main/kotlin/app/healthlog`.

Why it is **not** the identifiers, per the root-cause rule:

- The quoted pattern token (`"class WorkSchedule\|fun scheduledHours\|..."`) contains `\`, `|`, space
  — none in `[A-Za-z0-9+/=]` — so it fails the charset gate and is never entropy-scanned.
- Every camelCase identifier is **< 32 chars** (`CaseDeadline`=12, `WorkSchedule`=12,
  `upcomingDeadlineReminders`=25, `DbPassphraseProvider`=20) → fails the length gate.

The token that actually tripped was the **package-path argument**:

| Token | len | alnum+`/` | ≥32 | blocked |
|---|---|---|---|---|
| `app/src/main/kotlin/app/healthlog` | 33 | yes | yes | **yes** |
| `shared/src/commonMain/kotlin/app/healthlog/domain` | 49 | yes | yes | **yes** |

It read as "camelCase" only because such greps *also* mention identifiers; the identifiers are
noise, the path is the trigger.

## Minimal repro: a bare `ls` is blocked

Same trigger recurred in a Phase 8.3a reminder-engine UAT session. Three consecutive read-only
commands were blocked with `BLOCKED: Command contains a high-entropy string (possible secret)`:

1. `grep -rn '...|buildRrule|rrule =' app/src/main/kotlin/app/healthlog/ui/medication/`
2. `grep -rln "FREQ" app/src/main/kotlin/app/healthlog/ui/medication/ 2>/dev/null`
3. `ls app/src/main/kotlin/app/healthlog/ui/medication/`

Command **(3) is the proof**: a bare `ls` with a single directory argument — no `grep`, no search
pattern, no quoted value, no identifier — is still blocked. The only token in common across all three
is the path `app/src/main/kotlin/app/healthlog/ui/medication/`. Pattern eliminated; the **path
argument is the sole trigger**. This forecloses the camelCase misdiagnosis for good.

## Confirmed against the hook source

`hooks/block-secrets.py`:

- **L199** `_RE_HIGH_ENTROPY = re.compile(r'^[A-Za-z0-9+/=]+$')` — the charset gate **includes `/`**.
  A relative package path is pure `[A-Za-z0-9/]`, so it *matches* and is eligible. This is the bug's
  crux: `/` lives *inside* the entropy charset.
- **L637** `if len(clean) >= 32 and _RE_HIGH_ENTROPY.match(clean):`, then **L640–642**
  `ent = _shannon_entropy(clean); if ent >= 3.5: block`.
  `app/src/main/kotlin/app/healthlog/ui/medication/` (46 chars) clears both gates.
- **L203** `_is_benign_high_entropy` exempts two ≥32-char classes (per Vikunja #758) — source-token
  shapes and pure-hex git/sha digests — but **not filesystem paths**, so the package path falls
  through to the block.

| Token | len | matches `^[A-Za-z0-9+/=]+$` | ≥32 | scanned→blocked |
|---|---|---|---|---|
| `app/src/main/kotlin/app/healthlog/ui/medication/` | 46 | yes (`/` is in charset) | yes | yes |
| `FREQ` (grep pattern) | 4 | yes | no | no |
| `buildRrule` / camelCase id | ≤25 | yes | no | no |

## Fix (shipped — issue #5 / PR #6)

Resolved on branch `fix/issue-5-entropy-path-fp`. The fix lands in `_is_benign_high_entropy`, but is
**stricter than the "skip any token with `/`" recommendation below**: it exempts a slash-bearing
token only when **every** `/`-separated segment is filename-shaped (`_RE_PATH_SEGMENT =
^[A-Za-z0-9._-]+$`) **and** low-entropy (`isalpha()` or `_shannon_entropy(seg) < 3.0`). A base64
secret that contains a `/` retains a high-entropy segment, fails the all-segments test, and still
gets entropy-scanned — so value-position secret detection is fully preserved. Every case in this and
the 2026-06-09 writeup now passes. Tests: FP-FIX 5 in `hooks/test_fp_fixes.py` and the issue #5 block
in `hooks/test_block_secrets.py`.

Original recommendation (superseded by the per-segment approach above):

> In `_is_benign_high_entropy` (or before the L637 gate), **skip tokens containing `/`** (≥2 slashes
> to be conservative). A `/`-bearing token is a path or URL-ish argument, not a base64/hex secret
> value — real secrets in this charset are base64, already covered by the source-token/sha carve-outs.

Stronger, optional: don't entropy-scan **argument tokens of read-only verbs** (`ls`, `grep`, `find`,
`cat`, `head`, `tail`) — the exfiltration risk is in `echo`/`curl`/`export` of a literal value, not
in navigating the tree.

## Workaround (pre-fix, for reference)

Before the issue #5 fix shipped: use the `Read` / `Glob` / `Grep` / `Explore` tools (they bypass this
command scanner), or `./`-prefix / absolute-path the argument — though length alone still tripped it,
so the tool-based path was the reliable one. No longer needed for filename-shaped package paths.

## Memory-pointer correction

The HealthLog session memory `reference_block_secrets_false_positives.md` framed this as "long
camelCase identifiers." That framing is incidental and should be corrected to "**≥32-char
alnum+slash package-path argument**" — the identifiers are noise, the path is the trigger.
