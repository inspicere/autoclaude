# `--secrets` report high-entropy false positives — 2026-06-19

Report-side analog of the hook bug fixed in `e055478`
(*"fix(hooks): stop entropy gate blocking identifiers and git/sha hashes"*) and documented in
[`block-secrets-fp-2026-06-19.md`](block-secrets-fp-2026-06-19.md). That fix landed in
`hooks/block-secrets.py` only. The **report's** detector,
`_has_high_entropy_blob` in `claude-approval-report.py`, is a *separate* code path and still
carries the same `/`-in-charset bug. As a result `--secrets` massively over-counts.

> **For the other session:** this is doc-only. No code in `claude-approval-report.py` or
> `tests/test_report.py` was changed. A drafted (reverted) test + fix is included below as a
> starting point — apply it TDD-style.

## Evidence: 554 "secrets" in a repo that has none

Running `--secrets` over the HealthLog projects (local-first Android/KMP app; keys live in the
Android Keystore, never in repo files or shell commands — a true-zero-secrets project) reports:

```
SECRET EXPOSURE ANALYSIS — 554 flagged command(s)
  By exposure risk:
    EXPOSED   — literal secret in command text     527
    VARIABLE  — secret referenced via $VAR            5
    PIPE-SAFE — secret flows through pipe            20
    FALSE-POS — not actually a secret                 2
  By detection category:
    High-entropy blob          527
    Authorization header        25
    Secret variable assignment   2
```

Breaking the 527 `EXPOSED` / high-entropy hits down by the **first word of the command**:

| verb | count | verb | count |
|---|---|---|---|
| `cd` | 287 | `echo` | 22 |
| `ls` | 66 | `cat` | 9 |
| `grep` | 50 | `ssh` | 5 |
| `git` | 38 | `sed`/`python3`/`for`/… | rest |
| `find` | 33 | | |

≈505 of 527 are pure navigation/inspection commands. The "secret" redacted in each is a
**relative source path** such as `app/src/main/kotlin/app/healthlog/ui/HomeScreen`. There is no
secret value anywhere in them.

The 25 `Authorization header` hits are all `Authorization: token $FORGEJO_TOKEN` — a shell
**variable reference**. The report itself classifies them `SAFE` / `VAR-REF`; the token value never
entered the transcript. So even the "more plausible" category contains zero literal exposures.

Net: of 554 flagged, **effectively all are false positives; zero real literal secret exposures.**
The "523 secrets already on disk, rotate them" line in `--summary` is a heuristic artifact, not an
incident.

## Root cause — `claude-approval-report.py`, `_has_high_entropy_blob` (L173–188)

```python
def _has_high_entropy_blob(tokens):
    for token in tokens:
        clean = token.strip("\"'")
        if clean.startswith(("/", ".", "~")):       # only skips ABSOLUTE / dotted / ~ paths
            continue
        if len(clean) >= 32 and re.match(r'^[A-Za-z0-9+/=]+$', clean):  # but "/" is IN this charset
            ent = _shannon_entropy(clean)
            if ent >= 3.5:
                return True
            ...
```

Same crux as the hook bug: **`/` lives inside the base64 charset `[A-Za-z0-9+/=]`.** A *relative*
path (one that does not start with `/`, `.`, or `~`) clears the `startswith` guard, is pure
`[A-Za-z0-9/]`, exceeds 32 chars, and scores entropy ≥ 3.5 because path segments are character-
diverse. So it reads as a base64 secret.

Unlike the hook (which got the `_is_benign_high_entropy` carve-out for source-token shapes and
git/sha hex in `e055478`), the report has **no benign carve-out at all** — `grep -n benign
claude-approval-report.py` → none.

## Minimal repro

```python
import importlib.util
spec = importlib.util.spec_from_file_location("report", "claude-approval-report.py")
report = importlib.util.module_from_spec(spec); spec.loader.exec_module(report)

report._has_high_entropy_blob(["app/src/main/kotlin/app/healthlog/ui/HomeScreen"])   # True  (FP)
report._has_high_entropy_blob(["shared/src/commonMain/kotlin/app/healthlog/data"])    # True  (FP)
report._has_high_entropy_blob(["home/inspicere/.../worktrees/phase-06"])              # False (only because the "-" in "phase-06" isn't in the charset)
```

The third case escaping is incidental — a hyphen breaks the charset match. Any hyphen-free
relative path trips it.

## Proposed fix

Mirror the hook fix. A `/`-bearing token in this charset is a path/URL argument, not a base64/hex
secret value. Two equivalent options:

1. **Lowercase-dominant skip** — paths are lowercase-word dominant, random standard-base64 is only
   ~40% lowercase, so this preserves real-blob detection (including blobs that *contain* `/`):

   ```python
   if "/" in clean and sum(c.islower() for c in clean) / len(clean) > 0.5:
       continue
   ```

2. **Conservative ≥2-slash skip** (the approach `block-secrets-fp-2026-06-19.md` recommends for the
   hook): skip tokens with 2+ `/`. Simpler, slightly blunter.

Either clears every nav-command case above. Option 1 is preferred because it still flags a real
base64 blob that happens to contain a single `/` (a real secret can; a path is lowercase-heavy).

**Stronger, optional** (also noted for the hook): don't entropy-scan argument tokens of read-only
verbs (`ls`, `grep`, `find`, `cat`, `head`, `tail`) — exfiltration risk is in `echo`/`curl`/`export`
of a literal value, not in tree navigation.

## Suggested tests (`tests/test_report.py`, after the existing high-entropy block ~L64)

```python
# Bare relative paths (no leading / . ~) are still paths, not secrets.
check(not report._has_high_entropy_blob(["app/src/main/kotlin/app/healthlog/ui/HomeScreen"]),
      "bare relative path not flagged")
check(not report._has_high_entropy_blob(["shared/src/commonMain/kotlin/app/healthlog/data"]),
      "bare relative source path not flagged")
# Guard against over-correction: a real base64 blob containing "/" must still flag.
check(report._has_high_entropy_blob(["aB3xZ9kLmN4pQ7rS/tU2vW5yA8cE1fGhI"]),
      "base64 blob with slash still flagged")
```

The first two FAIL on current `main` (RED), the third already passes; option-1 fix turns all green.

## Note: `tests/test_report.py` is not runnable on a fresh checkout

Separately discovered while verifying the above: the suite hard-crashes before the summary at

```python
os.chdir('/home/terrabot/autoclaude')   # ~L1767, in "Phase 7: M2 _cwd_to_project_slug helper"
```

`/home/terrabot/autoclaude` is a machine-specific path (the laima/homelab user). On any other
checkout this raises `FileNotFoundError` and the whole run aborts, so the pass/fail summary never
prints. Worth replacing with a `tempfile.mkdtemp()` (or `monkeypatch`-style cwd) so the suite is
portable and the new RED/GREEN checks above are actually observable end-to-end.

## See also

- [`block-secrets-fp-2026-06-19.md`](block-secrets-fp-2026-06-19.md) — the hook-side twin (fixed)
- [`../block-secrets-false-positives.md`](../block-secrets-false-positives.md) — 2026-06-09 root-cause writeup
- `e055478` — the hook fix this report-side change should mirror
