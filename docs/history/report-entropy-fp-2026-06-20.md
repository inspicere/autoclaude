# `--secrets` residual high-entropy / secret_assign false positives — 2026-06-20

## Resolution (issue #9)

**Fixed in both `claude-approval-report.py` and `hooks/block-secrets.py`.** After v1.3.0 (the #5/#7
path carve-outs), `--secrets` on the HealthLog transcripts dropped from ~554 flagged to 41, of which
16 were graded `EXPOSED` — and on inspection all 16 were false positives (a true-zero-secrets repo).
They survived the #7 per-segment path carve-out via four shapes it didn't cover. Three fixes close
them; the side-finding "D" was a deliberate non-fix.

### Audit corrections to the issue's framing

- The issue described A/B/C as "report-side ports of carve-outs the hook already has." In fact the
  hook's `_is_benign_high_entropy` was **byte-identical to the buggy report version** — it had the
  same A/B gaps and would still block e.g. `git diff -- shared/build/generated/ksp/linuxX64`. So A
  and B were applied to **both** detectors, keeping them in lockstep.
- Fix C (env-read carve-out) was **partly present** already: the report's grading path
  (`_classify_exposure_risk`) had `_RE_ENV_READ_VALUE`, but (i) it was absent from the detection gate
  `_cmd_has_secrets`, and (ii) the anchored regex was defeated by trailing shell punctuation — the
  `\S+` capture in `_RE_SECRET_ASSIGN` swallows the `;` in `TOKEN=os.environ["X"]; NAME=y`.

## The false-positive shapes

| Trigger token | entropy | shape | fix |
|---|---|---|---|
| `CANON=/home/inspicere/projects/healthlog` | 4.19 | `VAR=path` prefix | A |
| `ITSAppUsesNonExemptEncryption=true` | 4.20 | `KEY=value` plist | A |
| `shared/build/generated/ksp/linuxX64` | 4.14 | rel-path w/ digit segment | B |
| `iosArm64/iosSimulatorArm64/linuxX64` | 3.94 | KMP target list w/ digits | B |
| `UnusedMaterial3ScaffoldPaddingParameter` | 4.05 | identifier w/ embedded digit | B |
| `MigrationTest+MedicationQuantityMigrationTest` | 3.77 | `+`-joined identifier list | B |
| `TOKEN=os.environ["FORGEJO_TOKEN"]; NAME=…` | — | env read + trailing `;` | C |

## Fixes

**A — strip a leading `IDENT=` assignment prefix** (`_RE_IDENT_ASSIGN_PREFIX`). `CANON=/home/...`
split on `/` into `['CANON=home', ...]`; the `=` broke `_RE_PATH_SEGMENT`. Now `_is_benign_high_entropy`
strips a leading `^[A-Za-z_][A-Za-z0-9_]*=` and re-tests the value, so the path / literal is judged on
its own (recurses; `ITSAppUsesNonExemptEncryption=true` → `true` → `isalpha` → benign).

**B — lowercase-dominant discriminator** (`_is_lowercase_dominant`, >50% lowercase) applied both at
whole-token level (camelCase identifiers with digits) and per path segment, with segments split on
`[/+]` rather than just `/`. Chosen by measurement: FP source segments are 0.51–0.87 lowercase;
random base64 segments are 0.36–0.38 (≈ 26 lowercase of 64 alphabet chars). This is the same
heuristic issue #7 originally endorsed, now made per-segment so a real base64 blob with `/`/`+` keeps
a low-lowercase segment and still flags.

**C — env-read carve-out in detection + trailing-terminator strip** (report only, per scope). Added
`_RE_ENV_READ_VALUE` to `_cmd_has_secrets`, and a `_RE_VALUE_TRAILER = [;&|]+$` strip before the
anchored env-read match in **both** `_cmd_has_secrets` and `_classify_exposure_risk`. `)` is
intentionally **not** stripped — it is a legitimate trailing char of `os.getenv("X")`. A literal
welded onto an env read (`os.getenv("X")or"…"`) has no trailing `[;&|]`, so it still grades exposed.

**D — git-SHA exemption masking a real 40-hex token: NOT fixed (deliberate).** A real
`export FORGEJO_TOKEN="<40-hex>"` is exempted as a git SHA by the `len in (40,64) and _RE_HEX`
branch, so it grades SAFE/`auth_header` rather than `EXPOSED` (it is still redacted). Tightening this
would re-introduce SHA false-positive noise on every `git checkout <sha>` / `git show <sha>`. Left as
a documented trade-off per the issue's own recommendation.

## Tests

- `tests/test_report.py`: +19 cases (high-entropy A/B shapes, `_cmd_has_secrets` env-reads with
  trailing `;`/`&&`, `_classify_exposure_risk` trailing-terminator, redaction parity) plus
  over-correction guards (`VAR=`-prefixed base64, `+`-containing base64 still flag). 467 → **486**.
- `hooks/test_fp_fixes.py`: +6 cases (FP-FIX 6 — the A/B shapes allowed end-to-end, `VAR=`/`+` blobs
  still block). 52 → **58**.
- Full suite **1386** across 19 suites; token pattern-sync 10/10.

## Cross-reference

Residual of #7 (report-side path FP) and the hook analog #5/#1. Shared `_is_benign_high_entropy`
keeps the report and hook detectors in lockstep — see also
[`block-secrets-fp-2026-06-19.md`](block-secrets-fp-2026-06-19.md) and
[`report-high-entropy-fp-2026-06-19.md`](report-high-entropy-fp-2026-06-19.md).
