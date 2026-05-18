# Changelog

All notable changes to this project will be documented in this file.

The format is loosely based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html)
once it reaches 1.0. Pre-1.0 releases are anchored to commit hashes; minor
incompatibilities are possible between any two snapshots.

## [Unreleased]

### Added
- `--version` flag on `claude-approval-report.py` prints `autoclaude <version>` sourced from `pyproject.toml`.
- `-q` / `--quiet` flag suppresses "Scanning..." and "Filters: ..." progress messages on stderr. Warnings/errors still surface.
- `AUTOCLAUDE_MAX_SESSION_MB` env var overrides the per-file 100 MB JSONL ingest cap (set to 0 to disable).
- `_canonicalize_pattern()` helper collapses semantically equivalent `Bash(...)` patterns (`Bash(git add:*)` ≡ `Bash(git add *)`) so `--apply` doesn't duplicate entries.
- Drop-count surfaced when `process_session` skips malformed JSONL lines (previously silent).
- `CHANGELOG.md` (this file). Closes Vikunja #541.
- `docs/history/` archive directory holding the verbatim text of resolved audit / red-team engagements: `audit-2026-05-07.md`, `red-team-2026-05-08.md`, `red-team-2026-05-10.md`, `audit-2026-05-16.md`, `token-report-plan-2026-05-15.md`.
- README "Privacy note" callout documenting that `HOOK_AUDIT=1` is the default and what gets captured.

### Changed
- `CLAUDE.md` trimmed from 272 to 119 lines by relocating the resolved-issue history into `docs/history/`. Loaded into every Claude session, so the saving compounds. Closes Vikunja #540. (`28e9711`)
- `_RE_PRIVATE_KEY` tightened from `[ A-Z0-9_-]{0,100}` to a closed set of real PEM header keywords (`RSA`, `DSA`, `EC`, `OPENSSH`, `PGP`, `ENCRYPTED`, plus PKCS#8 bare form). Same change in both the report script and the hook; verified by `check-pattern-sync.py`.
- `_split_shell_commands` recursion through `_unwrap_grouping` now bounded by `_MAX_UNWRAP_DEPTH = 8`. Pathological inputs like `((((cat .env))))` abort cleanly instead of risking the interpreter recursion limit.
- CI workflows pin `actions/checkout` by SHA (`11bd71901bbe5b1630ceea73d27597364c9af683`, v4.2.2 resolved 2026-05-18). semgrep install carries an inline comment documenting the accepted residual risk of unverified-hash pip install.

## [0.1.0] — 2026-05-18

First tagged snapshot. Project has been in active development since early 2026-05; this entry consolidates the milestones up to and including the 2026-05-16 audit remediation.

### Added
- **`pyproject.toml`** declaring `requires-python = ">=3.11"`, `version = "0.1.0"`, MIT license, classifiers. Stdlib-only dependencies. `[project.scripts]` deliberately omitted (hyphenated filename incompatibility — tracked as future enhancement). (`76d155f`)
- **`--max-records N`** CLI flag truncates the in-memory record list to the N most-recent records after load/filter. Useful for very large session corpora. Token-report aggregation sees a reduced sample under the cap. (`b19b5e8`)
- **`--token-report` / `--token-report-json`** mode: four detectors (repeated reads, recurring tool-call recipes, repeated user prose, re-summarized large outputs) ranked by `occurrences * avg_tokens * stability_factor`. Suggests reference docs, slash commands, skills, or wrapper scripts. (`4b1e457`, `38d7e9a`, `657be5b`)

### Security
The bulk of pre-0.1.0 work was security hardening across four engagements (full detail in `docs/history/`):

#### 2026-05-16 project audit (12-dim multidimensional review, 13/14 findings closed)
- **H1 docker `--mount type=bind,source=...`**: hook now parses both `--mount <val>` and `--mount=<val>` forms, splits on `,`, checks `source=`/`src=` against `_is_sensitive_path` and `_SENSITIVE_DIRS_RE`. (`256b6c6`)
- **H2 tar/zip flag bypasses**: hook now handles `--files-from=`, `--include-from=`, `--exclude-from=`, `--file=` (long-flag, both forms), `-T` (short-flag, both forms), and bunched short flags containing `T` (glued and next-arg). (`256b6c6`)
- **M1 `_RE_SECRET_ASSIGN` quoted-value capture**: now matches `(?:"[^"]*"|'[^']*'|\S+)` so quoted secrets with spaces redact fully. (`0db2431`)
- **M2 env-var truthy parsing**: `HOOK_DEBUG`, `HOOK_AUDIT`, `HOOK_CORRELATE` accept `1`/`true`/`yes`/`on` case-insensitively. (`0db2431`)
- **M3 audit-log redaction extended** to `summary` and `reason` fields via shared `_redact()` helper. (`0db2431`)
- **M4 race-safe audit-log rotation** via `fcntl.flock` on a sidecar `.lock` file with size re-check inside the lock. (`dd4e326`)
- **M5** (above — `--max-records` cap).
- **M6 `render_warns` perf**: added prefix-keyed index (`cmd[:64]`) replacing O(W×R) substring scan; full linear fallback preserved for non-prefix substring matches. (`b19b5e8`)
- **M7 audit-log retention**: documented single-backup model (≤10 MB steady state, bounded). (`dd4e326`)
- **M8 settings shape validation**: new `_safe_load_settings()` helper repairs bad shapes (non-dict root, non-dict permissions, non-list allow/deny) and emits stderr warnings. (`dd4e326`)
- **M9 CI base image pinned** to `node:22-slim@sha256:689c11043dad91472750cd824c97dd5e2318e9dd6f954e492fe7af0135d33ceb` in both Forgejo workflows. (`76d155f`)
- **M10** (above — `pyproject.toml`).
- **M11 multi-warning surfacing**: `(+N more)` suffix when several secret warnings detected in a single command. (`0db2431`)

#### 2026-05-10 red team round 3
All 10 confirmed bypasses fixed (git `diff --no-index`, `BASH_ENV`, `env --split-string`, `setsid`/`flock`/`unshare`/`coproc` wrappers, `find -exec`, `xargs | sh`, `for` loop variable tracking). 10 of 25 analysis-only findings also resolved. 15 remain unfixable by static analysis.

#### 2026-05-08 red team rounds 1 & 2
22 bypass classes found and fixed (quoted-path, glob, process substitution, write-then-execute, heredoc-to-interpreter, backtick, subshell unwrap, variable indirection, SSH remote, etc.). Hook grew from ~504 to ~830 lines.

#### 2026-05-07 adversarial audit
32 bypass vectors + 22 quality issues, all resolved. Includes regex backtracking fix, multi-statement bypass, grep-family file reads, sudo prefix stripping, docker volume detection.

### Tests
- 1092 tests across 15 suites (was 117 at end of 2026-05-08).
- New test suites in this release: `test_phase1_audit_fixes.py` (31), `test_round4_bypass_fixes.py` (26), `test_phase3_audit_fixes.py` (20). CI cross-file pattern-sync at 10 checks (`check-pattern-sync.py`).

### Architecture
- **Two hooks**: `hooks/block-secrets.py` (PreToolUse, ~1450 lines) blocks secret-leaking tool calls; `hooks/warn-secrets-output.py` (PostToolUse, ~280 lines) warns when command output contains a secret.
- **Landlock prototype** at `hooks/landlock-sandbox.py` addresses architectural gaps (shell function indirection, bash array expansion, runtime path construction, write-then-execute, symlink TOCTOU) at the kernel level via the Linux LSM.
- **CI**: Forgejo Actions runs `test.yml` (1092 tests → DefectDojo) and `security-scan.yml` (gitleaks + semgrep + trivy → DefectDojo). Both base images pinned by digest.
