# Changelog

All notable changes to this project will be documented in this file.

The format is loosely based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.1.1] — 2026-05-21

Patch release: three DefectDojo findings closed (two `block-secrets.py` false positives surfaced during the 2026-05-18 MetaMCP provisioning session, plus a semgrep false positive on a test fixture).

### Fixed

- **`block-secrets.py` false positives on jq accessors and quoted format-string identifiers** (commit `b07b1c0`, 2026-05-20). Closes DefectDojo #3404 and #3405 (both Low, filed 2026-05-18 during MetaMCP provisioning).
  - **#3404** — `_SENSITIVE_PATH_RE`'s `\.(?:pem|key|p12|pfx)$` alternation matched any token ending in `.key`. The single-command file-reader path (`_check_single_command_access`) splits on whitespace without quote-awareness, so jq filter args like `map(.key` or bare `.key` reached `_is_sensitive_path` where `os.path.realpath` resolved them to `/cwd/map(.key` and the loose regex matched. Tightened the basename to `(?:^|/)\.?\w[\w.\-]*\.(?:pem|key|p12|pfx)$` so a real filename character is required before the extension. Mirrored the same change in `hooks/landlock-sandbox.py` (kept `scripts/check-pattern-sync.py` green).
  - **#3405** — `_RE_SECRET_ASSIGN` matched `<ident>=<value>` anywhere in the command. jq/awk/printf format strings containing field-name templates (`enable_api_key_auth=\(.enable_api_key_auth)`) inside a single-quoted filter looked like inline secret assignments. New `_is_position_inside_quotes(text, pos)` helper; `_check_command_secrets` now iterates `_RE_SECRET_ASSIGN.finditer` and skips matches whose `=` sits inside an unclosed quoted span. Real unquoted shell assignments (`API_KEY=...`, `TOKEN=...`) still block.
- **Semgrep false positive on sample JWT used in redaction test** (commit `7bc6659`, 2026-05-21). Closes DefectDojo #3393 (High). Added `.semgrepignore` mirroring the existing `.gitleaks.toml` allowlist (`hooks/test_*.py`, `tests/test_*.py`, `hooks/block-secrets.py`, `hooks/warn-secrets-output.py`, `docs/hooks.md`, `settings/recommended-deny.json`). Repo-wide `semgrep scan --config auto .` now reports 0 findings (was 1).

### Tests

- **1131 tests across 15 suites** (was 1119). New "FP-FIX 3" section in `hooks/test_fp_fixes.py` adds 12 cases — 7 negative (jq `.key` accessor, jq `to_entries[] | .key`, `keys_unsorted[]`, jq template with `enable_api_key_auth=\(...)`, awk header with `_auth` ident, echo of `enable_api_key_auth=true`, printf with `token=`/`auth_required=` idents) plus 5 positive controls (`API_KEY=`/`TOKEN=` real assignments and `/etc/ssl/private/server.key`/`./mycert.key`/`~/.ssh/foo.pem` still block).

### Follow-up

- **Vikunja #671** (P3) tracks the deeper architectural fix for #3404: `_check_single_command_access` uses `cmd.split()` instead of `shlex.split()`, so any future shell-quoting blind spot will recur. The regex tighten in this release closes the specific FP path; the broader audit is queued.

## [1.1.0] — 2026-05-18

Audit-complete release. Consolidates the `--token-report` mode that shipped between v1.0.0 and this tag, the full 2026-05-16 project audit remediation (all 14 findings closed), and structural additions (`pyproject.toml`, `CHANGELOG.md`, `--version`, `--quiet`, env-var overrides).

### Added

- **`--token-report` / `--token-report-json`** mode: four detectors (repeated reads, recurring tool-call recipes, repeated user prose, re-summarized large outputs) ranked by `occurrences * avg_tokens * stability_factor`. Suggests reference docs, slash commands, skills, or wrapper scripts. (`4b1e457`, `38d7e9a`, `657be5b`)
- **`pyproject.toml`** declaring `requires-python = ">=3.11"`, MIT license, classifiers, stdlib-only dependencies. `[project.scripts]` deliberately omitted (hyphenated filename incompatibility — tracked as future enhancement). (`76d155f`)
- **`--version` flag** on `claude-approval-report.py` prints `autoclaude <version>` sourced from `pyproject.toml` via `tomllib._read_version()`. Module exposes `__version__`. (`1f589de`)
- **`-q` / `--quiet` flag** suppresses "Scanning..." and "Filters: ..." progress messages on stderr. Warnings/errors still surface. (`764e141`)
- **`--max-records N`** CLI flag truncates the in-memory record list to the N most-recent records after load/filter. Useful for very large session corpora; token-report aggregation sees a reduced sample under the cap. (`b19b5e8`)
- **`AUTOCLAUDE_MAX_SESSION_MB`** env var overrides the per-file 100 MB JSONL ingest cap (set to 0 to disable). (`764e141`)
- **`HOOK_DEBUG` / `HOOK_AUDIT` / `HOOK_CORRELATE`** env vars now accept any of `1` / `true` / `yes` / `on` (case-insensitive). Previously `HOOK_AUDIT=true` silently disabled auditing. (`0db2431`)
- **`_canonicalize_pattern()`** helper collapses semantically equivalent `Bash(...)` patterns (`Bash(git add:*)` ≡ `Bash(git add *)`) so `--apply` doesn't duplicate entries. (`764e141`)
- **CHANGELOG.md** (this file). (`1f589de`)
- **`docs/history/`** archive directory with the verbatim text of resolved audit / red-team engagements: `audit-2026-05-07.md`, `red-team-2026-05-08.md`, `red-team-2026-05-10.md`, `audit-2026-05-16.md`, `token-report-plan-2026-05-15.md`. (`28e9711`, `59c6e7b`)
- **README "Privacy note"** callout documenting that `HOOK_AUDIT=1` is the default and what the audit log captures. (`59c6e7b`)
- Drop-count surfaced via stderr when `process_session` skips malformed JSONL lines (previously silent). (`764e141`)

### Changed

- **`CLAUDE.md` trimmed** from 272 to 119 lines by relocating resolved-issue history into `docs/history/`. Loaded into every Claude session, so the saving compounds. (`28e9711`)
- **`_RE_PRIVATE_KEY` tightened** from `[ A-Z0-9_-]{0,100}` to a closed set of real PEM header keywords (`RSA`, `DSA`, `EC`, `OPENSSH`, `PGP`, `ENCRYPTED`, plus bare PKCS#8). Same change in both report script and hook; verified by `check-pattern-sync.py`. (`764e141`)
- **`_split_shell_commands` recursion bound**: `_MAX_UNWRAP_DEPTH = 8` caps the unwrap recursion through `_unwrap_grouping`. Pathological inputs like `((((cat .env))))` abort cleanly. (`764e141`)
- **CI base image** pinned to `node:22-slim@sha256:689c11043dad91472750cd824c97dd5e2318e9dd6f954e492fe7af0135d33ceb` in both Forgejo workflows. (`76d155f`)
- **`actions/checkout`** pinned by SHA (`11bd71901bbe5b1630ceea73d27597364c9af683`, v4.2.2 resolved 2026-05-18). semgrep install carries an inline comment documenting the accepted residual risk of unverified-hash pip install. (`59c6e7b`)

### Security

2026-05-16 project audit remediation — **14 of 14 findings closed** in DefectDojo engagement 123:

- **H1 docker `--mount type=bind,source=...`**: hook now parses both `--mount <val>` and `--mount=<val>` forms, splits on `,`, checks `source=`/`src=` against `_is_sensitive_path` and `_SENSITIVE_DIRS_RE`. (`256b6c6`)
- **H2 tar/zip flag bypasses**: hook now handles `--files-from=`, `--include-from=`, `--exclude-from=`, `--file=` (long-flag, both forms), `-T` (short-flag, both forms), and bunched short flags containing `T`. (`256b6c6`)
- **M1 `_RE_SECRET_ASSIGN` quoted-value capture**: now matches `(?:"[^"]*"|'[^']*'|\S+)` so quoted secrets with spaces redact fully. (`0db2431`)
- **M2 env-var truthy parsing** (above).
- **M3 audit-log redaction extended** to `summary` and `reason` fields via shared `_redact()` helper. (`0db2431`)
- **M4 race-safe audit-log rotation** via `fcntl.flock` on a sidecar `.lock` file with size re-check inside the lock. (`dd4e326`)
- **M5** (above — `--max-records` cap).
- **M6 `render_warns` perf**: added prefix-keyed index (`cmd[:64]`) replacing O(W×R) substring scan; full linear fallback preserved for non-prefix substring matches. (`b19b5e8`)
- **M7 audit-log retention**: documented single-backup model (≤10 MB steady state, bounded). (`dd4e326`)
- **M8 settings shape validation**: new `_safe_load_settings()` helper repairs bad shapes (non-dict root, non-dict permissions, non-list allow/deny) and emits stderr warnings. (`dd4e326`)
- **M9 CI base image pinned** (above).
- **M10** (above — `pyproject.toml`).
- **M11 multi-warning surfacing**: `(+N more)` suffix when several secret warnings are detected in a single command. (`0db2431`)
- **Low rollup** (#3275): 11 of 13 items resolved across `28e9711`, `1f589de`, `59c6e7b`, `764e141`; 5 accepted as wontfix with documented reasoning (symlink TOCTOU → Landlock; CI test sensitive strings → intentional fixtures; hard-coded POSIX paths → Linux focus; `_apply_suggestions` concurrent-safety → CLI one-shot; `_git_commit_count` cross-run cache → CLI one-shot). HOME_SLUG-in-JSON was preemptive — already mitigated.

### Tests

- **1119 tests across 15 suites** (was 117 at end of 2026-05-08, 802 at start of this release cycle).
- New test suites: `test_phase1_audit_fixes.py` (31), `test_round4_bypass_fixes.py` (26), `test_phase3_audit_fixes.py` (20). 47 new assertions in `test_report.py` for token-report attribution/detectors, `--version`, `--quiet`, env override, pattern canonicalization, depth limit, and tightened PEM regex.
- CI cross-file pattern-sync at 10 checks (`check-pattern-sync.py`).

### Architecture

- **Two hooks**: `hooks/block-secrets.py` (PreToolUse, ~1480 lines) blocks secret-leaking tool calls; `hooks/warn-secrets-output.py` (PostToolUse, ~280 lines) warns when command output contains a secret.
- **Landlock prototype** at `hooks/landlock-sandbox.py` addresses architectural gaps (shell function indirection, bash array expansion, runtime path construction, write-then-execute, symlink TOCTOU) at the kernel level via the Linux LSM.
- **CI**: Forgejo Actions runs `test.yml` (1119 tests → DefectDojo) and `security-scan.yml` (gitleaks + semgrep + trivy → DefectDojo). Both workflows pin base image and `actions/checkout` by SHA.

## [1.0.0] — earlier 2026-05

Initial tagged release. Pre-CHANGELOG; see git history at tag `v1.0.0`.
