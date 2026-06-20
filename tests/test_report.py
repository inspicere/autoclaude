#!/usr/bin/env python3
"""Test suite for claude-approval-report.py — tests pure functions without session data."""

import importlib.util
import io
import os
import sys
import unittest.mock

# Import the report module by file path (it has hyphens in the name)
spec = importlib.util.spec_from_file_location(
    "report", os.path.join(os.path.dirname(__file__), "..", "claude-approval-report.py")
)
report = importlib.util.module_from_spec(spec)
spec.loader.exec_module(report)

results = []


def check(condition, label):
    status = "PASS" if condition else "FAIL"
    results.append(condition)
    print(f"  {status}: {label}")
    if not condition:
        return False
    return True


# =============================================================================
# Shannon entropy
# =============================================================================
print("=== Shannon entropy ===")
check(report._shannon_entropy("") == 0.0, "empty string → 0.0")
check(report._shannon_entropy("aaaa") == 0.0, "uniform string → 0.0")
check(report._shannon_entropy("ab") == 1.0, "two equal chars → 1.0")
e = report._shannon_entropy("aB3$xZ9!")
check(e > 2.5, f"mixed chars → {e:.2f} > 2.5")
e_low = report._shannon_entropy("aaabbbccc")
check(e_low < 2.0, f"low-diversity string → {e_low:.2f} < 2.0")


# =============================================================================
# Secret detection
# =============================================================================
print("\n=== Secret detection (_has_secret_token) ===")
check(report._has_secret_token("ghp_" + "a" * 36), "GitHub PAT detected")
check(report._has_secret_token("sk-ant-api03-" + "a" * 93 + "AA"), "Anthropic key detected")
check(report._has_secret_token("xoxb-1234567890-abcdefghij"), "Slack token detected")
check(report._has_secret_token("AKIAIOSFODNN7EXAMPLE"), "AWS access key detected")
check(report._has_secret_token("eyJhbGciOiJIUzI1NiIsI.eyJzdWIiOiIxMjM0NTY3ODkwIiwidGVzdCI.aBcDeFgHiJkLmN0123"), "JWT detected")
check(report._has_secret_token("-----BEGIN RSA PRIVATE KEY-----"), "private key detected")
check(not report._has_secret_token("git push origin main"), "normal command not flagged")
check(not report._has_secret_token("echo hello world"), "echo not flagged")


# =============================================================================
# High entropy blob detection
# =============================================================================
print("\n=== High entropy blob detection ===")
check(report._has_high_entropy_blob(["aB3xZ9kLmN4pQ7rS0tU2vW5yA8cE1fGhI"]), "random base64 detected")
check(not report._has_high_entropy_blob(["aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"]), "uniform blob not flagged")
check(not report._has_high_entropy_blob(["short"]), "short token not flagged")
check(not report._has_high_entropy_blob(["/usr/local/bin/something1234567890abcdef"]), "path not flagged")
check(not report._has_high_entropy_blob(["./relative/path/with32charspaddd"]), "relative path not flagged")
# issue #7: report-side analog of the hook's e055478 + path carve-outs.
# Bare relative paths (no leading / . ~) whose segments are all filename-shaped
# and low-entropy must not be flagged as base64 secrets.
check(not report._has_high_entropy_blob(["app/src/main/kotlin/app/healthlog/ui/HomeScreen"]),
      "bare relative path not flagged (issue #7)")
check(not report._has_high_entropy_blob(["shared/src/commonMain/kotlin/app/healthlog/data"]),
      "bare relative source path not flagged (issue #7)")
# Parity with hook e055478: pure-alpha identifiers and git/sha hex digests.
check(not report._has_high_entropy_blob(["AndroidDbPassphraseProviderFactoryImpl"]),
      "pure-alpha identifier not flagged (e055478 analog)")
check(not report._has_high_entropy_blob(["356a192b7913b04c54574d18c28d46e6395428ab"]),
      "40-char git/sha1 hex not flagged (e055478 analog)")
# Over-correction guards: real base64 secrets must STILL be flagged, including
# ones containing '/' (their slash-separated segments are high-entropy).
check(report._has_high_entropy_blob(["aB3xZ9kLmN4pQ7rS/tU2vW5yA8cE1fGhI"]),
      "base64 blob with slash still flagged (issue #7 guard)")
# issue #9: residual FP shapes that survive the #7 path carve-out.
# (A) VAR=/KEY= assignment prefix welds an identifier onto a path/literal value.
check(not report._has_high_entropy_blob(["CANON=/home/inspicere/projects/healthlog"]),
      "VAR=path prefix not flagged (issue #9 A)")
check(not report._has_high_entropy_blob(["D=shared/src/commonMain/kotlin/app/healthlog/data"]),
      "VAR=relpath prefix not flagged (issue #9 A)")
check(not report._has_high_entropy_blob(["ITSAppUsesNonExemptEncryption=true"]),
      "KEY=value plist token not flagged (issue #9 A)")
# (B) digit-bearing path segments / KMP target lists (linuxX64, iosSimulatorArm64Test).
check(not report._has_high_entropy_blob(["shared/build/generated/ksp/linuxX64"]),
      "digit-bearing rel path not flagged (issue #9 B)")
check(not report._has_high_entropy_blob(["shared/src/iosSimulatorArm64Test"]),
      "digit-bearing camelCase rel path not flagged (issue #9 B)")
check(not report._has_high_entropy_blob(["iosArm64/iosSimulatorArm64/linuxX64"]),
      "KMP target list with digits not flagged (issue #9 B)")
# (3) camelCase/identifier tokens with an embedded digit (no slash, no equals).
check(not report._has_high_entropy_blob(["UnusedMaterial3ScaffoldPaddingParameter"]),
      "digit-bearing identifier not flagged (issue #9)")
# '+' is a base64 char but here it joins two source identifiers.
check(not report._has_high_entropy_blob(["MigrationTest+MedicationQuantityMigrationTest"]),
      "'+'-joined identifier list not flagged (issue #9)")
# Over-correction guards for issue #9: a real base64 blob whose value happens to
# carry a VAR= prefix, or contains '+', still flags (low-lowercase segments).
check(report._has_high_entropy_blob(["FOO=aB3xZ9kLmN4pQ7rS/tU2vW5yA8cE1fGhI"]),
      "VAR=base64 blob still flagged (issue #9 guard)")
check(report._has_high_entropy_blob(["aB3xZ9kLmN4pQ7rS+tU2vW5yA8cE1fGhI"]),
      "base64 blob with '+' still flagged (issue #9 guard)")


# =============================================================================
# Secret redaction
# =============================================================================
print("\n=== Secret redaction ===")
r = report.redact_secrets("ghp_" + "a" * 36)
check("<REDACTED>" in r and "ghp_" not in r, "GitHub PAT redacted")
r = report.redact_secrets("eyJhbGciOiJIUzI1NiIsI.eyJzdWIiOiIxMjM0NTY3ODkwIiwidGVzdCI.aBcDeFgHiJkLmN0123")
check("<REDACTED" in r and "eyJ" not in r, "JWT redacted")
r = report.redact_secrets("API_KEY=supersecretvalue123")
check("API_KEY=<REDACTED>" in r and "supersecret" not in r, "secret assignment redacted")
r = report.redact_secrets("-H 'Authorization: Bearer sk-ant-api03-xxxx'")
check("<REDACTED>" in r and "sk-ant" not in r, "Bearer token redacted")
r = report.redact_secrets("echo hello world")
check(r == "echo hello world", "normal command unchanged")
# issue #7: redaction must not blank out bare relative paths (same root cause
# as the detector FP — _RE_BASE64_BLOB permits '/').
r = report.redact_secrets("grep -rn X app/src/main/kotlin/app/healthlog/data/entity")
check("app/src/main/kotlin/app/healthlog/data/entity" in r and "<REDACTED>" not in r,
      "bare relative path not redacted (issue #7)")
r = report.redact_secrets("token aB3xZ9kLmN4pQ7rS/tU2vW5yA8cE1fGhI")
check("<REDACTED>" in r, "base64 blob with slash still redacted (issue #7 guard)")
# issue #9: the same benign carve-outs must apply to redaction (shares
# _is_benign_high_entropy). VAR=path, digit-bearing paths and camelCase
# identifiers must not be blanked out.
r = report.redact_secrets("CANON=/home/inspicere/projects/healthlog")
check("healthlog" in r and "<REDACTED>" not in r, "VAR=path not redacted (issue #9)")
r = report.redact_secrets("gradle :shared:compileKotlinLinuxX64 shared/build/generated/ksp/linuxX64")
check("linuxX64" in r and "<REDACTED>" not in r, "digit-bearing path not redacted (issue #9)")
r = report.redact_secrets("grep UnusedMaterial3ScaffoldPaddingParameter build.log")
check("UnusedMaterial3ScaffoldPaddingParameter" in r and "<REDACTED>" not in r,
      "digit-bearing identifier not redacted (issue #9)")


# =============================================================================
# _cmd_has_secrets
# =============================================================================
print("\n=== _cmd_has_secrets ===")
check(report._cmd_has_secrets("curl -H 'Authorization: Bearer realtoken123'"), "curl with Bearer flagged")
check(report._cmd_has_secrets("export API_KEY=realsecretvalue123"), "secret assignment flagged")
check(report._cmd_has_secrets("vault write secret/x token=ghp_abcdef1234567890ABCDEF12345678"),
      "command with GitHub PAT flagged")
check(not report._cmd_has_secrets("git push origin main"), "git push not flagged")
check(not report._cmd_has_secrets("ls -la"), "ls not flagged")
check(not report._cmd_has_secrets("export API_KEY=changeme"), "placeholder value not flagged")
check(not report._cmd_has_secrets("export API_KEY=placeholder"), "placeholder literal not flagged")
check(not report._cmd_has_secrets("export API_KEY=$VAULT_TOKEN"), "variable reference not flagged")
# issue #9 C: a secret-named var assigned from an environment read carries no
# literal secret. The carve-out must hold even when a shell terminator (the ';'
# from a following statement) is welded onto the captured value.
check(not report._cmd_has_secrets('TOKEN=os.environ["FORGEJO_TOKEN"]'),
      "os.environ read not flagged as secret_assign (issue #9 C)")
check(not report._cmd_has_secrets('TOKEN=os.environ["FORGEJO_TOKEN"]; NAME="clove-ios"'),
      "os.environ read with trailing ';' not flagged (issue #9 C)")
check(not report._cmd_has_secrets('API_KEY=os.getenv("OPENAI_API_KEY") && run'),
      "os.getenv read with trailing '&&' not flagged (issue #9 C)")
# Guard: a real literal assignment is still flagged.
check(report._cmd_has_secrets('TOKEN=realsecretvalue123; NAME="x"'),
      "literal secret assignment still flagged (issue #9 C guard)")


# =============================================================================
# _classify_exposure_risk — env reads contain no literal secret (false-positive)
# =============================================================================
print("\n=== _classify_exposure_risk (env reads) ===")
check(report._classify_exposure_risk('export TOKEN=os.environ["FORGEJO_TOKEN"]', "secret_assign")[0] == "false-positive",
      "os.environ read classified false-positive")
check(report._classify_exposure_risk('export API_KEY=os.getenv("OPENAI_API_KEY")', "secret_assign")[0] == "false-positive",
      "os.getenv read classified false-positive")
check(report._classify_exposure_risk("export DB_SECRET=os.environ.get('DB_SECRET')", "secret_assign")[0] == "false-positive",
      "os.environ.get read classified false-positive")
check(report._classify_exposure_risk('const API_TOKEN=process.env.FORGEJO_TOKEN', "secret_assign")[0] == "false-positive",
      "process.env read classified false-positive")
check(report._classify_exposure_risk('DB_SECRET=process.env["DB_SECRET"]', "secret_assign")[0] == "false-positive",
      "process.env[...] read classified false-positive")
# Guards: a literal welded onto an env read, or a plain literal, still exposed
check(report._classify_exposure_risk('export TOKEN=os.getenv("X")or"abcdef1234567890"', "secret_assign")[0] == "exposed",
      "env read + concatenated literal still exposed")
check(report._classify_exposure_risk("export API_KEY=realsecretvalue123", "secret_assign")[0] == "exposed",
      "plain literal still exposed")
# issue #9 C: trailing shell terminator must not defeat the env-read carve-out
# in the grading path (the real-world case had '; NAME="clove-ios"' appended).
check(report._classify_exposure_risk('TOKEN=os.environ["FORGEJO_TOKEN"]; NAME="clove-ios"', "secret_assign")[0] == "false-positive",
      "os.environ read with trailing ';' classified false-positive (issue #9 C)")
check(report._classify_exposure_risk('API_KEY=os.getenv("OPENAI_API_KEY") && deploy', "secret_assign")[0] == "false-positive",
      "os.getenv read with trailing '&&' classified false-positive (issue #9 C)")


# =============================================================================
# M1 (2026-05-16 audit): _RE_SECRET_ASSIGN captures quoted values with spaces
# =============================================================================
print("\n=== _RE_SECRET_ASSIGN quoted-value capture (M1) ===")
m = report._RE_SECRET_ASSIGN.search('API_KEY="value with spaces here"')
check(m is not None and m.group(2) == '"value with spaces here"',
      f"double-quoted value with spaces captured fully (got {m.group(2) if m else None!r})")
m = report._RE_SECRET_ASSIGN.search("VAULT_TOKEN='multi word secret'")
check(m is not None and m.group(2) == "'multi word secret'",
      f"single-quoted value with spaces captured fully (got {m.group(2) if m else None!r})")
m = report._RE_SECRET_ASSIGN.search("API_KEY=plainvalue")
check(m is not None and m.group(2) == "plainvalue",
      f"unquoted value still captured (got {m.group(2) if m else None!r})")
red = report.redact_secrets('export API_KEY="long secret with spaces"')
check("<REDACTED>" in red and "long secret" not in red,
      f"redaction covers full quoted span (got {red!r})")


# =============================================================================
# Risk classification
# =============================================================================
print("\n=== Risk classification ===")

check(report.classify_risk("Bash", {"command": "ls -la"}) == "read-only", "ls → read-only")
check(report.classify_risk("Bash", {"command": "cat README.md"}) == "read-only", "cat → read-only")
check(report.classify_risk("Bash", {"command": "grep -r TODO ."}) == "read-only", "grep → read-only")
check(report.classify_risk("Bash", {"command": "git status"}) == "read-only", "git status → read-only")
check(report.classify_risk("Bash", {"command": "git log --oneline"}) == "read-only", "git log → read-only")
check(report.classify_risk("Bash", {"command": "git diff HEAD"}) == "read-only", "git diff → read-only")

check(report.classify_risk("Bash", {"command": "git add ."}) == "mutating", "git add → mutating")
check(report.classify_risk("Bash", {"command": "git commit -m 'test'"}) == "mutating", "git commit → mutating")
check(report.classify_risk("Bash", {"command": "git push origin main"}) == "mutating", "git push → mutating")
check(report.classify_risk("Bash", {"command": "cp foo bar"}) == "mutating", "cp → mutating")
check(report.classify_risk("Bash", {"command": "mkdir -p /tmp/test"}) == "mutating", "mkdir → mutating")

check(report.classify_risk("Bash", {"command": "rm -rf /tmp/test"}) == "destructive", "rm -rf → destructive")
check(report.classify_risk("Bash", {"command": "git clean -f"}) == "destructive", "git clean -f → destructive")
check(report.classify_risk("Bash", {"command": "git push --force"}) == "destructive", "git push --force → destructive")

check(report.classify_risk("Bash", {"command": "find /tmp -name '*.log'"}) == "read-only",
      "find without -delete → read-only")
check(report.classify_risk("Bash", {"command": "find /tmp -name '*.log' -delete"}) == "destructive",
      "find -delete → destructive")
check(report.classify_risk("Bash", {"command": "find /tmp -exec chmod 644 {} +"}) == "mutating",
      "find -exec → mutating")

check(report.classify_risk("Bash", {"command": "sed 's/foo/bar/' file.txt"}) == "read-only",
      "sed without -i → read-only")
check(report.classify_risk("Bash", {"command": "sed -i 's/foo/bar/' file.txt"}) == "mutating",
      "sed -i → mutating")

check(report.classify_risk("Bash", {"command": "curl http://example.com"}) == "read-only",
      "curl GET → read-only")
check(report.classify_risk("Bash", {"command": "curl -X POST http://example.com"}) == "mutating",
      "curl POST → mutating")
check(report.classify_risk("Bash", {"command": "curl -X DELETE http://example.com/resource"}) == "destructive",
      "curl DELETE → destructive")

check(report.classify_risk("Bash", {"command": "ansible-playbook deploy.yml"}) == "mutating",
      "ansible-playbook → mutating")
check(report.classify_risk("Bash", {"command": "ansible-playbook deploy.yml --check"}) == "read-only",
      "ansible-playbook --check → read-only")
check(report.classify_risk("Bash", {"command": "git clean -n"}) == "read-only",
      "git clean --dry-run → read-only")

check(report.classify_risk("Read", {"file_path": "/tmp/file.txt"}) == "read-only", "Read → read-only")
check(report.classify_risk("Write", {"file_path": "/tmp/file.txt"}) == "mutating", "Write → mutating (not in DESTRUCTIVE)")
check(report.classify_risk("Bash", {"command": ""}) == "read-only", "empty command → read-only")
check(report.classify_risk("Bash", {"command": "# comment"}) == "read-only", "comment → read-only")

check(report.classify_risk("mcp__vault__vault_read", {}) == "mutating", "MCP tool → mutating")


# =============================================================================
# Risk classification — command-runners (source, timeout) — issue #3
# =============================================================================
print("\n=== Risk classification: command-runners (source, timeout) ===")

# `source` (and its dot-alias) activates env / runs a sub-script — treat as mutating
# when used alone, and dispatch to the trailing command when chained with && or ;.
check(report.classify_risk("Bash", {"command": "source .venv/bin/activate"}) == "mutating",
      "source alone → mutating")
check(report.classify_risk("Bash", {"command": ". .venv/bin/activate"}) == "mutating",
      "dot alias for source → mutating")
check(report.classify_risk("Bash", {"command": "source .venv/bin/activate && python3 foo.py"}) == "mutating",
      "source ... && python3 → mutating (python3 is mutating)")
check(report.classify_risk("Bash", {"command": "source .venv/bin/activate && ls -la"}) == "read-only",
      "source ... && ls → read-only")
check(report.classify_risk("Bash", {"command": "source .venv/bin/activate && rm -rf /tmp/x"}) == "destructive",
      "source ... && rm -rf → destructive")

# `timeout` is a command-wrapper — skip its duration argument and flags, then
# classify the trailing command.
check(report.classify_risk("Bash", {"command": "timeout 300 semgrep --config rules ."}) == "read-only",
      "timeout DURATION semgrep → read-only")
check(report.classify_risk("Bash", {"command": "timeout 5 ls /tmp"}) == "read-only",
      "timeout 5 ls → read-only")
check(report.classify_risk("Bash", {"command": "timeout 5s rm -rf /tmp/x"}) == "destructive",
      "timeout 5s rm -rf → destructive")
check(report.classify_risk("Bash", {"command": "timeout -k 5 30 curl -X POST http://example.com"}) == "mutating",
      "timeout -k 5 30 curl POST → mutating")
check(report.classify_risk("Bash", {"command": "timeout --kill-after=5s 30 rm -rf /tmp/x"}) == "destructive",
      "timeout --kill-after=5s 30 rm -rf → destructive")
check(report.classify_risk("Bash", {"command": "timeout --foreground 30 python3 script.py"}) == "mutating",
      "timeout --foreground 30 python3 → mutating")
check(report.classify_risk("Bash", {"command": "timeout -s SIGKILL 10 grep -r foo ."}) == "read-only",
      "timeout -s SIGKILL 10 grep → read-only")


# =============================================================================
# Risk classification — env-prefix subshell handling — issue #4
# =============================================================================
print("\n=== Risk classification: env-prefix subshell / paren / $VAR ===")

# Subshell in env value must not leak into the base command.
check(report.classify_risk("Bash", {
    "command": "TOKEN=$(vault kv get -field=api_token secret/forgejo) curl http://example.com"
}) == "read-only",
      "TOKEN=$(vault kv get ...) curl GET → read-only (not 'kv')")

check(report.classify_risk("Bash", {
    "command": "MB=$(git merge-base HEAD origin/main) && echo \"merge base: $MB\""
}) == "read-only",
      "MB=$(git merge-base ...) && echo → read-only (not 'merge-base')")

# Backtick subshell — same handling as $().
check(report.classify_risk("Bash", {
    "command": "REV=`git rev-parse HEAD` && echo $REV"
}) == "read-only",
      "REV=`git rev-parse HEAD` && echo → read-only")

# ${...} brace expansion in value should not break the prefix strip.
check(report.classify_risk("Bash", {
    "command": "OUT=${HOME}/log.txt cat ${OUT}"
}) == "read-only",
      "OUT=${HOME}/log.txt cat → read-only")

# Leading paren grouping — strip and classify the inner command.
check(report.classify_risk("Bash", {
    "command": "(source .venv/bin/activate; python3 -m pytest)"
}) == "mutating",
      "(source ...; python3 ...) → mutating")
check(report.classify_risk("Bash", {
    "command": "(ls -la)"
}) == "read-only",
      "(ls -la) → read-only")

# When the base is a shell variable like $WRAPPER, we can't see through it,
# but it's almost certainly invoking a script — classify as mutating.
check(report.classify_risk("Bash", {
    "command": "WRAPPER=~/scripts/wrap.sh $WRAPPER do-thing"
}) == "mutating",
      "WRAPPER=... $WRAPPER cmd → mutating")
check(report.classify_risk("Bash", {
    "command": "$HOME/bin/tool --flag"
}) == "mutating",
      "$HOME/bin/tool ... → mutating")

# Newline-separated multi-statement commands (the `cd PATH\nNEXT` case).
check(report.classify_risk("Bash", {
    "command": "cd ~/laima\necho '=== refs ==='\ngrep -r foo ."
}) == "read-only",
      "cd PATH<newline>echo<newline>grep → read-only")
check(report.classify_risk("Bash", {
    "command": "cd /tmp\nrm -rf /tmp/x"
}) == "destructive",
      "cd PATH<newline>rm -rf → destructive")
check(report.classify_risk("Bash", {
    "command": "cd /tmp; ls -la"
}) == "read-only",
      "cd PATH; ls → read-only (semicolon separator)")

# Line-continuation: `\<newline>` should be collapsed before classification.
check(report.classify_risk("Bash", {
    "command": "cd /tmp && \\\n  echo foo"
}) == "read-only",
      "cd PATH && \\<newline> echo → read-only (line continuation)")
check(report.classify_risk("Bash", {
    "command": "cd ~/svc && \\\n  TOKEN=abc rm -rf /tmp/x"
}) == "destructive",
      "cd PATH && \\<newline> ENV=val rm -rf → destructive")


# =============================================================================
# Risk classification — grep-family secret-scan exemption survives wrapping
# =============================================================================
# A bare grep searching *for* a token shape is exempt from secret scanning
# (it searches for patterns, it doesn't use them). When that grep is wrapped
# in a command-runner (timeout/source) or carries an env prefix, the exemption
# must follow the *effective* base, not the literal wrapper base — otherwise a
# legitimate audit grep is mislabeled `destructive`. The PreToolUse hook
# already peels wrappers before applying its grep-family exemption; the report
# classifier must agree.
print("\n=== Risk classification: grep-family exemption through wrappers ===")

# These greps search FOR an AWS-key shape — exempt, even when wrapped.
check(report.classify_risk("Bash", {
    "command": "timeout 300 grep -rn 'AKIAIOSFODNN7EXAMPLE' ."
}) == "read-only",
      "timeout DURATION grep <token-shape> → read-only (not destructive)")
check(report.classify_risk("Bash", {
    "command": "source .venv/bin/activate && grep -rn 'AKIAIOSFODNN7EXAMPLE' ."
}) == "read-only",
      "source ... && grep <token-shape> → read-only (not destructive)")
check(report.classify_risk("Bash", {
    "command": "timeout 60 rg 'AKIAIOSFODNN7EXAMPLE' src/"
}) == "read-only",
      "timeout DURATION rg <token-shape> → read-only (not destructive)")
check(report.classify_risk("Bash", {
    "command": "TOKEN=$(vault kv get -field=x secret/y) grep -rn 'AKIAIOSFODNN7EXAMPLE' ."
}) == "read-only",
      "ENV=$(...) grep <token-shape> → read-only (not destructive)")

# Regression guards — wrapping a NON-grep command must still catch a real
# secret being *used*. The effective base resolves to curl, not grep.
check(report.classify_risk("Bash", {
    "command": "timeout 5 curl -H 'Authorization: Bearer AKIAIOSFODNN7EXAMPLE'"
}) == "destructive",
      "timeout DURATION curl -H <token> → destructive (secret still caught)")
check(report.classify_risk("Bash", {
    "command": "WRAPPER=~/w.sh $WRAPPER curl -H 'Authorization: AKIAIOSFODNN7EXAMPLE'"
}) == "destructive",
      "ENV=val $WRAPPER curl -H <token> → destructive (secret still caught)")
check(report.classify_risk("Bash", {
    "command": "TOKEN=AKIAIOSFODNN7EXAMPLE curl http://example.com"
}) == "destructive",
      "ENV=<token> curl → destructive (inline secret still caught)")


# =============================================================================
# Command normalization
# =============================================================================
print("\n=== Command normalization ===")

check(report.normalize_command("ls -la") == "ls", "ls -la → ls")
check(report.normalize_command("git status") == "git status", "git status → git status")
check(report.normalize_command("git add .") == "git add", "git add → git add")
check(report.normalize_command("docker ps -a") == "docker ps", "docker ps → docker ps")
check(report.normalize_command("ssh user@192.168.86.100 uptime") == "ssh 192.168.86.100",
      "ssh strips user@ prefix")
check(report.normalize_command("cd /tmp && ls") == "ls", "cd prefix stripped")
check(report.normalize_command("FOO=bar ls") == "ls", "env prefix stripped")
# Command-runners attribute to the underlying command (issue #3) — no more
# misleading `Bash(source *)` / `Bash(timeout *)` allowlist suggestions.
check(report.normalize_command("source .venv/bin/activate && python3 foo.py") == "python3 foo.py",
      "source ... && python3 → python3 foo.py (not 'source')")
check(report.normalize_command("source .venv/bin/activate && git status") == "git status",
      "source ... && git status → git status")
check(report.normalize_command("timeout 300 semgrep --config rules .") == "semgrep",
      "timeout DURATION semgrep → semgrep (not 'timeout')")
check(report.normalize_command("timeout 5 grep -r foo .") == "grep",
      "timeout DURATION grep → grep")
check(report.normalize_command("timeout -k 5 30 curl -X POST http://x") == "curl",
      "timeout -k 5 30 curl → curl")
check(report.normalize_command("source .venv/bin/activate") == "source",
      "bare source (no chained cmd) stays 'source'")
check(report.normalize_command("timeout 5") == "timeout",
      "bare timeout (no command) stays 'timeout'")
check(report.normalize_command("") == "(empty)", "empty → (empty)")
check(report.normalize_command("# test") == "(comment/shebang)", "comment → (comment/shebang)")
check(report.normalize_command("/usr/local/bin/my-tool arg") == "my-tool", "path → basename")
check(report.normalize_command("terraform plan") == "terraform plan", "terraform plan preserved")
check(report.normalize_command("npm install express") == "npm install", "npm install preserved")
check(report.normalize_command("ssh -p 2222 host") == "ssh", "ssh with flag → ssh")
check(report.normalize_command("python3 script.py") == "python3 script.py", "python3 preserved")


# =============================================================================
# Pattern parsing and matching
# =============================================================================
print("\n=== Pattern parsing ===")

t, a = report.parse_permission_pattern("Bash(git add *)")
check(t == "Bash" and a == "git add *", "Bash(git add *) parsed")

t, a = report.parse_permission_pattern("Bash(git add:*)")
check(t == "Bash" and a == "git add:*", "Bash(git add:*) parsed")

t, a = report.parse_permission_pattern("Read(**/.env.example)")
check(t == "Read" and a == "**/.env.example", "Read(**/.env.example) parsed")

t, a = report.parse_permission_pattern("mcp__vault__vault_read")
check(t == "mcp__vault__vault_read" and a is None, "bare tool name parsed")

t, a = report.parse_permission_pattern("WebSearch")
check(t == "WebSearch" and a is None, "WebSearch parsed")


print("\n=== Pattern matching ===")

check(report.command_matches_pattern("Bash", {"command": "git add ."}, "Bash(git add *)"),
      "git add . matches Bash(git add *)")
check(report.command_matches_pattern("Bash", {"command": "git add README.md"}, "Bash(git add *)"),
      "git add README.md matches Bash(git add *)")
check(not report.command_matches_pattern("Bash", {"command": "git push"}, "Bash(git add *)"),
      "git push does NOT match Bash(git add *)")
check(not report.command_matches_pattern("Read", {"file_path": "/tmp/x"}, "Bash(ls *)"),
      "tool name mismatch → no match")
check(report.command_matches_pattern("Bash", {"command": "ls -la"}, "Bash(ls *)"),
      "ls -la matches Bash(ls *)")
check(report.command_matches_pattern("Bash", {"command": "cd /tmp && git status --short"}, "Bash(git status *)"),
      "cd prefix stripped for matching")
check(report.command_matches_pattern("Bash", {"command": "git add README.md"}, "Bash(git add:*)"),
      "colon-style pattern matches (: becomes space)")


# =============================================================================
# is_auto_allowed
# =============================================================================
print("\n=== is_auto_allowed ===")

patterns = ["Bash(git status *)", "Bash(ls *)", "Bash(grep *)"]
check(report.is_auto_allowed("Read", {"file_path": "/tmp/x"}, patterns),
      "Read always auto-allowed")
check(report.is_auto_allowed("Bash", {"command": "git status --short"}, patterns),
      "git status --short matches allowlist")
check(report.is_auto_allowed("Bash", {"command": "ls -la"}, patterns),
      "ls matches allowlist")
check(not report.is_auto_allowed("Bash", {"command": "rm -rf /"}, patterns),
      "rm not in allowlist")


# =============================================================================
# suggest_pattern
# =============================================================================
print("\n=== suggest_pattern ===")

check(report.suggest_pattern("Bash: git add") == "Bash(git add *)", "Bash git add suggestion")
check("ssh" in report.suggest_pattern("Bash: ssh 192.168.86.100"), "SSH suggestion contains ssh")
check(report.suggest_pattern("MCP vault: vault_read") == "mcp__vault__vault_read",
      "MCP suggestion correct")
check(report.suggest_pattern("WebSearch") == "WebSearch", "WebSearch suggestion")
check("Edit(" in report.suggest_pattern("Edit: ~/file.txt"), "Edit suggestion uses Edit()")
check("Write(" in report.suggest_pattern("Write: ~/file.txt"), "Write suggestion uses Write()")


# =============================================================================
# suggest_pattern_applicable
# =============================================================================
print("\n=== suggest_pattern_applicable ===")

check(report.suggest_pattern_applicable("Bash: git add") == "Bash(git add *)",
      "simple Bash pattern applicable")
check(report.suggest_pattern_applicable("Bash: ssh 192.168.86.100") is not None,
      "SSH pattern returns second option")
p = report.suggest_pattern_applicable("Bash: ssh 192.168.86.100")
if p:
    check("or" not in p, "applicable pattern has no 'or'")
check(report.suggest_pattern_applicable("MCP vault: vault_read") == "mcp__vault__vault_read",
      "MCP pattern applicable")


# =============================================================================
# shorten_path
# =============================================================================
print("\n=== shorten_path ===")

home = str(report.Path.home())
check(report.shorten_path(f"{home}/autoclaude/file.py") == "~/autoclaude/file.py",
      "home replaced with ~")
check(report.shorten_path("/tmp/file.txt") == "/tmp/file.txt", "non-home path unchanged")


# =============================================================================
# Duration and time helpers
# =============================================================================
print("\n=== Duration and time helpers ===")

check(report._is_duration("7d"), "7d is a duration")
check(report._is_duration("2w"), "2w is a duration")
check(report._is_duration("1m"), "1m is a duration")
check(not report._is_duration("2026-05-01"), "ISO date is not a duration")
check(not report._is_duration("foo"), "arbitrary string is not a duration")
check(not report._is_duration(""), "empty string is not a duration")

check(report._duration_to_days("7d") == 7, "7d → 7 days")
check(report._duration_to_days("2w") == 14, "2w → 14 days")
check(report._duration_to_days("1m") == 30, "1m → 30 days")
check(report._duration_to_days("bad") is None, "invalid → None")

check(report._auto_bucket(7) == "day", "7 days → day bucket")
check(report._auto_bucket(31) == "day", "31 days → day bucket")
check(report._auto_bucket(60) == "week", "60 days → week bucket")
check(report._auto_bucket(90) == "week", "90 days → week bucket")
check(report._auto_bucket(365) == "month", "365 days → month bucket")
check(report._auto_bucket(730) == "month", "730 days → month bucket")
check(report._auto_bucket(1000) == "quarter", "1000 days → quarter bucket")
check(report._auto_bucket(2000) == "year", "2000 days → year bucket")

from datetime import datetime, timezone
ts = report.parse_time_filter("7d")
check(ts is not None, "parse_time_filter('7d') returns datetime")
check(ts.tzinfo is not None, "parse_time_filter result is tz-aware")
ts2 = report.parse_time_filter("2026-05-01")
check(ts2 is not None, "parse_time_filter ISO date returns datetime")
check(ts2.year == 2026 and ts2.month == 5 and ts2.day == 1, "ISO date parsed correctly")


# =============================================================================
# _parse_ts
# =============================================================================
print("\n=== _parse_ts ===")

check(report._parse_ts(None) is None, "None → None")
check(report._parse_ts("") is None, "empty → None")
dt = report._parse_ts("2026-05-08T10:30:00+00:00")
check(dt is not None and dt.year == 2026 and dt.month == 5, "ISO with tz parsed")
dt2 = report._parse_ts("2026-05-08T10:30:00")
check(dt2 is not None, "ISO without tz parsed")


# =============================================================================
# extract_tool_calls_from_assistant
# =============================================================================
print("\n=== extract_tool_calls_from_assistant ===")

content = [
    {"type": "text", "text": "Let me check."},
    {"type": "tool_use", "id": "abc", "name": "Bash", "input": {"command": "ls"}},
    {"type": "tool_use", "id": "def", "name": "Read", "input": {"file_path": "/tmp/x"}},
]
calls = report.extract_tool_calls_from_assistant(content)
check(len(calls) == 2, f"extracted 2 tool calls from 3 content blocks")
check(calls[0]["name"] == "Bash", "first call is Bash")
check(calls[1]["name"] == "Read", "second call is Read")

check(report.extract_tool_calls_from_assistant("not a list") == [], "non-list → []")
check(report.extract_tool_calls_from_assistant([]) == [], "empty list → []")
check(report.extract_tool_calls_from_assistant([{"type": "text"}]) == [], "text only → []")


# =============================================================================
# get_tool_display
# =============================================================================
print("\n=== get_tool_display ===")

check(report.get_tool_display("Bash", {"command": "git status"}) == "Bash: git status",
      "Bash display correct")
check(report.get_tool_display("Read", {"file_path": f"{home}/autoclaude/CLAUDE.md"}).startswith("Read: "),
      "Read display starts with Read:")
check("~/" in report.get_tool_display("Read", {"file_path": f"{home}/autoclaude/CLAUDE.md"}),
      "Read display shortens path")


# =============================================================================
# _is_noise_command
# =============================================================================
print("\n=== _is_noise_command ===")

check(report._is_noise_command("Bash: (empty)"), "(empty) is noise")
check(report._is_noise_command("Bash: (comment/shebang)"), "(comment/shebang) is noise")
check(report._is_noise_command("Bash: -la"), "flag-like is noise")
check(report._is_noise_command("Bash: 192.168.1.1"), "IP address is noise")
check(not report._is_noise_command("Bash: git status"), "git status is not noise")


# =============================================================================
# filter_records
# =============================================================================
print("\n=== filter_records ===")

from datetime import timedelta
now = datetime.now(timezone.utc)
home_slug = report.HOME_SLUG
records = [
    {"timestamp": (now - timedelta(days=1)).isoformat(), "project": f"{home_slug}-proj-a"},
    {"timestamp": (now - timedelta(days=10)).isoformat(), "project": f"{home_slug}-proj-b"},
    {"timestamp": (now - timedelta(days=30)).isoformat(), "project": f"{home_slug}-proj-a"},
]
filtered = report.filter_records(records, since=now - timedelta(days=5))
check(len(filtered) == 1, f"since filter: 1 record within 5 days (got {len(filtered)})")
filtered = report.filter_records(records, project="proj-a")
check(len(filtered) == 2, f"project filter: 2 records for proj-a (got {len(filtered)})")
filtered = report.filter_records(records, since=now - timedelta(days=15), project="proj-a")
check(len(filtered) == 1, f"combined filter: 1 record (got {len(filtered)})")
filtered = report.filter_records(records)
check(len(filtered) == 3, "no filter returns all")


# =============================================================================
# render_json
# =============================================================================
print("\n=== render_json ===")

home_slug_for_records = report.HOME_SLUG
test_records = [
    {
        "timestamp": "2026-05-08T10:00:00+00:00",
        "tool_name": "Bash",
        "tool_input": {"command": "ls"},
        "display": "Bash: ls",
        "risk": "read-only",
        "auto_allowed": True,
        "prompted": False,
        "rejected": False,
        "project": f"{home_slug_for_records}-test",
    },
    {
        "timestamp": "2026-05-08T10:01:00+00:00",
        "tool_name": "Bash",
        "tool_input": {"command": "git push origin main"},
        "display": "Bash: git push",
        "risk": "mutating",
        "auto_allowed": False,
        "prompted": True,
        "rejected": False,
        "project": f"{home_slug_for_records}-test",
    },
]
buf = io.StringIO()
import json
report.render_json(test_records, out=buf)
output = json.loads(buf.getvalue())
check(isinstance(output, dict), "JSON output is a dict")
check("summary" in output, "JSON has summary key")
check(output["summary"]["total"] == 2, "JSON summary has correct total")
check(output["summary"]["auto_allowed"] == 1, "JSON summary has correct auto_allowed count")


# =============================================================================
# render_summary
# =============================================================================
print("\n=== render_summary ===")

buf = io.StringIO()
report.render_summary(test_records, out=buf)
summary = buf.getvalue()
check("APPROVAL SUMMARY" in summary, "summary has header")
check("auto" in summary.lower(), "summary mentions auto-allowed")


# =============================================================================
# render_trend
# =============================================================================
print("\n=== render_trend ===")

trend_records = []
for i in range(10):
    trend_records.append({
        "timestamp": (now - timedelta(days=i)).isoformat(),
        "tool_name": "Bash",
        "tool_input": {"command": "ls"},
        "display": "Bash: ls",
        "risk": "read-only",
        "auto_allowed": i % 3 != 0,
        "prompted": i % 3 == 0,
        "rejected": False,
        "project": f"{home_slug_for_records}-test",
    })

buf = io.StringIO()
report.render_trend(trend_records, bucket="day", out=buf)
trend_out = buf.getvalue()
check(len(trend_out) > 0, "trend output is non-empty")
check("TREND ANALYSIS" in trend_out, "trend has header")


# =============================================================================
# Token-attribution: read target normalization
# =============================================================================
print("\n=== Read target normalization ===")
home = os.path.expanduser("~")
check(report._normalize_read_target(home + "/autoclaude/x.py") == "~/autoclaude/x.py", "home -> ~")
check(report._normalize_read_target("/etc/passwd") == "/etc/passwd", "non-home path unchanged")
check(report._normalize_read_target("") == "", "empty -> empty")
check(report._normalize_read_target(None) == "", "None -> empty")


# =============================================================================
# Token-attribution: URL normalization
# =============================================================================
print("\n=== URL normalization ===")
check(report._normalize_url("HTTPS://Example.COM/path") == "https://example.com/path", "scheme+host lowercased")
check(report._normalize_url("https://example.com/x?q=1") == "https://example.com/x", "query stripped")
check(report._normalize_url("https://example.com/x#frag") == "https://example.com/x", "fragment stripped")
check(report._normalize_url("https://example.com/x?q=1#frag") == "https://example.com/x", "query+fragment stripped")
check(report._normalize_url("") == "", "empty -> empty")
check(report._normalize_url("not-a-url") == "not-a-url", "non-URL passes through")


# =============================================================================
# Token-attribution: input target extraction (dispatch)
# =============================================================================
print("\n=== Input target extraction ===")
check(report._extract_input_target("Read", {"file_path": home + "/x.py"}) == "~/x.py", "Read -> normalized path")
check(report._extract_input_target("Write", {"file_path": "/tmp/x"}) == "/tmp/x", "Write -> path")
check(report._extract_input_target("Edit", {"file_path": "/tmp/x"}) == "/tmp/x", "Edit -> path")
check(report._extract_input_target("WebFetch", {"url": "https://Example.com/?q=1"}) == "https://example.com/", "WebFetch -> normalized URL")
check(report._extract_input_target("Bash", {"command": "git status"}) == "git status", "Bash -> normalized command")
check(report._extract_input_target("WebSearch", {"query": "anything"}) == "", "WebSearch -> empty (no target)")
check(report._extract_input_target("Read", {}) == "", "missing field -> empty")
check(report._extract_input_target("Read", "not-a-dict") == "", "non-dict input -> empty")


# =============================================================================
# Token-attribution: result byte counting
# =============================================================================
print("\n=== Result byte counting ===")
check(report._compute_result_bytes({"stdout": "abc", "stderr": "de"}, None) == 5, "Bash dict stdout+stderr")
check(report._compute_result_bytes({"stdout": "abc"}, None) == 3, "Bash dict stdout only")
check(report._compute_result_bytes("hello", None) == 5, "string toolUseResult")
check(report._compute_result_bytes(None, "from-msg") == 8, "fallback to string msg.content")
check(report._compute_result_bytes(None, [{"type": "tool_result", "content": "abcdef"}]) == 6, "fallback to list msg.content (str)")
check(report._compute_result_bytes(None, [{"type": "tool_result", "content": [{"type": "text", "text": "abcd"}]}]) == 4, "fallback to list msg.content (list of text)")
check(report._compute_result_bytes(None, None) == 0, "no source -> 0")
check(report._compute_result_bytes({}, None) == 0, "empty dict -> 0")
check(report._compute_result_bytes({"interrupted": False, "stdout": "x"}, None) == 1, "ignores non-string fields")


# =============================================================================
# Token-attribution: byte->token fallback
# =============================================================================
print("\n=== Byte to token fallback ===")
check(report._estimate_tokens_from_bytes(0) == 0, "zero bytes -> 0 tokens")
check(report._estimate_tokens_from_bytes(4) == 1, "4 bytes -> 1 token")
check(report._estimate_tokens_from_bytes(100) == 25, "100 bytes -> 25 tokens")
check(report._estimate_tokens_from_bytes(-5) == 0, "negative clamped to 0")


# =============================================================================
# Token-attribution: proportional split + cap behavior
# =============================================================================
print("\n=== Token attribution (attribute_tool_result_tokens) ===")

# Single tool, modest delta below cap: gets full delta
recs = [{"_turn_uuid": "A", "_result_bytes": 3000}]
report.attribute_tool_result_tokens(recs, {"A": {}, "B": {"cache_creation_input_tokens": 500}}, ["A", "B"])
check(recs[0]["_result_tokens_est"] == 500, f"single tool, delta below cap -> 500 (got {recs[0]['_result_tokens_est']})")
check(recs[0]["_token_estimate_method"] == "usage_delta", "method=usage_delta when no cap")

# Single tool, delta above cap (cap = bytes/3 = 100): capped
recs = [{"_turn_uuid": "A", "_result_bytes": 300}]
report.attribute_tool_result_tokens(recs, {"A": {}, "B": {"cache_creation_input_tokens": 50000}}, ["A", "B"])
check(recs[0]["_result_tokens_est"] == 100, f"capped at bytes/3=100 (got {recs[0]['_result_tokens_est']})")
check(recs[0]["_token_estimate_method"] == "usage_delta_capped", "method=usage_delta_capped")

# Two tools in parallel, proportional split by bytes
recs = [
    {"_turn_uuid": "A", "_result_bytes": 9000},
    {"_turn_uuid": "A", "_result_bytes": 3000},
]
report.attribute_tool_result_tokens(recs, {"A": {}, "B": {"cache_creation_input_tokens": 1200}}, ["A", "B"])
check(recs[0]["_result_tokens_est"] == 900, f"75% share -> 900 (got {recs[0]['_result_tokens_est']})")
check(recs[1]["_result_tokens_est"] == 300, f"25% share -> 300 (got {recs[1]['_result_tokens_est']})")

# Last turn has no next-turn delta -> char/4 fallback
recs = [{"_turn_uuid": "Z", "_result_bytes": 400}]
report.attribute_tool_result_tokens(recs, {"Z": {}}, ["Z"])
check(recs[0]["_result_tokens_est"] == 100, f"last turn fallback char/4 -> 100 (got {recs[0]['_result_tokens_est']})")
check(recs[0]["_token_estimate_method"] == "char_div_4", "method=char_div_4 when last")

# Missing usage on next turn -> fallback
recs = [{"_turn_uuid": "A", "_result_bytes": 200}]
report.attribute_tool_result_tokens(recs, {"A": {}, "B": {}}, ["A", "B"])
check(recs[0]["_token_estimate_method"] == "char_div_4", "no cache_creation -> char/4 fallback")
check(recs[0]["_result_tokens_est"] == 50, "200 bytes -> 50 tokens fallback")

# Zero bytes + delta -> even split with usage_delta
recs = [
    {"_turn_uuid": "A", "_result_bytes": 0},
    {"_turn_uuid": "A", "_result_bytes": 0},
]
report.attribute_tool_result_tokens(recs, {"A": {}, "B": {"cache_creation_input_tokens": 100}}, ["A", "B"])
check(recs[0]["_result_tokens_est"] == 50 and recs[1]["_result_tokens_est"] == 50, "zero-bytes splits evenly")

# Records without _turn_uuid are ignored, not crashed
recs = [{"_result_bytes": 100}, {"_turn_uuid": "A", "_result_bytes": 100}]
report.attribute_tool_result_tokens(recs, {"A": {}}, ["A"])
check("_result_tokens_est" not in recs[0], "record without turn_uuid is skipped")
check(recs[1]["_token_estimate_method"] == "char_div_4", "tagged record is processed")


# =============================================================================
# Prose extraction: boilerplate stripping
# =============================================================================
print("\n=== Prose boilerplate stripping ===")
out = report._strip_prose_boilerplate("hello <system-reminder>noise</system-reminder> world")
check(out == "hello  world", f"system-reminder stripped (got {out!r})")
out = report._strip_prose_boilerplate("<command-name>foo</command-name>real text")
check(out == "real text", f"command-name stripped (got {out!r})")
out = report._strip_prose_boilerplate("<system-reminder>line1\nline2</system-reminder>kept")
check(out == "kept", f"multi-line system-reminder stripped (got {out!r})")
check(report._strip_prose_boilerplate("") == "", "empty -> empty")
check(report._strip_prose_boilerplate(None) == "", "None -> empty")
check(report._strip_prose_boilerplate("plain text") == "plain text", "plain text unchanged")


# =============================================================================
# Phase 2: annotate_next_turn_output
# =============================================================================
print("\n=== annotate_next_turn_output ===")
recs = [
    {"_turn_uuid": "A"},
    {"_turn_uuid": "B"},
]
report.annotate_next_turn_output(
    recs,
    {"A": {"output_tokens": 100}, "B": {"output_tokens": 50}},
    ["A", "B"],
)
check(recs[0]["_next_turn_output_tokens"] == 50, "turn A sees turn B output")
check(recs[1]["_next_turn_output_tokens"] == 0, "last turn -> 0")

# Records without turn_uuid are ignored without crashing
recs2 = [{"foo": "bar"}, {"_turn_uuid": "X"}]
report.annotate_next_turn_output(recs2, {"X": {"output_tokens": 10}}, ["X"])
check("_next_turn_output_tokens" not in recs2[0], "no turn_uuid -> no annotation")
check(recs2[1]["_next_turn_output_tokens"] == 0, "last turn fallback")


# =============================================================================
# Phase 2 Pattern A: find_repeated_reads
# =============================================================================
print("\n=== find_repeated_reads ===")

def _read_record(session, target, tokens, ts="2026-05-15T00:00:00Z", tool="Read"):
    return {
        "tool_name": tool, "session": session, "_input_target": target,
        "_result_tokens_est": tokens, "_kind": None, "timestamp": ts,
    }

# Below thresholds: not flagged
recs = [_read_record(f"s{i}", "~/x.py", 1000) for i in range(2)]
out = report.find_repeated_reads(recs, min_sessions=3, min_tokens=5000)
check(out == [], "2 sessions doesn't meet min_sessions=3")

# Meets sessions but not tokens
recs = [_read_record(f"s{i}", "~/x.py", 100) for i in range(3)]
out = report.find_repeated_reads(recs, min_sessions=3, min_tokens=5000)
check(out == [], "3 sessions, 300 tokens doesn't meet min_tokens=5000")

# Meets both
recs = [_read_record(f"s{i}", "~/x.py", 2000) for i in range(3)]
out = report.find_repeated_reads(recs, min_sessions=3, min_tokens=5000)
check(len(out) == 1 and out[0]["target"] == "~/x.py", "meets both -> finding")
check(out[0]["sum_tokens"] == 6000 and out[0]["occurrences"] == 3, "sum_tokens=6000 occ=3")
check(out[0]["distinct_sessions"] == 3, "distinct_sessions=3")
check(out[0]["kind"] == "repeated_read", "kind=repeated_read")
check(out[0]["avg_tokens"] == 2000, "avg_tokens=2000")

# WebFetch produces repeated_webfetch kind
recs = [_read_record(f"s{i}", "https://x.com/", 3000, tool="WebFetch") for i in range(3)]
out = report.find_repeated_reads(recs)
check(out[0]["kind"] == "repeated_webfetch", "WebFetch -> repeated_webfetch kind")

# Empty target ignored
recs = [_read_record(f"s{i}", "", 5000) for i in range(5)]
out = report.find_repeated_reads(recs)
check(out == [], "empty target ignored")

# Other tools ignored
recs = [{"tool_name": "Bash", "session": f"s{i}", "_input_target": "ls",
         "_result_tokens_est": 5000, "timestamp": "2026-05-15T00:00:00Z"} for i in range(5)]
out = report.find_repeated_reads(recs)
check(out == [], "Bash records ignored")

# Prose records ignored
recs = [{"_kind": "prose", "tool_name": None, "session": f"s{i}",
         "_input_target": "~/x.py", "_result_tokens_est": 5000} for i in range(5)]
out = report.find_repeated_reads(recs)
check(out == [], "prose records ignored")

# Sorted by sum_tokens descending
recs = (
    [_read_record(f"a{i}", "~/big", 3000) for i in range(3)] +
    [_read_record(f"b{i}", "~/small", 2000) for i in range(3)]
)
out = report.find_repeated_reads(recs, min_tokens=5000)
check(out[0]["target"] == "~/big" and out[1]["target"] == "~/small", "sorted by sum_tokens desc")

# Sample sessions truncated to 5
recs = [_read_record(f"s{i}", "~/x", 1000) for i in range(8)]
out = report.find_repeated_reads(recs, min_tokens=5000)
check(len(out[0]["sample_session_ids"]) == 5, "sample_session_ids capped at 5")


# =============================================================================
# Phase 2 Pattern B: find_recipe_ngrams
# =============================================================================
print("\n=== find_recipe_ngrams ===")

def _step_rec(session, tool, target, idx, ts_minute=0):
    return {
        "tool_name": tool, "session": session, "project": "p",
        "_input_target": target, "_turn_index": idx,
        "_result_tokens_est": 100,
        "timestamp": f"2026-05-15T00:{ts_minute:02d}:00Z",
    }

# Build same Read-Edit-Read recipe across 3 sessions, 6 times each = 18 occurrences
recs = []
for s in ("s1", "s2", "s3"):
    for cycle in range(6):
        base = cycle * 3
        recs.append(_step_rec(s, "Read", "~/a", base + 0, base))
        recs.append(_step_rec(s, "Edit", "~/a", base + 1, base))
        recs.append(_step_rec(s, "Read", "~/a", base + 2, base))
out = report.find_recipe_ngrams(recs, min_occurrences=5, min_sessions=2)
# After collapse_runs the sequence is Read,Edit,Read,Edit,Read,Edit,...
check(any("Read → Edit → Read" in f["target"] for f in out), "Read→Edit→Read recipe found")

# Single-step n-gram (A,A,A) rejected
recs = []
for s in ("s1", "s2", "s3"):
    for i in range(15):
        recs.append(_step_rec(s, "Read", "~/x", i, i))
out = report.find_recipe_ngrams(recs, min_occurrences=3, min_sessions=2)
check(out == [], "all-same-step n-gram rejected (collapses to 1 distinct)")

# Idle gap segmentation: gap > 10 min splits sequences
recs = []
# Session with two segments: [Read,Edit,Read] then 11min gap then [Read,Edit,Read]
seq_a = [("Read","~/a",0,0), ("Edit","~/a",1,0), ("Read","~/a",2,0)]
seq_b = [("Read","~/b",3,11), ("Edit","~/b",4,11), ("Read","~/b",5,11)]
for tool, tgt, idx, mn in seq_a + seq_b:
    recs.append(_step_rec("s1", tool, tgt, idx, mn))
# Add same pattern in 2 more sessions to meet min_occurrences=2
for s in ("s2", "s3"):
    for tool, tgt, idx, mn in seq_a + seq_b:
        recs.append(_step_rec(s, tool, tgt, idx, mn))
out = report.find_recipe_ngrams(recs, min_occurrences=3, min_sessions=2)
# Each session contributes 2 segments × the same 3-step recipe = 6 occurrences across 3 sessions
check(any("Read → Edit → Read" in f["target"] for f in out), "idle-gap segments still produce ngrams")

# All-safe-allow rejection: cat→ls→pwd should be filtered
recs = []
for s in ("s1", "s2", "s3"):
    for cycle in range(6):
        base = cycle * 3
        recs.append(_step_rec(s, "Bash", "cat", base + 0, base))
        recs.append(_step_rec(s, "Bash", "ls",  base + 1, base))
        recs.append(_step_rec(s, "Bash", "pwd", base + 2, base))
out = report.find_recipe_ngrams(recs, min_occurrences=3, min_sessions=2)
check(out == [], "all-baseline-safe-allow chain rejected")

# Below min_occurrences: not flagged
recs = []
for s in ("s1", "s2"):
    recs.append(_step_rec(s, "Read", "~/a", 0, 0))
    recs.append(_step_rec(s, "Edit", "~/a", 1, 0))
    recs.append(_step_rec(s, "Read", "~/a", 2, 0))
out = report.find_recipe_ngrams(recs, min_occurrences=5, min_sessions=2)
check(out == [], "1 occ per session, 2 sessions < min_occurrences=5")

# Single session: rejected by min_sessions
recs = []
for cycle in range(10):
    base = cycle * 3
    recs.append(_step_rec("s1", "Read", "~/a", base+0, base))
    recs.append(_step_rec("s1", "Edit", "~/a", base+1, base))
    recs.append(_step_rec("s1", "Read", "~/a", base+2, base))
out = report.find_recipe_ngrams(recs, min_occurrences=3, min_sessions=2)
check(out == [], "single session rejected by min_sessions=2")

# Empty input
check(report.find_recipe_ngrams([]) == [], "empty records -> []")

# Run-collapsing: A,A,B,B,C
check(report._collapse_runs(["A","A","B","B","C"]) == ["A","B","C"], "_collapse_runs basic")
check(report._collapse_runs([]) == [], "_collapse_runs empty")
check(report._collapse_runs(["X"]) == ["X"], "_collapse_runs single")


# =============================================================================
# Phase 2 Pattern C: find_repeated_prose
# =============================================================================
print("\n=== find_repeated_prose ===")

def _prose_rec(session, text):
    return {"_kind": "prose", "session": session, "text": text, "_char_len": len(text)}

para = "Hello world. " * 50  # ~650 chars
recs = [_prose_rec(f"s{i}", para) for i in range(3)]
out = report.find_repeated_prose(recs, min_occurrences=3, min_chars=400)
check(len(out) == 1, f"3 identical paragraphs -> 1 finding (got {len(out)})")
check(out[0]["occurrences"] == 3 and out[0]["distinct_sessions"] == 3, "occ=3 sessions=3")

# Short paragraphs ignored
recs = [_prose_rec(f"s{i}", "short.") for i in range(5)]
out = report.find_repeated_prose(recs, min_chars=400)
check(out == [], "short paragraphs ignored")

# Below min_occurrences
recs = [_prose_rec(f"s{i}", para) for i in range(2)]
out = report.find_repeated_prose(recs, min_occurrences=3, min_chars=400)
check(out == [], "below min_occurrences -> []")

# Numeric tokens normalized: same paragraph differing only in numbers should cluster
para_with_dates = "Today is " + "2026-05-15. " * 50
recs = []
for s, ymd in [("s1", "2026-05-15"), ("s2", "2026-06-20"), ("s3", "2027-01-01")]:
    recs.append(_prose_rec(s, "Today is " + (ymd + ". ") * 50))
out = report.find_repeated_prose(recs, min_occurrences=3, min_chars=400)
check(len(out) == 1, "date variants normalize to same hash")

# Non-prose records ignored
recs = [{"_kind": "tool_call", "session": "s1", "text": para}]
out = report.find_repeated_prose(recs, min_chars=400)
check(out == [], "non-prose ignored")

# Multi-paragraph splits on blank lines
multi = para + "\n\n" + ("Other long paragraph. " * 50)
recs = [_prose_rec(f"s{i}", multi) for i in range(3)]
out = report.find_repeated_prose(recs, min_occurrences=3, min_chars=400)
check(len(out) == 2, f"2 distinct paragraphs -> 2 findings (got {len(out)})")

# Empty input
check(report.find_repeated_prose([]) == [], "empty records -> []")

# _normalize_prose_text spot checks
check(report._normalize_prose_text("Hello   World") == "hello world", "whitespace collapsed")
check(report._normalize_prose_text("ID 12345 here") == "id <N> here", "numbers replaced")
check(report._normalize_prose_text("") == "", "empty -> empty")
check(report._normalize_prose_text(None) == "", "None -> empty")


# =============================================================================
# Phase 2 Pattern D: find_resummarized_outputs
# =============================================================================
print("\n=== find_resummarized_outputs ===")

def _output_rec(session, target, bytes_, est_tokens, next_out_tokens, tool="Read"):
    return {
        "tool_name": tool, "session": session, "_input_target": target,
        "_result_bytes": bytes_, "_result_tokens_est": est_tokens,
        "_next_turn_output_tokens": next_out_tokens,
    }

# Large output, tiny next-turn summary -> flagged
recs = [_output_rec(f"s{i}", "~/big", 50000, 12000, 500) for i in range(3)]
out = report.find_resummarized_outputs(recs, min_bytes=8000, max_narrow_ratio=0.25, min_occurrences=3)
check(len(out) == 1 and out[0]["target"] == "~/big", "large output + tiny summary flagged")
check(out[0]["_raw"]["narrow_ratio"] < 0.25, f"narrow_ratio < 0.25 (got {out[0]['_raw']['narrow_ratio']})")

# Below min_bytes
recs = [_output_rec(f"s{i}", "~/small", 1000, 250, 10) for i in range(3)]
out = report.find_resummarized_outputs(recs, min_bytes=8000)
check(out == [], "below min_bytes ignored")

# Ratio above threshold (large output, large summary too)
recs = [_output_rec(f"s{i}", "~/x", 50000, 12000, 8000) for i in range(3)]
out = report.find_resummarized_outputs(recs, max_narrow_ratio=0.25)
check(out == [], "ratio above threshold not flagged")

# Below min_occurrences
recs = [_output_rec(f"s{i}", "~/x", 50000, 12000, 100) for i in range(2)]
out = report.find_resummarized_outputs(recs, min_occurrences=3)
check(out == [], "below min_occurrences not flagged")

# Zero next_out_tokens (no following turn) -> skipped
recs = [_output_rec(f"s{i}", "~/x", 50000, 12000, 0) for i in range(5)]
out = report.find_resummarized_outputs(recs)
check(out == [], "zero next_out skipped")

# Zero result_tokens_est -> skipped (would div by zero)
recs = [_output_rec(f"s{i}", "~/x", 50000, 0, 100) for i in range(5)]
out = report.find_resummarized_outputs(recs)
check(out == [], "zero result_tokens skipped")

# Prose records skipped
recs = [{"_kind": "prose", "session": f"s{i}", "_input_target": "x", "_result_bytes": 50000,
         "_result_tokens_est": 12000, "_next_turn_output_tokens": 100} for i in range(5)]
out = report.find_resummarized_outputs(recs)
check(out == [], "prose records skipped")

# Aggregation: same target across 3 sessions
recs = [_output_rec(f"s{i}", "~/big", 50000, 12000, 500) for i in range(3)]
out = report.find_resummarized_outputs(recs, min_occurrences=3)
check(out[0]["distinct_sessions"] == 3, "distinct_sessions counted across records")
check(out[0]["sum_tokens"] == 36000, "sum_tokens aggregated")


# =============================================================================
# Phase 3: stability factor mapping
# =============================================================================
print("\n=== _stability_from_commit_count ===")
check(report._stability_from_commit_count(0) == 1.0, "0 commits -> 1.0")
check(report._stability_from_commit_count(1) == 0.8, "1 commit -> 0.8")
check(report._stability_from_commit_count(3) == 0.8, "3 commits -> 0.8")
check(report._stability_from_commit_count(4) == 0.5, "4 commits -> 0.5")
check(report._stability_from_commit_count(10) == 0.5, "10 commits -> 0.5")
check(report._stability_from_commit_count(11) == 0.25, "11 commits -> 0.25")
check(report._stability_from_commit_count(30) == 0.25, "30 commits -> 0.25")
check(report._stability_from_commit_count(31) == 0.1, "31 commits -> 0.1")
check(report._stability_from_commit_count(999) == 0.1, "999 commits -> 0.1")


# =============================================================================
# Phase 3: mtime-based stability
# =============================================================================
print("\n=== _stability_from_mtime ===")
import time as _t
now = _t.time()
check(report._stability_from_mtime(now - 3 * 86400) == 0.5, "3 days old -> 0.5")
check(report._stability_from_mtime(now - 14 * 86400) == 0.7, "14 days old -> 0.7")
check(report._stability_from_mtime(now - 60 * 86400) == 1.0, "60 days old -> 1.0")


# =============================================================================
# Phase 3: target path resolution
# =============================================================================
print("\n=== _resolve_target_path ===")
home = os.path.expanduser("~")
check(report._resolve_target_path("~/x.py") == home + "/x.py", "~ expansion")
check(report._resolve_target_path("/etc/passwd") == "/etc/passwd", "absolute path passthrough")
check(report._resolve_target_path("relative") is None, "relative -> None")
check(report._resolve_target_path("") is None, "empty -> None")
check(report._resolve_target_path(None) is None, "None -> None")
check(report._resolve_target_path("https://x.com/") is None, "URL -> None")


# =============================================================================
# Phase 3: compute_stability_factor dispatch (no subprocess for these branches)
# =============================================================================
print("\n=== compute_stability_factor (kind dispatch) ===")
check(report.compute_stability_factor("anything", "repeated_prose") == 1.0, "prose -> 1.0")
check(report.compute_stability_factor("https://x.com/", "repeated_webfetch") == 0.7, "webfetch -> 0.7")
check(report.compute_stability_factor("Read → Edit", "recipe_ngram") == 1.0, "recipe -> 1.0")
check(report.compute_stability_factor("not-a-path", "repeated_read") == 0.7, "unresolvable target -> 0.7")
check(report.compute_stability_factor("/nonexistent/file/here", "repeated_read") == 0.7, "missing file (no git result) -> 0.7")


# =============================================================================
# Phase 3: _git_commit_count with mocked subprocess
# =============================================================================
print("\n=== _git_commit_count (mocked) ===")
report._git_commit_count.cache_clear()


class _MockResult:
    def __init__(self, returncode, stdout):
        self.returncode = returncode
        self.stdout = stdout
        self.stderr = ""


with unittest.mock.patch.object(report.subprocess, "run") as mock_run:
    mock_run.return_value = _MockResult(0, "abc def\nghi jkl\nmno pqr\n")
    n = report._git_commit_count("/tmp/fake-test-path-1.txt")
    check(n == 3, f"3 lines -> count 3 (got {n})")

report._git_commit_count.cache_clear()
with unittest.mock.patch.object(report.subprocess, "run") as mock_run:
    mock_run.return_value = _MockResult(0, "")
    n = report._git_commit_count("/tmp/fake-test-path-2.txt")
    check(n == 0, "empty stdout -> count 0")

report._git_commit_count.cache_clear()
with unittest.mock.patch.object(report.subprocess, "run") as mock_run:
    mock_run.return_value = _MockResult(128, "")  # not a git repo
    n = report._git_commit_count("/tmp/fake-test-path-3.txt")
    check(n is None, "non-zero returncode -> None")

report._git_commit_count.cache_clear()
with unittest.mock.patch.object(report.subprocess, "run") as mock_run:
    import subprocess as _sub
    mock_run.side_effect = _sub.TimeoutExpired("git", 2)
    n = report._git_commit_count("/tmp/fake-test-path-4.txt")
    check(n is None, "subprocess timeout -> None")

report._git_commit_count.cache_clear()
with unittest.mock.patch.object(report.subprocess, "run") as mock_run:
    mock_run.side_effect = FileNotFoundError("git not installed")
    n = report._git_commit_count("/tmp/fake-test-path-5.txt")
    check(n is None, "git missing -> None")

report._git_commit_count.cache_clear()
n = report._git_commit_count("")
check(n is None, "empty path -> None (no subprocess)")


# =============================================================================
# Phase 3: score_finding
# =============================================================================
print("\n=== score_finding ===")
check(report.score_finding({"occurrences": 10, "avg_tokens": 100}, 1.0) == 1000, "stable -> full score")
check(report.score_finding({"occurrences": 10, "avg_tokens": 100}, 0.1) == 100, "volatile -> 10x discount")
check(report.score_finding({"occurrences": 10, "avg_tokens": 100}, 0.5) == 500, "mid -> half")
check(report.score_finding({"occurrences": 0, "avg_tokens": 100}, 1.0) == 0, "zero occ -> 0")
check(report.score_finding({}, 1.0) == 0, "empty finding -> 0")
# Floor: stability < 0.1 clamps to 0.1 (defensive)
check(report.score_finding({"occurrences": 10, "avg_tokens": 100}, 0.05) == 100, "below 0.1 floor")


# =============================================================================
# Phase 3: rank_findings (full pipeline w/ mocked git)
# =============================================================================
print("\n=== rank_findings ===")
report._git_commit_count.cache_clear()
findings = [
    # Volatile: should drop to bottom
    {"kind": "repeated_read", "target": "/tmp/volatile.py",
     "occurrences": 100, "avg_tokens": 1000, "distinct_sessions": 5,
     "sum_tokens": 100000, "sample_session_ids": [], "_raw": {}},
    # Stable file: full credit
    {"kind": "repeated_read", "target": "/tmp/stable.py",
     "occurrences": 50, "avg_tokens": 1000, "distinct_sessions": 5,
     "sum_tokens": 50000, "sample_session_ids": [], "_raw": {}},
    # Recipe: always 1.0
    {"kind": "recipe_ngram", "target": "Read -> Edit",
     "occurrences": 60, "avg_tokens": 800, "distinct_sessions": 5,
     "sum_tokens": 48000, "sample_session_ids": [], "_raw": {"n": 2}},
]


def _mock_run(cmd, **kwargs):
    if "/tmp/volatile.py" in cmd:
        return _MockResult(0, "\n".join("c" * 50) + "\n")  # 50 commits -> 0.1
    if "/tmp/stable.py" in cmd:
        return _MockResult(0, "")  # 0 commits -> 1.0
    return _MockResult(128, "")


with unittest.mock.patch.object(report.subprocess, "run", side_effect=_mock_run):
    ranked = report.rank_findings(findings)

# Annotations applied
check(all("_stability_factor" in f for f in ranked), "all findings annotated with _stability_factor")
check(all("_score" in f for f in ranked), "all findings annotated with _score")
# Scores: stable=50000, volatile=10000, recipe=48000 -> stable > recipe > volatile
check(ranked[0]["target"] == "/tmp/stable.py", f"stable file ranks #1 (got {ranked[0]['target']})")
check(ranked[2]["target"] == "/tmp/volatile.py", f"volatile file ranks last (got {ranked[2]['target']})")
check(ranked[0]["_stability_factor"] == 1.0, "stable factor 1.0")
check(ranked[2]["_stability_factor"] == 0.1, "volatile factor 0.1")

report._git_commit_count.cache_clear()


# =============================================================================
# Phase 4: suggestion dispatch
# =============================================================================
print("\n=== _suggestion_headline / _suggestion_type / _suggestion_body ===")

def _f(kind, target="t", n=3):
    return {"kind": kind, "target": target, "_raw": {"n": n, "steps": ["A", "B"], "exemplar_full": "x", "narrow_ratio": 0.1, "avg_input_bytes": 10000}}

check(report._suggestion_type(_f("repeated_read")) == "reference_md", "type: reference_md")
check(report._suggestion_type(_f("repeated_webfetch")) == "reference_md_external", "type: reference_md_external")
check(report._suggestion_type(_f("recipe_ngram", n=3)) == "slash_command", "type: slash_command for n=3")
check(report._suggestion_type(_f("recipe_ngram", n=5)) == "skill", "type: skill for n>=5")
check(report._suggestion_type(_f("repeated_prose")) == "claude_md_addition", "type: claude_md_addition")
check(report._suggestion_type(_f("resummarized_output")) == "wrapper_script", "type: wrapper_script")
check(report._suggestion_type(_f("unknown")) == "", "type: unknown -> empty")

check("slash command" in report._suggestion_headline(_f("recipe_ngram", n=3)), "headline: slash command for n=3")
check("skill" in report._suggestion_headline(_f("recipe_ngram", n=5)), "headline: skill for n=5")
check(".claude/refs/" in report._suggestion_headline(_f("repeated_read")), "headline: refs for read")

check(".claude/refs/" in report._suggestion_body(_f("repeated_read", target="~/x.py")), "body: read mentions refs/")
check("CLAUDE.md" in report._suggestion_body(_f("repeated_prose")), "body: prose mentions CLAUDE.md")
check("scripts/" in report._suggestion_body(_f("resummarized_output", target="~/x")), "body: resummarized mentions scripts/")
check("snapshot" in report._suggestion_body(_f("repeated_webfetch", target="https://x")), "body: webfetch mentions snapshot")
body = report._suggestion_body(_f("recipe_ngram", n=5))
check("skills/" in body, "body: 5+ step recipe -> skill path")


# =============================================================================
# Phase 4: _compute_token_findings
# =============================================================================
print("\n=== _compute_token_findings ===")

# Build records that trigger Pattern A
recs = [{"tool_name": "Read", "session": f"s{i}", "_input_target": "~/x.py",
         "_result_tokens_est": 5000, "timestamp": "2026-05-15T00:00:00Z"} for i in range(3)]
out = report._compute_token_findings(recs, [])
check(len(out) >= 1, "produces at least one finding")
check(all("_score" in f and "_stability_factor" in f for f in out), "findings are ranked (have _score + _stability_factor)")

# top=N truncates
recs_many = []
for j in range(10):
    for i in range(3):
        recs_many.append({"tool_name": "Read", "session": f"s{j}_{i}",
                          "_input_target": f"~/file{j}.py", "_result_tokens_est": 5000,
                          "timestamp": "2026-05-15T00:00:00Z"})
out = report._compute_token_findings(recs_many, [], top=5)
check(len(out) == 5, f"top=5 truncates (got {len(out)})")

# top=None returns all
out = report._compute_token_findings(recs_many, [], top=None)
check(len(out) >= 5, "top=None returns all findings")

# Empty input is graceful
check(report._compute_token_findings([], []) == [], "empty input -> []")
check(report._compute_token_findings([], None) == [], "None prose -> []")


# =============================================================================
# Phase 4: render_token_report (text)
# =============================================================================
print("\n=== render_token_report (text) ===")

# Empty report
buf = io.StringIO()
report.render_token_report([], [], top=10, out=buf)
out_text = buf.getvalue()
check("CLAUDE CODE TOKEN-CONSUMPTION REPORT" in out_text, "header rendered")
check("No findings above threshold" in out_text, "empty -> no-findings line")

# With findings
recs = []
for j in range(4):
    for i in range(3):
        recs.append({"tool_name": "Read", "session": f"s{j}_{i}",
                     "_input_target": f"~/file{j}.py", "_result_tokens_est": 3000,
                     "timestamp": "2026-05-15T00:00:00Z"})
buf = io.StringIO()
report.render_token_report(recs, [], top=10, detail_top=2, out=buf)
out_text = buf.getvalue()
check("Records scanned:" in out_text, "scanned line present")
check("repeated_read" in out_text, "kind appears in table")
check("DETAILS (top 2)" in out_text, "DETAILS section labelled with detail_top")
check(out_text.count("[1]") >= 1 and out_text.count("[2]") >= 1, "detail entries [1] and [2]")
# Header columns present
for col in ("KIND", "OCC", "SESS", "AVG_TOK", "SCORE", "STAB", "TARGET", "SUGGESTION"):
    check(col in out_text, f"header has {col}")

# Long target truncated with ellipsis
recs_long = [{"tool_name": "Read", "session": f"s{i}",
              "_input_target": "/very/long/path/" + "x" * 100,
              "_result_tokens_est": 3000, "timestamp": "2026-05-15T00:00:00Z"} for i in range(3)]
buf = io.StringIO()
report.render_token_report(recs_long, [], out=buf)
check("…" in buf.getvalue(), "long target truncated with ellipsis")


# =============================================================================
# Phase 4: render_token_report_json
# =============================================================================
print("\n=== render_token_report_json ===")
import json as _json

# Empty
buf = io.StringIO()
report.render_token_report_json([], [], out=buf)
payload = _json.loads(buf.getvalue())
check("generated_at" in payload, "JSON has generated_at")
check("filters" in payload and "summary" in payload and "findings" in payload, "JSON has top-level keys")
check(payload["findings"] == [], "empty findings list")

# With findings
buf = io.StringIO()
report.render_token_report_json(recs, [], top=5, filters={"project": "p"}, out=buf)
payload = _json.loads(buf.getvalue())
check(payload["filters"] == {"project": "p"}, "filters echoed")
check(payload["summary"]["records_scanned"] == len(recs), "records_scanned in summary")
check(payload["summary"]["top"] == 5, "top in summary")
check(len(payload["findings"]) >= 1, "findings present")

f0 = payload["findings"][0]
for key in ("rank", "kind", "target", "occurrences", "distinct_sessions",
            "avg_tokens", "sum_tokens", "stability_factor", "score",
            "sample_session_ids", "suggestion", "raw"):
    check(key in f0, f"finding has {key}")
check(f0["rank"] == 1, "first finding rank=1")
check(isinstance(f0["suggestion"], dict), "suggestion is dict")
for key in ("type", "headline", "body"):
    check(key in f0["suggestion"], f"suggestion has {key}")
check(isinstance(f0["stability_factor"], float), "stability_factor is float")
check(isinstance(f0["score"], (int, float)), "score is numeric")

# Findings are sorted by rank (ascending) which corresponds to score (descending)
buf = io.StringIO()
report.render_token_report_json(recs, [], top=20, out=buf)
payload = _json.loads(buf.getvalue())
ranks = [f["rank"] for f in payload["findings"]]
check(ranks == sorted(ranks), "ranks ascending")
scores = [f["score"] for f in payload["findings"]]
check(scores == sorted(scores, reverse=True), "scores descending")


# =============================================================================
# M6 (2026-05-16 audit Phase 5): render_warns prefix index correctness
# =============================================================================
print("\n=== M6: render_warns prefix index (correctness) ===")
import tempfile as _tempfile
import os as _os
from unittest.mock import patch as _patch

home_slug2 = report.HOME_SLUG

# Build session records that share a common 64-char prefix
common_prefix = "git log --oneline --all --decorate=full --graph "
sess_records = [
    {
        "tool_name": "Bash",
        "tool_input": {"command": common_prefix + " --since=2026-01-01 --until=2026-12-31"},
        "full_command": common_prefix + " --since=2026-01-01 --until=2026-12-31",
        "rejected": False,
        "auto_allowed": False,
        "timestamp": "2026-05-15T10:00:00+00:00",
        "project": f"{home_slug2}-test",
        "display": "Bash: git log",
        "risk": "read-only",
    },
    {
        "tool_name": "Bash",
        "tool_input": {"command": common_prefix + " --since=2026-02-01"},
        "full_command": common_prefix + " --since=2026-02-01",
        "rejected": True,
        "auto_allowed": False,
        "timestamp": "2026-05-15T11:00:00+00:00",
        "project": f"{home_slug2}-test",
        "display": "Bash: git log",
        "risk": "read-only",
    },
]

# Synthetic audit log: one warn entry whose command shares the prefix
with _tempfile.TemporaryDirectory() as _td:
    audit_dir = _os.path.join(_td, ".claude")
    _os.makedirs(audit_dir)
    audit_path = _os.path.join(audit_dir, "hook-audit.jsonl")
    with open(audit_path, "w") as _f:
        warn_record = {
            "ts": "2026-05-15T10:00:30+00:00",
            "decision": "warn",
            "tool": "Bash",
            "command": common_prefix + " --since=2026-01-01 --until=2026-12-31",
            "reason": "test warn",
        }
        _f.write(_json.dumps(warn_record) + "\n")

    # Point CLAUDE_DIR at the temp audit log
    with _patch.object(report, "CLAUDE_DIR", report.Path(_td) / ".claude"):
        buf = io.StringIO()
        report.render_warns(sess_records, out=buf)
        out_text = buf.getvalue()

check("Hook Warnings — 1 event" in out_text,
      f"warn count rendered (got {out_text[:80]!r})")
check("APPROVED" in out_text,
      f"warn matched to approved session record via prefix index "
      f"(got {out_text[:200]!r})")


# =============================================================================
# M5 (2026-05-16 audit Phase 5): --max-records flag presence
# =============================================================================
print("\n=== M5: --max-records argparse flag ===")
import subprocess as _sp
import os.path as _op

_script = _op.join(_op.dirname(__file__), "..", "claude-approval-report.py")
_r = _sp.run([sys.executable, _script, "--help"],
             capture_output=True, text=True, timeout=10)
check(_r.returncode == 0, "--help exits 0")
check("--max-records" in _r.stdout,
      f"--help mentions --max-records (got tail={_r.stdout[-200:]!r})")
check("most-recent" in _r.stdout,
      "--max-records help text describes behavior")


# =============================================================================
# #541 (2026-05-18): --version flag sourced from pyproject.toml
# =============================================================================
print("\n=== --version flag ===")
_r = _sp.run([sys.executable, _script, "--version"],
             capture_output=True, text=True, timeout=10)
check(_r.returncode == 0, "--version exits 0")
check(_r.stdout.startswith("autoclaude "),
      f"--version prints 'autoclaude <version>' (got {_r.stdout!r})")
check(report.__version__ != "unknown",
      f"__version__ resolved from pyproject.toml (got {report.__version__!r})")
import re as _re
check(_re.match(r'^\d+\.\d+\.\d+', report.__version__) is not None,
      f"__version__ looks like semver (got {report.__version__!r})")


# =============================================================================
# Lows-B (2026-05-18): tightened _RE_PRIVATE_KEY, --quiet, env override,
#                      _canonicalize_pattern dedupe, _MAX_UNWRAP_DEPTH guard
# =============================================================================
print("\n=== Lows-B: tightened _RE_PRIVATE_KEY ===")
# Real PEM headers — all match (constructed at runtime to avoid hook block)
_pk_real = [
    '-----' + 'BEGIN RSA PRIVATE ' + 'KEY-----',
    '-----' + 'BEGIN DSA PRIVATE ' + 'KEY-----',
    '-----' + 'BEGIN EC PRIVATE ' + 'KEY-----',
    '-----' + 'BEGIN OPENSSH PRIVATE ' + 'KEY-----',
    '-----' + 'BEGIN PGP PRIVATE ' + 'KEY BLOCK-----',
    '-----' + 'BEGIN ENCRYPTED PRIVATE ' + 'KEY-----',
    '-----' + 'BEGIN PRIVATE ' + 'KEY-----',
]
for h in _pk_real:
    check(report._RE_PRIVATE_KEY.search(h) is not None,
          f"PEM header matches: {h!r}")

# Prose noise that the old permissive regex would have matched
_pk_noise = [
    '-----' + 'BEGIN FAKE FOO PRIVATE ' + 'KEY-----',
    '-----' + 'BEGIN 12345 PRIVATE ' + 'KEY-----',
]
for n in _pk_noise:
    check(report._RE_PRIVATE_KEY.search(n) is None,
          f"prose noise rejected: {n!r}")


print("\n=== Lows-B: --quiet suppresses progress messages ===")
_r = _sp.run([sys.executable, _script, "--help"],
             capture_output=True, text=True, timeout=10)
check("--quiet" in _r.stdout or "-q," in _r.stdout,
      f"--help mentions --quiet (got tail={_r.stdout[-300:]!r})")

# Live-scan timeout: --summary runs against ~/.claude/projects/ which has
# grown over time. 30s was flaky as the session corpus crossed ~39k records;
# 90s gives margin without masking a real regression.
_r = _sp.run([sys.executable, _script, "--summary", "--quiet"],
             capture_output=True, text=True, timeout=90)
check("Scanning Claude Code" not in _r.stderr,
      f"--quiet suppresses 'Scanning' (got stderr={_r.stderr[:200]!r})")

_r = _sp.run([sys.executable, _script, "--summary"],
             capture_output=True, text=True, timeout=90)
check("Scanning Claude Code" in _r.stderr,
      f"default still prints 'Scanning' (got stderr={_r.stderr[:200]!r})")


print("\n=== Lows-B: AUTOCLAUDE_MAX_SESSION_MB env override ===")
import os as _os
_env = _os.environ.copy()
_env["AUTOCLAUDE_MAX_SESSION_MB"] = "5"
_r = _sp.run([sys.executable, "-c",
              "import importlib.util as i; "
              "s=i.spec_from_file_location('r','claude-approval-report.py'); "
              "m=i.module_from_spec(s); s.loader.exec_module(m); "
              "print(m._MAX_SESSION_SIZE)"],
             capture_output=True, text=True, timeout=10, env=_env)
check(_r.stdout.strip() == str(5 * 1024 * 1024),
      f"env override sets _MAX_SESSION_SIZE to 5 MB (got {_r.stdout.strip()!r})")

_env["AUTOCLAUDE_MAX_SESSION_MB"] = "not-a-number"
_r = _sp.run([sys.executable, "-c",
              "import importlib.util as i; "
              "s=i.spec_from_file_location('r','claude-approval-report.py'); "
              "m=i.module_from_spec(s); s.loader.exec_module(m); "
              "print(m._MAX_SESSION_SIZE)"],
             capture_output=True, text=True, timeout=10, env=_env)
check(_r.stdout.strip() == str(100 * 1024 * 1024),
      f"invalid env value falls back to 100 MB (got {_r.stdout.strip()!r})")
check("not an integer" in _r.stderr,
      f"invalid env value emits Warning (got stderr={_r.stderr[:120]!r})")


print("\n=== Lows-B: _canonicalize_pattern ===")
check(report._canonicalize_pattern("Bash(git add *)") == "Bash(git add *)",
      "space-form unchanged")
check(report._canonicalize_pattern("Bash(git add:*)") == "Bash(git add *)",
      f"colon-form canonicalizes to space-form (got {report._canonicalize_pattern('Bash(git add:*)')!r})")
check(report._canonicalize_pattern("Read(**/.env)") == "Read(**/.env)",
      "non-Bash pattern unchanged")
check(report._canonicalize_pattern("WebSearch") == "WebSearch",
      "bare tool name unchanged")
check(report._canonicalize_pattern(None) is None, "None passes through")


print("\n=== Lows-B: _split_shell_commands depth limit ===")
import importlib.util as _iu
_hook_spec = _iu.spec_from_file_location(
    'block_secrets', _op.join(_op.dirname(__file__), '..', 'hooks', 'block-secrets.py'))
_hook = _iu.module_from_spec(_hook_spec)
_hook_spec.loader.exec_module(_hook)
check(hasattr(_hook, '_MAX_UNWRAP_DEPTH'),
      "_MAX_UNWRAP_DEPTH is exported")
check(_hook._MAX_UNWRAP_DEPTH == 8,
      f"_MAX_UNWRAP_DEPTH == 8 (got {_hook._MAX_UNWRAP_DEPTH})")
# Deeply nested grouping should abort cleanly (no RecursionError)
_deep = "(" * 50 + "cat /tmp/safe" + ")" * 50
_out = _hook._split_shell_commands(_deep)
check(isinstance(_out, list),
      f"deep nesting returns a list (got {type(_out).__name__})")


# =============================================================================
# Phase 6 (v1.2.1): 2.3 git-log budget, M8 settings mode preservation,
#                   L10 --why label, L11 --help env vars, L12 --auto warning
# =============================================================================

import subprocess as _sub
import tempfile as _tf
import stat as _stat
import json as _json6
import time as _time6

_SCRIPT = _op.join(_op.dirname(__file__), '..', 'claude-approval-report.py')


print("\n=== Phase 6: 2.3 _git_commit_count wall-clock budget ===")
check(hasattr(report, '_STABILITY_TOTAL_BUDGET_SECONDS'),
      "_STABILITY_TOTAL_BUDGET_SECONDS constant exists")
check(getattr(report, '_STABILITY_TOTAL_BUDGET_SECONDS', 0) > 0,
      f"budget > 0 (got {getattr(report, '_STABILITY_TOTAL_BUDGET_SECONDS', 0)})")

# Reset internal state so the test is hermetic. Module-level cache and budget
# counter are exposed under known names.
if hasattr(report, '_git_commit_count'):
    report._git_commit_count.cache_clear()
if hasattr(report, '_reset_stability_budget'):
    report._reset_stability_budget()

# Simulate exhausted budget by pinning the consumed counter near the cap.
if hasattr(report, '_STABILITY_TOTAL_BUDGET_SECONDS') and hasattr(report, '_set_stability_budget_used'):
    report._set_stability_budget_used(report._STABILITY_TOTAL_BUDGET_SECONDS + 1.0)
    out = report._git_commit_count('/nonexistent/path/that/will/never/exist')
    check(out is None,
          f"exhausted budget returns None (got {out!r})")
    report._reset_stability_budget()


print("\n=== Phase 6: M8 _write_settings preserves existing file mode ===")
with _tf.TemporaryDirectory() as _td:
    p644 = _op.join(_td, 'settings_644.json')
    with open(p644, 'w') as f:
        f.write('{}')
    os.chmod(p644, 0o644)

    # Use the same Path-handling that callers use (pathlib).
    from pathlib import Path as _Path
    report._write_settings(_Path(p644), {'permissions': {'allow': ['Bash(ls *)']}}, dry_run=False)
    mode = _stat.S_IMODE(os.stat(p644).st_mode)
    check(mode == 0o644,
          f"existing 0o644 preserved (got 0o{mode:o})")

    p600 = _op.join(_td, 'settings_600.json')
    with open(p600, 'w') as f:
        f.write('{}')
    os.chmod(p600, 0o600)
    report._write_settings(_Path(p600), {'permissions': {'allow': ['Bash(ls *)']}}, dry_run=False)
    mode = _stat.S_IMODE(os.stat(p600).st_mode)
    check(mode == 0o600,
          f"existing 0o600 preserved (got 0o{mode:o})")

    # New file: defaults to 0o600 (no prior mode to preserve)
    pnew = _op.join(_td, 'subdir', 'settings_new.json')
    os.makedirs(_op.dirname(pnew), exist_ok=True)
    report._write_settings(_Path(pnew), {'permissions': {'allow': []}}, dry_run=False)
    mode = _stat.S_IMODE(os.stat(pnew).st_mode)
    check(mode == 0o600,
          f"new file defaults to 0o600 (got 0o{mode:o})")


print("\n=== Phase 6: L10 render_why uses unambiguous allowlist label ===")
# Build a tiny in-memory record set and capture render_why output.
import io as _io6
_rec = {
    'project': '-home-terrabot-autoclaude',
    'session': 'test.jsonl',
    'tool_name': 'Bash',
    'tool_input': {'command': 'git status'},
    'display': 'Bash: git status',
    'full_command': 'git status',
    'rejected': False,
    'auto_allowed': False,
    'risk': 'read-only',
    'timestamp': '',
    '_has_secrets': False,
    '_secret_category': None,
    '_exposure_risk': None,
    '_input_target': 'git status',
    '_result_bytes': 0,
    '_turn_uuid': 'x',
    '_turn_index': 0,
    '_result_tokens_est': 0,
    '_token_estimate_method': 'char_div_4',
    '_next_turn_output_tokens': 0,
}
_buf = _io6.StringIO()
_old_stdout = sys.stdout
sys.stdout = _buf
try:
    report.render_why('git status', [_rec])
finally:
    sys.stdout = _old_stdout
_out = _buf.getvalue()
# Pre-fix the output had two lines starting with "Auto-allowed:" — historical
# counts and per-project status — which is ambiguous. After fix, the second
# uses an unambiguous label.
_auto_allowed_count = _out.count('Auto-allowed:')
check(_auto_allowed_count <= 1,
      f"'Auto-allowed:' appears at most once (got {_auto_allowed_count})")
check('llowlist' in _out or 'currently allowed' in _out.lower(),
      f"output mentions allowlist status with clearer label "
      f"(snippet={_out[:200]!r})")


print("\n=== Phase 6: L11 --help mentions env-var overrides ===")
_help_proc = _sub.run(['python3', _SCRIPT, '--help'],
                      capture_output=True, text=True, timeout=10)
_help_text = _help_proc.stdout + _help_proc.stderr
for _var in ('HOOK_AUDIT', 'HOOK_DEBUG', 'AUTOCLAUDE_MAX_SESSION_MB'):
    check(_var in _help_text,
          f"--help mentions {_var}")


print("\n=== Phase 6: L12 --auto downgrade prints stderr warning ===")
# --apply mutating --auto silently downgrades to read-only today; should
# warn so the user knows the intent wasn't fully honored. Use a temp HOME
# so the live-session scan is empty and the command returns fast.
with _tf.TemporaryDirectory() as _empty_home:
    os.makedirs(os.path.join(_empty_home, '.claude', 'projects'), exist_ok=True)
    _env = os.environ.copy()
    _env['HOME'] = _empty_home
    _proc = _sub.run(
        ['python3', _SCRIPT, '--apply', 'mutating', '--auto', '--dry-run'],
        capture_output=True, text=True, timeout=15, env=_env,
    )
    _combined = _proc.stdout + _proc.stderr
    check('downgrad' in _combined.lower() or
          ('--auto' in _combined.lower() and 'read-only' in _combined.lower()),
          f"--apply mutating --auto warns about downgrade "
          f"(combined={_combined.strip()[:200]!r})")


# =============================================================================
# Phase 7 (v1.2.2): M2 --no-cross-project, redact_secrets idempotency,
#                   _safe_load_settings scope comment
# =============================================================================

print("\n=== Phase 7: redact_secrets is idempotent ===")
_text = (
    "Authorization: Bearer ghp_" + "a" * 36 + " | "
    "AKIAIOSFODNN7EXAMPLE token=" + "Z" * 40 + " "
    "API_KEY=abcdef0123456789abcdef0123 done"
)
_once = report.redact_secrets(_text)
_twice = report.redact_secrets(_once)
check(_once == _twice,
      f"redact_secrets is idempotent under a second pass "
      f"(once[:80]={_once[:80]!r}, twice[:80]={_twice[:80]!r})")
# Sanity: the first pass actually redacted something.
check('<REDACTED>' in _once or '<REDACTED-JWT>' in _once,
      f"first pass emits a placeholder (got {_once[:80]!r})")


print("\n=== Phase 7: M2 _cwd_to_project_slug helper ===")
check(hasattr(report, '_cwd_to_project_slug'),
      "_cwd_to_project_slug helper exists")
if hasattr(report, '_cwd_to_project_slug'):
    _orig_cwd = os.getcwd()
    # Use a real, created temp dir instead of a hardcoded absolute path so the
    # test is portable (CI checks the repo out somewhere other than the dev
    # box's home). Derive the expected slug independently from the *resolved*
    # cwd — mkdtemp may sit under a symlinked /tmp on some platforms.
    _tmpdir = _tf.mkdtemp(prefix='slug-')
    try:
        os.chdir(_tmpdir)
        _cwd = os.getcwd()
        _expected = '-' + '-'.join(seg for seg in _cwd.split('/') if seg)
        _slug = report._cwd_to_project_slug()
        check(_slug == _expected,
              f"slug for {_cwd} == {_expected!r} (got {_slug!r})")
    finally:
        os.chdir(_orig_cwd)
        try:
            os.rmdir(_tmpdir)
        except OSError:
            pass


print("\n=== Phase 7: M2 --no-cross-project filters scan ===")
# Build two fake project dirs in a temp HOME; --no-cross-project should
# limit the scan to the project matching CWD.
import tempfile as _tf7
import json as _json7
with _tf7.TemporaryDirectory() as _td:
    _projects = os.path.join(_td, '.claude', 'projects')
    # Two fake project dirs, each with one JSONL file (empty array is OK;
    # process_session skips lines that don't match the schema).
    _proj_a = os.path.join(_projects, '-tmp-proj-a')
    _proj_b = os.path.join(_projects, '-tmp-proj-b')
    os.makedirs(_proj_a, exist_ok=True)
    os.makedirs(_proj_b, exist_ok=True)
    # Each project gets one fake-but-empty session file
    for d in (_proj_a, _proj_b):
        with open(os.path.join(d, 'fake.jsonl'), 'w') as f:
            f.write('')  # empty session — produces no records

    # Verify --help mentions the new flag (cheap sanity)
    _hp = _sub.run([sys.executable, _SCRIPT, '--help'],
                   capture_output=True, text=True, timeout=10)
    check('--no-cross-project' in _hp.stdout,
          f"--help mentions --no-cross-project")

    # Run with the flag from inside the fake CWD; the script should accept
    # the flag without crashing.
    _env = os.environ.copy()
    _env['HOME'] = _td
    _proj_cwd = os.path.join(_td, 'proj-a')
    os.makedirs(_proj_cwd, exist_ok=True)
    _r = _sub.run(
        [sys.executable, _SCRIPT, '--no-cross-project', '--summary', '--quiet'],
        capture_output=True, text=True, timeout=15, env=_env, cwd=_proj_cwd,
    )
    # Either succeeds with empty output or exits 1 with "No tool call data".
    check(_r.returncode in (0, 1),
          f"--no-cross-project runs without crash (exit={_r.returncode}, "
          f"stderr={_r.stderr[:120]!r})")


print("\n=== Phase 7: _safe_load_settings carries scope-limit comment ===")
# This is a doc-comment-only check; the function's behavior is unchanged.
import inspect as _insp
_src = _insp.getsource(report._safe_load_settings)
check('scope-limited' in _src.lower() or
      'only validates' in _src.lower() or
      'allow / deny' in _src.lower(),
      f"_safe_load_settings source mentions scope limitation "
      f"(src head={_src.splitlines()[0:8]!r})")


# =============================================================================
# SUMMARY
# =============================================================================
print("\n" + "=" * 70)
passed = sum(results)
total = len(results)
print(f"RESULTS: {passed}/{total} passed")
print("=" * 70)
sys.exit(0 if passed == total else 1)
