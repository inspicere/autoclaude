#!/usr/bin/env python3
"""Adversarial tests for the PostToolUse warn-secrets-output.py hook.

Tests that exempt patterns cannot be bypassed to suppress secret warnings,
while legitimate exemptions still work correctly.
"""

import json
import os
import subprocess
import sys

HOOK = os.path.join(os.path.dirname(__file__), "warn-secrets-output.py")

FAKE_GHP = "ghp_" + "a" * 36
FAKE_HVS = "hvs." + "a" * 95
FAKE_AWS = "AKIAIOSFODNN7EXAMPLE"
FAKE_JWT = (
    "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9."
    "eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6Ik"
    "pvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ."
    "SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"
)
FAKE_PRIVKEY = "-----BEGIN RSA PRIVATE KEY-----\nMIIEpAIBAAKCAQ..."

passed = 0
failed = 0


def test_hook(tool_name, tool_input, tool_result, expect_warn, label=""):
    global passed, failed
    data = json.dumps({
        "tool_name": tool_name,
        "tool_input": tool_input,
        "tool_result": tool_result,
    })
    env = dict(os.environ, HOOK_CORRELATE="0")
    r = subprocess.run(
        [sys.executable, HOOK],
        input=data, capture_output=True, text=True, timeout=10,
        env=env,
    )
    has_warn = "SECRET IN OUTPUT" in r.stdout
    if has_warn == expect_warn:
        passed += 1
    else:
        failed += 1
        expected = "WARN" if expect_warn else "NO WARN"
        actual = "WARN" if has_warn else "NO WARN"
        print(f"  FAIL: {label} — expected {expected}, got {actual}")
        if r.stdout:
            print(f"    stdout: {r.stdout.strip()[:200]}")


def bash(cmd, output, expect_warn, label=""):
    test_hook("Bash", {"command": cmd}, output, expect_warn, label)


def main():
    global passed, failed

    print("=" * 60)
    print("PostToolUse Hook Adversarial Tests")
    print("=" * 60)

    # ---- A. Exempt bypass: python3 name-in-path attacks ----
    print("\n--- A. python3 exempt bypass (expect WARN) ---")

    bash("python3 /tmp/evil-block-secrets.py",
         f"result: {FAKE_GHP}", True,
         "exempt name in arbitrary path")

    bash("python3 exploit.py --output block-secrets",
         f"token: {FAKE_GHP}", True,
         "exempt name in flag value")

    bash("python3 /home/user/my-claude-approval-report.py",
         f"data: {FAKE_HVS}", True,
         "exempt name in non-project path")

    bash("python3 scripts/warn-secrets-exfil.py",
         f"got: {FAKE_GHP}", True,
         "exempt name as substring of different script")

    bash("python3 -c 'print(open(\"x\").read())' block-secrets.py",
         f"{FAKE_GHP}", True,
         "inline code with exempt name as positional arg")

    # ---- B. Exempt bypass: grep-family attacks ----
    print("\n--- B. grep-family exempt bypass (expect WARN) ---")

    bash("grep . ~/.env",
         f"API_KEY={FAKE_GHP}", True,
         "grep dumping .env contents")

    bash("grep TOKEN ~/.env",
         f"VAULT_TOKEN={FAKE_HVS}", True,
         "grep extracting token from .env")

    bash("rg SECRET_KEY .env",
         f"SECRET_KEY={FAKE_GHP}", True,
         "ripgrep finding secret in .env")

    bash("ack password config.yml",
         f"db_password: {FAKE_GHP}", True,
         "ack finding password in config")

    bash("fgrep token credentials.json",
         f'"api_token": "{FAKE_HVS}"', True,
         "fgrep finding token in credentials")

    bash("egrep -r 'ghp_' /tmp/stolen/",
         f"/tmp/stolen/creds.txt:{FAKE_GHP}", True,
         "egrep finding real token in files")

    bash("grep -rn . /etc/shadow",
         f"root:{FAKE_GHP}:19000:0::", True,
         "grep on shadow file with token-like content")

    bash("ag secret src/",
         f"src/config.py:3:api_secret = \"{FAKE_GHP}\"", True,
         "ag finding secret assignment")

    # ---- C. Legitimate exemptions (expect NO WARN) ----
    print("\n--- C. Legitimate exemptions (expect NO WARN) ---")

    bash("python3 hooks/block-secrets.py",
         "ghp_[0-9a-zA-Z]{36} pattern defined\nPASS", False,
         "actual hook script")

    bash("python3 hooks/test_block_secrets.py",
         f"PASS: blocks {FAKE_GHP}", False,
         "actual test script with synthetic token")

    bash("python3 tests/test_report.py",
         "155/155 passed", False,
         "test script in tests/ dir")

    bash("python3 claude-approval-report.py --summary",
         "Calls: 1,234 total", False,
         "actual report script")

    bash("python3 scripts/ci-test-runner.py",
         "ALL SUITES PASSED", False,
         "CI test runner")

    bash("python3 hooks/warn-secrets-output.py",
         "exit 0", False,
         "actual warn-secrets hook script")

    bash("python3 verify_config.py",
         "config OK", False,
         "verify_ prefixed script")

    bash("cat hooks/block-secrets.py",
         "r'ghp_[0-9a-zA-Z]{36}' # GitHub PAT", False,
         "cat project source")

    bash("cat README.md",
         "# autoclaude\nAnalyzer for Claude Code", False,
         "cat README")

    bash("head CLAUDE.md",
         "# CLAUDE.md\nGuidance for Claude Code", False,
         "head CLAUDE.md")

    bash("cat claude-approval-report.py",
         "def classify_risk(tool_name, tool_input):", False,
         "cat report script")

    bash("less warn-secrets-output.py",
         "_PREFIXED_TOKEN_PATTERNS = re.compile(", False,
         "less on hook source")

    # ---- D. Secret detection in non-exempt commands ----
    print("\n--- D. Secret detection (expect WARN) ---")

    bash("curl https://api.example.com/data",
         f"Authorization: Bearer {FAKE_GHP}", True,
         "curl output with token")

    bash("vault kv get secret/myservice",
         f"token    {FAKE_HVS}", True,
         "vault output with hvs token")

    bash("env | sort",
         f"AWS_ACCESS_KEY_ID={FAKE_AWS}", True,
         "env output with AWS key")

    bash("cat /tmp/config.json",
         f'{{"token": "{FAKE_GHP}"}}', True,
         "reading non-project file with token")

    bash("echo test",
         FAKE_JWT, True,
         "output containing JWT")

    bash("openssl rsa -in key.pem",
         FAKE_PRIVKEY, True,
         "output containing private key")

    test_hook("Read", {"file_path": "/tmp/config.json"},
              f'{{"api_key": "{FAKE_GHP}"}}', True,
              "Read tool with token in output")

    test_hook("Edit", {"file_path": "/tmp/script.py"},
              f"old: TOKEN={FAKE_GHP}", True,
              "Edit tool with token in output")

    # ---- E. No false positives ----
    print("\n--- E. No false positives (expect NO WARN) ---")

    bash("ls -la /home/user",
         "drwxr-xr-x 5 user user 4096 May 10 src", False,
         "normal ls output")

    bash("git status",
         "On branch main\nnothing to commit", False,
         "normal git status")

    bash("git log --oneline -5",
         "abc1234 fix: update token validation\ndef5678 feat: add scanner", False,
         "git log mentioning 'token' (not a real token)")

    bash("python3 -c 'print(42)'",
         "42", False,
         "simple python output")

    bash("curl https://example.com",
         "<html><body>Hello World</body></html>", False,
         "curl with normal HTML output")

    bash("grep TODO src/main.py",
         "src/main.py:42:# TODO: refactor this", False,
         "grep with no secrets in output")

    bash("rg 'def test_' hooks/",
         "hooks/test_block_secrets.py:12:def test_hook", False,
         "ripgrep finding function defs (no secrets)")

    bash("true", "", False, "empty output")

    # ---- F. Edge cases ----
    print("\n--- F. Edge cases ---")

    test_hook("Bash", {"command": "echo test"}, {"key": "value"}, False,
              "dict tool_result without secrets")

    test_hook("Bash", {"command": "echo test"}, {"key": FAKE_GHP}, True,
              "dict tool_result with token in value")

    test_hook("Write", {"file_path": "/tmp/x"}, FAKE_GHP, False,
              "Write tool is not scanned")

    test_hook("Agent", {"prompt": "do stuff"}, FAKE_GHP, False,
              "unscanned tool type")

    bash("python3 unknown_script.py",
         f"{FAKE_GHP}", True,
         "python3 with non-exempt script name")

    bash("cat /tmp/random-file.txt",
         f"secret={FAKE_GHP}", True,
         "cat on non-exempt file with secret")

    bash("head /tmp/leaked-block-secrets-copy.txt",
         f"{FAKE_GHP}", True,
         "file with exempt substring in name but wrong location")

    # ---- Summary ----
    print(f"\n{'=' * 60}")
    total = passed + failed
    if failed:
        print(f"{passed}/{total} passed, {failed} failed")
        sys.exit(1)
    else:
        print(f"{passed}/{total} passed")


if __name__ == "__main__":
    main()
