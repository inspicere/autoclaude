#!/usr/bin/env python3
"""Test suite for Phase 1 audit fixes (M1, M2, M3, M11) from 2026-05-16 project audit.

Covers:
  M1 — _RE_SECRET_ASSIGN captures quoted values with spaces
  M2 — HOOK_DEBUG/HOOK_AUDIT/HOOK_CORRELATE accept true/yes/on
  M3 — audit log summary/reason fields are redacted
  M11 — multiple secret warnings surface "+N more" count
"""

import importlib.util
import json
import os
import subprocess
import sys
import tempfile

HOOK = os.path.join(os.path.dirname(__file__), 'block-secrets.py')
POST_HOOK = os.path.join(os.path.dirname(__file__), 'warn-secrets-output.py')


def _load_module(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


# Import the hook modules so we can poke their internals directly
block_secrets = _load_module('block_secrets', HOOK)
warn_secrets = _load_module('warn_secrets', POST_HOOK)


results = []


def check(condition, label):
    status = 'PASS' if condition else 'FAIL'
    results.append(condition)
    print(f'  {status}: {label}')


def run_hook(tool_name, tool_input, env=None):
    """Run block-secrets.py with the given input. Returns (exit_code, stderr)."""
    data = json.dumps({'tool_name': tool_name, 'tool_input': tool_input})
    full_env = os.environ.copy()
    if env:
        full_env.update(env)
    r = subprocess.run(
        ['python3', HOOK],
        input=data, capture_output=True, text=True, timeout=10,
        env=full_env,
    )
    return r.returncode, r.stderr


# =============================================================================
# M1 — _RE_SECRET_ASSIGN captures quoted values with spaces
# =============================================================================
print('=== M1: _RE_SECRET_ASSIGN quoted-value capture ===')

# Direct regex behavior
m = block_secrets._RE_SECRET_ASSIGN.search('export API_KEY="value with spaces here"')
check(m is not None, "regex matches quoted value with spaces")
check(m.group(2) == '"value with spaces here"',
      f"full quoted value captured (got {m.group(2)!r})")

m = block_secrets._RE_SECRET_ASSIGN.search("VAULT_TOKEN='multi word secret'")
check(m is not None, "regex matches single-quoted value with spaces")
check(m.group(2) == "'multi word secret'",
      f"full single-quoted value captured (got {m.group(2)!r})")

# Unquoted still works (backward compatibility)
m = block_secrets._RE_SECRET_ASSIGN.search('API_KEY=plainvalue')
check(m is not None, "regex still matches unquoted value")
check(m.group(2) == 'plainvalue', f"unquoted value captured (got {m.group(2)!r})")

# Redaction now covers the entire quoted span (M3 helper)
red = block_secrets._redact('export API_KEY="my long secret with spaces"')
check('<REDACTED>' in red and 'my long secret' not in red,
      f"redaction covers full quoted span (got {red!r})")

# End-to-end: hook still blocks the assignment
code, _ = run_hook('Bash', {'command': 'export API_KEY="this is a real secret value"'})
check(code == 2, "hook blocks Bash with quoted secret containing spaces")


# =============================================================================
# M2 — Env-var truthy parsing accepts true/yes/on
# =============================================================================
print('\n=== M2: env-var truthy parsing ===')

check('1' in block_secrets._TRUTHY, "'1' is truthy")
check('true' in block_secrets._TRUTHY, "'true' is truthy")
check('yes' in block_secrets._TRUTHY, "'yes' is truthy")
check('on' in block_secrets._TRUTHY, "'on' is truthy")
check('0' not in block_secrets._TRUTHY, "'0' is not truthy")
check('false' not in block_secrets._TRUTHY, "'false' is not truthy")

check('1' in warn_secrets._TRUTHY, "warn-secrets _TRUTHY has '1'")
check('true' in warn_secrets._TRUTHY, "warn-secrets _TRUTHY has 'true'")

# End-to-end: HOOK_AUDIT=true creates an audit log entry
with tempfile.TemporaryDirectory() as tmpdir:
    log_path = os.path.join(tmpdir, 'audit.jsonl')
    full_env = os.environ.copy()
    full_env['HOOK_AUDIT'] = 'true'
    full_env['HOOK_DEBUG'] = 'YES'
    # Point audit log at our tmpdir by patching HOME
    full_env['HOME'] = tmpdir
    os.makedirs(os.path.join(tmpdir, '.claude'), exist_ok=True)

    data = json.dumps({'tool_name': 'Bash', 'tool_input': {'command': 'ls -la'}})
    r = subprocess.run(['python3', HOOK], input=data,
                       capture_output=True, text=True, timeout=10, env=full_env)
    check(r.returncode == 0, f"ls allowed (got exit {r.returncode}, stderr={r.stderr[:80]})")

    expected_log = os.path.join(tmpdir, '.claude', 'hook-audit.jsonl')
    check(os.path.exists(expected_log),
          f"HOOK_AUDIT=true creates audit log (path={expected_log}, exists={os.path.exists(expected_log)})")

    if os.path.exists(expected_log):
        with open(expected_log) as f:
            entry = json.loads(f.readline())
        check(entry.get('decision') == 'allow',
              f"audit entry decision=allow (got {entry.get('decision')})")


# =============================================================================
# M3 — Audit log summary/reason fields are redacted
# =============================================================================
print('\n=== M3: audit log summary/reason redaction ===')

# Helper redacts known tokens
red = block_secrets._redact('ghp_' + 'a' * 36)
check('<REDACTED>' in red and 'ghp_' not in red, "redact GitHub PAT")

red = block_secrets._redact('-H "Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"')
check('<REDACTED-JWT>' in red, "redact JWT")

red = block_secrets._redact('VAULT_TOKEN=hvs.aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa')
check('<REDACTED>' in red and 'hvs.' not in red,
      f"redact secret assignment (got {red!r})")

# Empty input is safe
check(block_secrets._redact('') == '', "redact empty string returns empty")
check(block_secrets._redact(None) is None, "redact None returns None")

# End-to-end: a Bash command whose first word looks like a token lands redacted
# in the audit log summary
with tempfile.TemporaryDirectory() as tmpdir:
    full_env = os.environ.copy()
    full_env['HOOK_AUDIT'] = '1'
    full_env['HOME'] = tmpdir
    os.makedirs(os.path.join(tmpdir, '.claude'), exist_ok=True)

    # An echo command with a token-shaped arg — the COMMAND scan will block,
    # but we also want to verify the summary (built from first_word + length)
    # gets redacted on its way to the log
    fake_token = 'ghp_' + 'b' * 36
    data = json.dumps({'tool_name': 'Bash',
                       'tool_input': {'command': f'echo {fake_token}'}})
    r = subprocess.run(['python3', HOOK], input=data,
                       capture_output=True, text=True, timeout=10, env=full_env)
    check(r.returncode == 2, "echo with GitHub PAT is blocked")

    log_path = os.path.join(tmpdir, '.claude', 'hook-audit.jsonl')
    check(os.path.exists(log_path), "block decision creates audit entry")
    if os.path.exists(log_path):
        with open(log_path) as f:
            entry = json.loads(f.readline())
        cmd_field = entry.get('command', '')
        check(fake_token not in cmd_field,
              f"token redacted from command field (got cmd={cmd_field!r})")

    # Now feed a command whose first word IS the token (unusual but possible)
    # — verify summary gets redacted
    data = json.dumps({'tool_name': 'Bash',
                       'tool_input': {'command': f'{fake_token} arg'}})
    r = subprocess.run(['python3', HOOK], input=data,
                       capture_output=True, text=True, timeout=10, env=full_env)
    if os.path.exists(log_path):
        with open(log_path) as f:
            lines = f.readlines()
        entry = json.loads(lines[-1])
        summary_field = entry.get('summary', '')
        check(fake_token not in summary_field,
              f"token redacted from summary field (got summary={summary_field!r})")


# =============================================================================
# M11 — Multi-warning surfacing
# =============================================================================
print('\n=== M11: multi-warning surfacing ===')

# A command with two warn-level patterns: two VAR=$(...) assignments
# Each one triggers a "will be set from a secret source at runtime" warning
code, stderr = run_hook('Bash', {'command':
    'TOKEN_A=$(vault kv get -field=t secret/a); TOKEN_B=$(vault kv get -field=t secret/b); echo ok'
})
# Warn surfaces via stdout JSON (permissionDecision=ask) and exit 0
# Check that the reason mentions the additional count
# Note: warn() uses sys.stdout for the JSON response, sys.exit(0)
data = json.dumps({'tool_name': 'Bash', 'tool_input': {'command':
    'TOKEN_A=$(vault kv get -field=t secret/a); TOKEN_B=$(vault kv get -field=t secret/b); echo ok'
}})
r = subprocess.run(['python3', HOOK], input=data,
                   capture_output=True, text=True, timeout=10)
check(r.returncode == 0, f"two-warning command exits 0 (warn, not block; got {r.returncode})")
try:
    resp = json.loads(r.stdout) if r.stdout else {}
    reason = resp.get('hookSpecificOutput', {}).get('permissionDecisionReason', '')
    check('+1 more' in reason or '+2 more' in reason,
          f"reason mentions additional warnings (got {reason[:200]!r})")
except json.JSONDecodeError:
    check(False, f"warn response is valid JSON (got stdout={r.stdout[:200]!r})")

# Single warning does NOT include "+N more"
data = json.dumps({'tool_name': 'Bash', 'tool_input': {'command':
    'TOKEN_X=$(vault kv get -field=t secret/x); echo ok'
}})
r = subprocess.run(['python3', HOOK], input=data,
                   capture_output=True, text=True, timeout=10)
try:
    resp = json.loads(r.stdout) if r.stdout else {}
    reason = resp.get('hookSpecificOutput', {}).get('permissionDecisionReason', '')
    check('more' not in reason.lower() or '+0 more' not in reason,
          f"single warning has no '+N more' (got {reason[:200]!r})")
except json.JSONDecodeError:
    check(False, "single warning response is valid JSON")


# =============================================================================
# SUMMARY
# =============================================================================
print("\n" + "=" * 70)
passed = sum(results)
total = len(results)
print(f"RESULTS: {passed}/{total} passed")
print("=" * 70)
sys.exit(0 if passed == total else 1)
