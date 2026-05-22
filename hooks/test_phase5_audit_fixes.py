#!/usr/bin/env python3
"""Phase 5 audit fixes — 2026-05-22 audit H2 + Mediums + #758 follow-up.

Items shipped in v1.2.0:
  H2  — warn-secrets-output.py uses decision:"warn" (silently ignored by
        current Claude Code). Migrate to decision:"block" + reason.
  2.1 — block-secrets.py realpath pre-filter (perf; behaviour-preserving).
  2.4 — _classify_leak_confidence: curl -v / 2>&1 → "high" confidence.
  #758 — block-secrets.py pipe-safe carveout: `… | xargs -I{} curl -H
         "Authorization: token {}" …` should NOT block (xargs replaces {}
         with each line from the pipe, never embeds the literal token in
         shell history).
  2.2 — warn-secrets-output.py _extract_variable_names: also catch backtick
        and double-quoted command substitution.
"""

import json
import os
import re
import subprocess
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
PRE_HOOK = os.path.join(HERE, 'block-secrets.py')
POST_HOOK = os.path.join(HERE, 'warn-secrets-output.py')
HOME = os.path.expanduser('~')

results = {'pass': 0, 'fail': 0, 'fail_labels': []}


def _record(ok, label, detail):
    status = 'PASS' if ok else 'FAIL'
    if ok:
        results['pass'] += 1
    else:
        results['fail'] += 1
        results['fail_labels'].append(label)
    print(f'  {status}: {label} -> {detail}')


def test_pre(command, expect_blocked, label):
    """Run PreToolUse block-secrets.py against a Bash command, assert block/allow."""
    data = json.dumps({'tool_name': 'Bash', 'tool_input': {'command': command}})
    result = subprocess.run(
        ['python3', PRE_HOOK],
        input=data, capture_output=True, text=True
    )
    blocked = result.returncode == 2
    detail = result.stderr.strip()[:80] if blocked else 'allowed'
    _record(blocked == expect_blocked, label, detail)
    return result


def test_pre_warn(command, expect_confidence, label):
    """Run PreToolUse and assert the warn output carries the expected confidence
    via the exposure-message phrase ('is likely to expose' = high,
    'may expose' = low). Returns the parsed JSON output (or {}).
    """
    data = json.dumps({'tool_name': 'Bash', 'tool_input': {'command': command}})
    result = subprocess.run(
        ['python3', PRE_HOOK],
        input=data, capture_output=True, text=True
    )
    # warn output is JSON to stdout with exit 0
    try:
        out = json.loads(result.stdout) if result.stdout.strip() else {}
    except json.JSONDecodeError:
        out = {}
    reason_text = out.get('hookSpecificOutput', {}).get('permissionDecisionReason', '')
    if expect_confidence == 'high':
        ok = 'is likely to expose' in reason_text
    elif expect_confidence == 'low':
        ok = 'may expose' in reason_text and 'is likely to expose' not in reason_text
    else:
        ok = False
    _record(ok, label, f"confidence={'high' if 'is likely' in reason_text else 'low' if 'may expose' in reason_text else 'none'}")
    return result


def test_post(command, tool_result, expect_decision, expect_in_reason, label):
    """Run PostToolUse hook with a fake tool result; assert decision + reason text."""
    payload = json.dumps({
        'tool_name': 'Bash',
        'tool_input': {'command': command},
        'tool_result': tool_result,
    })
    result = subprocess.run(
        ['python3', POST_HOOK],
        input=payload, capture_output=True, text=True
    )
    try:
        out = json.loads(result.stdout) if result.stdout.strip() else {}
    except json.JSONDecodeError:
        out = {}
    decision_ok = out.get('decision') == expect_decision
    reason_ok = expect_in_reason in out.get('reason', '') if expect_in_reason else True
    ok = decision_ok and reason_ok
    detail = f"decision={out.get('decision')!r} reason={out.get('reason','')[:50]!r}"
    _record(ok, label, detail)
    return result


# =============================================================================
# H2 — PostToolUse hook must use decision:"block", not decision:"warn"
# =============================================================================
print("=== H2: PostToolUse output schema (decision:'block' for leaked secrets) ===")

# Known token in output -> block decision (was: 'warn', silently ignored)
test_post(
    'cat config.json',
    'GITHUB_TOKEN=ghp_' + 'a' * 36,
    'block',
    'SECRET IN OUTPUT',
    'H2.1: known token in output emits decision:"block"',
)

# JWT in output -> block decision
test_post(
    'cat config.json',
    'JWT=eyJhbGciOiJIUzI1NiIsI.eyJzdWIiOiIxMjM0NTY3ODkwIiwidGVzdCI.aBcDeFgHiJkLmN0123',
    'block',
    'SECRET IN OUTPUT',
    'H2.2: JWT in output emits decision:"block"',
)

# Private key header in output -> block decision
test_post(
    'cat key.pem',
    '-----BEGIN RSA PRIVATE KEY-----\nMIIEpAIBAAKCAQEA...',
    'block',
    'SECRET IN OUTPUT',
    'H2.3: private key header emits decision:"block"',
)

# Reason text must still include "rotate" guidance
test_post(
    'cat config.json',
    'TOKEN=ghp_' + 'a' * 36,
    'block',
    'rotate',
    'H2.4: reason includes rotation guidance',
)

# Clean output -> no decision emitted (hook exits 0 with empty body)
result = subprocess.run(
    ['python3', POST_HOOK],
    input=json.dumps({
        'tool_name': 'Bash',
        'tool_input': {'command': 'echo hello'},
        'tool_result': 'hello\n',
    }),
    capture_output=True, text=True,
)
ok = result.returncode == 0 and not result.stdout.strip()
_record(ok, 'H2.5: clean output produces no decision', f"stdout={result.stdout!r} exit={result.returncode}")


# =============================================================================
# 2.4 — _classify_leak_confidence: curl -v / -vvv / 2>&1 → "high" confidence
# =============================================================================
print("\n=== 2.4: _classify_leak_confidence — verbose / stderr-merge → 'high' ===")

# curl -v with auth var -> high (verbose flag exposes headers to stderr)
test_pre_warn(
    'curl -v -H "Authorization: Bearer $GITHUB_TOKEN" https://api.example.com',
    'high',
    '2.4.1: curl -v with $TOKEN → high',
)

# curl -vvv -> high (more verbose)
test_pre_warn(
    'curl -vvv -H "Authorization: Bearer $TOKEN" https://api.example.com',
    'high',
    '2.4.2: curl -vvv with $TOKEN → high',
)

# curl --verbose -> high
test_pre_warn(
    'curl --verbose -H "Authorization: Bearer $TOKEN" https://api.example.com',
    'high',
    '2.4.3: curl --verbose with $TOKEN → high',
)

# 2>&1 redirect merges stderr to stdout, exposing the value in transcript -> high
test_pre_warn(
    'curl -H "Authorization: Bearer $TOKEN" https://api.example.com 2>&1',
    'high',
    '2.4.4: 2>&1 redirect with $TOKEN → high',
)

# Bare curl (no -v, no 2>&1) -> low (existing behaviour preserved)
test_pre_warn(
    'curl -H "Authorization: Bearer $TOKEN" https://api.example.com',
    'low',
    '2.4.5: bare curl with $TOKEN → low (regression check)',
)

# >/dev/null still 'low' (existing behaviour)
test_pre_warn(
    'curl -H "Authorization: Bearer $TOKEN" https://api.example.com > /dev/null',
    'low',
    '2.4.6: >/dev/null with $TOKEN → low (regression check)',
)


# =============================================================================
# #758 — Hook should ALLOW the `xargs -I{} curl -H "token {}"` pipe pattern.
# The report script's _classify_exposure_risk already classifies this as
# 'pipe-safe' (no transcript exposure). Mirror the carveout in the hook.
# =============================================================================
print("\n=== #758: xargs -I{} pipe-safe carveout ===")

test_pre(
    'vault kv get -field=api_token secret/forgejo | xargs -I{} curl -s -H "Authorization: token {}" http://192.168.86.124:3000/api/v1/repos/inspicere/autoclaude',
    False,
    '#758.1: documented Forgejo API pattern (xargs -I{} | curl)',
)

test_pre(
    'vault kv get -field=api_token secret/forgejo | xargs -I{0} curl -H "Authorization: Bearer {0}" http://example.com',
    False,
    '#758.2: xargs -I{0} variant',
)

test_pre(
    'cat /tmp/tokens.txt | xargs -I{} curl -H "Authorization: token {}" http://example.com',
    False,
    '#758.3: pipe from arbitrary upstream (xargs still pipe-safe)',
)

# Negative controls — literal `{}` without a pipe is NOT safe; this is just a
# typo or an attempt to bypass detection.
test_pre(
    'curl -H "Authorization: token {}" http://example.com',
    True,
    '#758.N1: literal {} without pipe still blocks',
)

# No `{}` template even with pipe — the value would still be raw on the curl
# command line if xargs is invoked differently.
test_pre(
    'vault kv get -field=api_token secret/forgejo | xargs curl -H',
    False,
    '#758.N2: xargs without -I and incomplete auth — no auth header parsed',
)

# Real auth header with a literal token (existing block path)
test_pre(
    'curl -H "Authorization: token ghp_' + 'a' * 36 + '" http://example.com',
    True,
    '#758.N3: literal known token still blocks',
)


# =============================================================================
# 2.2 — _extract_variable_names: catch backtick + double-quoted subst forms.
# The PostToolUse correlation reads recent warns from the audit log and
# extracts variable names. Pre-fix: only `\b\w+=\$\(` matched. After fix:
# also `\b\w+="\$\(`, `\b\w+=\``, `\b\w+="\``.
# =============================================================================
print("\n=== 2.2: _extract_variable_names broader subst forms ===")

# Verify the regex change directly by importing the hook module.
import importlib.util
spec = importlib.util.spec_from_file_location("warn_hook", POST_HOOK)
warn_hook = importlib.util.module_from_spec(spec)
spec.loader.exec_module(warn_hook)

cases = [
    ('TOK=$(vault kv get -field=p secret/db)',        {'TOK'}, '2.2.1: $() form (existing)'),
    ('TOK="$(vault kv get -field=p secret/db)"',      {'TOK'}, '2.2.2: "$()" double-quoted form'),
    ('TOK=`vault kv get -field=p secret/db`',         {'TOK'}, '2.2.3: backtick form'),
    ('TOK="`vault kv get -field=p secret/db`"',       {'TOK'}, '2.2.4: double-quoted backtick form'),
    ('FOO=bar',                                        set(),   '2.2.5: plain assignment — not captured'),
]

for cmd, expected_subset, label in cases:
    recs = [{'reason': '', 'command': cmd}]
    extracted = warn_hook._extract_variable_names(recs)
    ok = expected_subset.issubset(extracted) if expected_subset else not extracted
    _record(ok, label, f"extracted={extracted}")


# =============================================================================
# Regression — existing warn/block paths still work
# =============================================================================
print("\n=== Regression: existing warn / block paths preserved ===")

# Literal known token in PreToolUse — must still block
test_pre(
    'curl -H "Authorization: Bearer ghp_' + 'a' * 36 + '" http://example.com',
    True,
    'R1: literal GitHub PAT still blocks',
)

# Variable reference — must still warn (not block)
data = json.dumps({'tool_name': 'Bash', 'tool_input': {
    'command': 'curl -H "Authorization: Bearer $GITHUB_TOKEN" http://example.com'
}})
result = subprocess.run(['python3', PRE_HOOK], input=data, capture_output=True, text=True)
ok = result.returncode == 0 and '"permissionDecision": "ask"' in result.stdout
_record(ok, 'R2: $GITHUB_TOKEN warn (permissionDecision:ask) preserved',
        f"exit={result.returncode}")


# =============================================================================
print("\n" + "=" * 60)
print(f"Results: {results['pass']} passed, {results['fail']} failed")
if results['fail']:
    print("\nFailed tests:")
    for label in results['fail_labels']:
        print(f"  - {label}")
    sys.exit(1)
print("ALL TESTS PASSED")
