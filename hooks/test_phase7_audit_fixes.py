#!/usr/bin/env python3
"""Phase 7 audit fixes — v1.2.2 hook-side items.

  L-cap — _split_shell_commands max-segments cap: pathologically long
          command chains (many ;/&&/||/| segments) become local-DoS risk
          for the static analyzer. Cap segments at a generous threshold;
          beyond that the hook fail-closes with a 'too complex' block.
"""

import json
import os
import subprocess
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
PRE_HOOK = os.path.join(HERE, 'block-secrets.py')

results = {'pass': 0, 'fail': 0, 'fail_labels': []}


def _record(ok, label, detail):
    status = 'PASS' if ok else 'FAIL'
    if ok:
        results['pass'] += 1
    else:
        results['fail'] += 1
        results['fail_labels'].append(label)
    print(f'  {status}: {label} -> {detail}')


def test_block(command, expect_blocked, label, expect_in_stderr=None):
    data = json.dumps({'tool_name': 'Bash', 'tool_input': {'command': command}})
    r = subprocess.run(
        ['python3', PRE_HOOK],
        input=data, capture_output=True, text=True, timeout=30,
    )
    blocked = r.returncode == 2
    ok = blocked == expect_blocked
    if ok and expect_in_stderr is not None and blocked:
        ok = expect_in_stderr in r.stderr
    detail = r.stderr.strip()[:80] if blocked else 'allowed'
    _record(ok, label, detail)


# =============================================================================
# L-cap: _split_shell_commands max-segments fail-closed cap
# =============================================================================
print("=== L-cap: _split_shell_commands max-segments cap ===")

# Normal multi-segment commands should still pass (well under any reasonable cap).
test_block('echo a; echo b; echo c', False, 'L-cap.1: 3 segments — allow')
test_block('cd /tmp && ls && pwd && date', False, 'L-cap.2: 4 segments — allow')
test_block(' && '.join(['echo x'] * 50), False, 'L-cap.3: 50 segments — allow')
test_block(' && '.join(['echo x'] * 200), False, 'L-cap.4: 200 segments — allow')

# Pathological input above the cap should fail-closed with a clear reason.
test_block(' && '.join(['echo x'] * 600), True,
           'L-cap.5: 600 segments — block (too complex)',
           expect_in_stderr='too complex')
test_block(';'.join(['echo y'] * 1000), True,
           'L-cap.6: 1000 segments — block',
           expect_in_stderr='too complex')


# =============================================================================
# Regression: existing path blocks still work
# =============================================================================
print("\n=== Regression: existing checks unaffected by the cap ===")

home = os.path.expanduser('~')
test_block(f'cat {home}/.env', True, 'R1: sensitive-path block unaffected')
test_block(f'echo hello', False, 'R2: normal command unaffected')
test_block(f'cat /tmp/safe.txt', False, 'R3: safe path unaffected')


# =============================================================================
print("\n" + "=" * 60)
print(f"Results: {results['pass']} passed, {results['fail']} failed")
if results['fail']:
    print("\nFailed tests:")
    for label in results['fail_labels']:
        print(f"  - {label}")
    sys.exit(1)
print("ALL TESTS PASSED")
