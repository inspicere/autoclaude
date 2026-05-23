#!/usr/bin/env python3
"""Phase 6 audit fixes — v1.2.1 hook-side items.

  M7  — first-run audit-log hint: when ~/.claude/hook-audit.jsonl doesn't
        exist yet, the hook prints a one-time stderr hint pointing at
        docs/hooks.md#audit-log and the HOOK_AUDIT=0 opt-out.
  L2  — _SENSITIVE_PATH_RE coverage for .envrc (direnv config files; can
        contain literal `export FOO=secret`). Mirror in landlock-sandbox.py
        so the pattern-sync CI gate stays green.
"""

import json
import os
import shutil
import subprocess
import sys
import tempfile

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


def run_hook(command, env_override=None):
    """Run the hook with the given Bash command; return CompletedProcess."""
    data = json.dumps({'tool_name': 'Bash', 'tool_input': {'command': command}})
    env = os.environ.copy()
    if env_override:
        env.update(env_override)
    return subprocess.run(
        ['python3', PRE_HOOK],
        input=data, capture_output=True, text=True, env=env,
    )


def test_block(command, expect_blocked, label):
    r = run_hook(command)
    blocked = r.returncode == 2
    detail = r.stderr.strip()[:80] if blocked else 'allowed'
    _record(blocked == expect_blocked, label, detail)


# =============================================================================
# L2 — .envrc coverage in _SENSITIVE_PATH_RE
# =============================================================================
print("=== L2: .envrc coverage ===")

home = os.path.expanduser('~')

test_block(f'cat {home}/.envrc', True, 'L2.1: cat ~/.envrc blocks')
test_block(f'sudo cat {home}/.envrc', True, 'L2.2: sudo cat ~/.envrc blocks')
test_block(f'env cat {home}/.envrc', True, 'L2.3: env cat ~/.envrc blocks')
test_block(f'cp {home}/.envrc /tmp/exfil', True, 'L2.4: cp ~/.envrc blocks')
test_block(f'less /some/proj/.envrc', True, 'L2.5: bare .envrc anywhere blocks')

# Negative: .envrc.example should NOT block (existing .example carveout)
test_block(f'cat /some/proj/.envrc.example', False, 'L2.N1: .envrc.example allowed')
test_block(f'cat /some/proj/.envrc.sample', False, 'L2.N2: .envrc.sample allowed')
test_block(f'cat /some/proj/.envrc.template', False, 'L2.N3: .envrc.template allowed')

# Negative: similar-looking but not .envrc
test_block(f'cat /some/proj/envrc.txt', False, 'L2.N4: envrc.txt allowed')
test_block(f'cat /some/proj/.envrcfile', False, 'L2.N5: .envrcfile (no extension boundary) allowed')


# =============================================================================
# M7 — first-run audit-log hint
# =============================================================================
print("\n=== M7: first-run audit-log hint ===")

# Set up a temporary HOME so we get a fresh audit-log state.
tmp_home = tempfile.mkdtemp(prefix='autoclaude_phase6_')
try:
    os.makedirs(os.path.join(tmp_home, '.claude'), exist_ok=True)
    env_override = {'HOME': tmp_home}

    # First call: audit log doesn't exist → expect stderr hint
    r1 = run_hook('ls -la', env_override=env_override)
    hint_present = 'HOOK_AUDIT' in r1.stderr and (
        'docs/hooks.md' in r1.stderr or 'audit log' in r1.stderr.lower()
    )
    _record(hint_present, 'M7.1: first-run prints HOOK_AUDIT hint',
            f"stderr={r1.stderr.strip()[:120]!r}")

    # Second call: audit log now exists → no hint
    r2 = run_hook('ls -la', env_override=env_override)
    hint_absent = ('HOOK_AUDIT' not in r2.stderr or
                   ('docs/hooks.md' not in r2.stderr and 'audit log' not in r2.stderr.lower()))
    _record(hint_absent, 'M7.2: second call suppresses hint',
            f"stderr={r2.stderr.strip()[:80]!r}")

    # With HOOK_AUDIT=0: no hint regardless of state
    tmp_home2 = tempfile.mkdtemp(prefix='autoclaude_phase6_off_')
    try:
        os.makedirs(os.path.join(tmp_home2, '.claude'), exist_ok=True)
        r3 = run_hook('ls -la', env_override={
            'HOME': tmp_home2,
            'HOOK_AUDIT': '0',
        })
        no_hint = ('HOOK_AUDIT' not in r3.stderr or
                   'docs/hooks.md' not in r3.stderr)
        _record(no_hint, 'M7.3: HOOK_AUDIT=0 suppresses hint',
                f"stderr={r3.stderr.strip()[:80]!r}")
    finally:
        shutil.rmtree(tmp_home2, ignore_errors=True)
finally:
    shutil.rmtree(tmp_home, ignore_errors=True)


# =============================================================================
# Regression — existing sensitive-path blocks still work
# =============================================================================
print("\n=== Regression: existing path blocks preserved ===")

test_block(f'cat {home}/.env', True, 'R1: ~/.env still blocks')
test_block(f'cat {home}/.ssh/id_rsa', True, 'R2: ~/.ssh/id_rsa still blocks')
test_block(f'cat /etc/shadow', True, 'R3: /etc/shadow still blocks')
test_block(f'cat {home}/.env.example', False, 'R4: .env.example still allowed')


# =============================================================================
print("\n" + "=" * 60)
print(f"Results: {results['pass']} passed, {results['fail']} failed")
if results['fail']:
    print("\nFailed tests:")
    for label in results['fail_labels']:
        print(f"  - {label}")
    sys.exit(1)
print("ALL TESTS PASSED")
