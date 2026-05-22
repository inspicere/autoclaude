#!/usr/bin/env python3
"""Phase 4 audit fixes — 2026-05-22 audit H1: wrapper-prefixed dangerous env vars.

Validates that `env <VAR>=<sensitive>`, `sudo <VAR>=<sensitive>`,
`cd dir && <VAR>=<sensitive>`, and their combinations are blocked alongside
the direct `<VAR>=<sensitive>` form. Before the v1.1.2 fix, only the direct
form was caught — wrapper-stripping silently consumed dangerous assignments.
"""

import json
import subprocess
import os

HOOK = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'block-secrets.py')
HOME = os.path.expanduser('~')

# Sensitive paths used in positive cases — rotated across tests to exercise
# different SENSITIVE_PATH_RE branches.
SENSITIVE_TARGETS = [
    '/etc/shadow',
    HOME + '/.ssh/id_rsa',
    HOME + '/.aws/credentials',
    HOME + '/.env',
]

# Mirrors _DANGEROUS_ENV_VARS in hooks/block-secrets.py.
DANGEROUS_VARS = [
    'BASH_ENV', 'ENV', 'ZDOTDIR', 'PYTHONSTARTUP', 'RUBYOPT',
    'PERL5OPT', 'PERL5LIB', 'NODE_OPTIONS', 'LD_PRELOAD', 'LD_LIBRARY_PATH',
]

# Form templates — '{var}' and '{path}' are substituted. Each form is one
# distinct attack surface; the audit's H1 covered E/S/CD/CE/CS.
FORMS = [
    ('D',  "{var}={path} bash -c 'echo'"),
    ('E',  "env {var}={path} bash -c 'echo'"),
    ('S',  "sudo {var}={path} bash -c 'echo'"),
    ('CD', "cd /tmp && {var}={path} bash -c 'echo'"),
    ('CE', "cd /tmp && env {var}={path} bash -c 'echo'"),
    ('CS', "cd /tmp && sudo {var}={path} bash -c 'echo'"),
]

results = {'pass': 0, 'fail': 0, 'fail_labels': []}


def test_hook(command, expect_blocked, label):
    data = json.dumps({'tool_name': 'Bash', 'tool_input': {'command': command}})
    result = subprocess.run(
        ['python3', HOOK],
        input=data, capture_output=True, text=True
    )
    blocked = result.returncode == 2
    ok = blocked == expect_blocked
    status = 'PASS' if ok else 'FAIL'
    if ok:
        results['pass'] += 1
    else:
        results['fail'] += 1
        results['fail_labels'].append(label)
    detail = result.stderr.strip()[:80] if blocked else 'allowed'
    print(f'  {status}: {label} -> {detail}')


# === Positive cases: all forms × all dangerous vars must BLOCK ===
print("=== H1: dangerous env vars via direct + wrapper + cd-chain forms ===")
for form_id, template in FORMS:
    for i, var in enumerate(DANGEROUS_VARS):
        path = SENSITIVE_TARGETS[i % len(SENSITIVE_TARGETS)]
        cmd = template.format(var=var, path=path)
        label = f'{form_id}: {var}={path}'
        test_hook(cmd, True, label)

# === Negative controls: must ALLOW ===
print("\n=== Negative controls — non-dangerous or non-sensitive ===")
test_hook("env FOO=bar bash -c 'echo'", False, 'N1: env non-dangerous var')
test_hook("env BASH_ENV=/tmp/safe.sh bash -c 'echo'", False, 'N2: dangerous var to non-sensitive path')
test_hook('sudo -u terrabot ls', False, 'N3: sudo with no env')
test_hook('cd /tmp && ls', False, 'N4: cd with no env')
test_hook("env bash -c 'echo'", False, 'N5: env with no assignments')
test_hook("BASH_ENV=safe bash -c 'echo'", False, 'N6: dangerous var to short non-sensitive value')
test_hook("FOO=bar bash -c 'echo'", False, 'N7: direct non-dangerous var')
test_hook("cd /tmp && FOO=bar bash -c 'echo'", False, 'N8: cd + non-dangerous var')

# === Edge cases ===
print("\n=== Edge cases ===")
test_hook("sudo env BASH_ENV=/etc/shadow bash -c 'echo'", True,
          'EC1: two wrappers stacked (sudo env)')
test_hook("env -i BASH_ENV=/etc/shadow bash -c 'echo'", True,
          'EC2: env -i flag before assign')
test_hook("env -u FOO BASH_ENV=/etc/shadow bash -c 'echo'", True,
          'EC3: env -u <name> before assign')
test_hook("env --split-string='cat /etc/shadow'", True,
          'EC4: env --split-string (regression check, already handled)')
# EC5: subshell value is an architectural gap, documented in docs/hooks.md.
# Not blocked statically — block only if the literal $(…) string itself
# resolves as sensitive, which it does not.
test_hook("BASH_ENV=$(cat /etc/shadow) bash -c 'echo'", True,
          'EC5: subshell command-substitution reads sensitive file '
          '(blocked via subshell-content scan, not env-var check)')

# === Regression: existing direct-form blocks still work ===
print("\n=== Regression: direct-form blocks (must still BLOCK) ===")
test_hook("BASH_ENV=/etc/shadow bash -c 'echo hi'", True,
          'R1: direct BASH_ENV (existing behavior)')
test_hook("LD_PRELOAD=" + HOME + "/.env ls", True,
          'R2: direct LD_PRELOAD (existing behavior)')

# === Regression: wrapper sensitive-path detection unchanged ===
print("\n=== Regression: wrapper + sensitive path via file readers ===")
test_hook('sudo cat ' + HOME + '/.env', True, 'R3: sudo cat .env still blocked')
test_hook('env cat ' + HOME + '/.env', True, 'R4: env cat .env still blocked')
test_hook('cd /tmp && cat ' + HOME + '/.env', True, 'R5: cd && cat .env still blocked')


print("\n" + "=" * 60)
print(f"Results: {results['pass']} passed, {results['fail']} failed")
if results['fail']:
    print("\nFailed tests:")
    for label in results['fail_labels']:
        print(f"  - {label}")
    exit(1)
print("ALL TESTS PASSED")
