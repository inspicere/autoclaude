#!/usr/bin/env python3
"""Test analysis-only finding fixes — 25 findings from round 3 red team analysis."""

import json
import subprocess
import os

HOOK = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'block-secrets.py')
WARN_HOOK = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'warn-secrets-output.py')
HOME = os.path.expanduser('~')
S = HOME + '/.env'
T = HOME + '/autoclaude_engagement_target/.env'

results = {'pass': 0, 'fail': 0}


def test_hook(tool_name, tool_input, expect_blocked, label):
    data = json.dumps({'tool_name': tool_name, 'tool_input': tool_input})
    result = subprocess.run(
        ['python3', HOOK],
        input=data, capture_output=True, text=True
    )
    blocked = result.returncode == 2
    status = 'PASS' if blocked == expect_blocked else 'FAIL'
    results['pass' if status == 'PASS' else 'fail'] += 1
    detail = result.stderr.strip()[:100] if blocked else 'allowed'
    print(f'  {status}: {label} -> {detail}')


def test_warn_hook(tool_name, tool_input, tool_result, expect_warning, label):
    """Test PostToolUse warn hook."""
    data = json.dumps({
        'tool_name': tool_name,
        'tool_input': tool_input,
        'tool_result': tool_result,
    })
    result = subprocess.run(
        ['python3', WARN_HOOK],
        input=data, capture_output=True, text=True
    )
    has_warning = 'SECRET IN OUTPUT' in result.stdout
    status = 'PASS' if has_warning == expect_warning else 'FAIL'
    results['pass' if status == 'PASS' else 'fail'] += 1
    detail = 'warned' if has_warning else 'clean'
    print(f'  {status}: {label} -> {detail}')


# === 6c: ANSI-C quoting ($'...') ===
print("=== 6c: ANSI-C quoting decode ===")
# .env encoded as hex
test_hook('Bash', {'command': "$'cat " + HOME + "/\\x2e\\x65\\x6e\\x76'"}, True, 'ANSI-C hex .env')
# .env encoded as octal
test_hook('Bash', {'command': "$'cat " + HOME + "/\\056\\145\\156\\166'"}, True, 'ANSI-C octal .env')
# Mixed normal and ANSI-C
test_hook('Bash', {'command': "head $'" + HOME + "/\\x2eenv'"}, True, 'ANSI-C hex head .env')
# Safe command with ANSI-C
test_hook('Bash', {'command': "$'echo \\x48\\x65\\x6c\\x6c\\x6f'"}, False, 'ANSI-C safe echo')
# Unicode escapes
test_hook('Bash', {'command': "$'cat " + HOME + "/\\u002e\\u0065\\u006e\\u0076'"}, True, 'ANSI-C unicode .env')

# === 6d: local/declare/typeset/readonly variable tracking ===
print("\n=== 6d: local/declare/typeset/readonly variable assignments ===")
test_hook('Bash', {'command': 'local F=' + S + '; cat "$F"'}, True, 'local var .env')
test_hook('Bash', {'command': 'declare F=' + S + '; cat "$F"'}, True, 'declare var .env')
test_hook('Bash', {'command': 'typeset F=' + S + '; cat "$F"'}, True, 'typeset var .env')
test_hook('Bash', {'command': 'readonly F=' + S + '; cat "$F"'}, True, 'readonly var .env')
test_hook('Bash', {'command': 'declare -r F=' + S + '; cat "$F"'}, True, 'declare -r var .env')
test_hook('Bash', {'command': 'local -x F=' + S + '; cat "$F"'}, True, 'local -x var .env')
# Safe declarations
test_hook('Bash', {'command': 'local F=/tmp/safe.txt; cat "$F"'}, False, 'local safe var')
test_hook('Bash', {'command': 'declare -i N=42; echo $N'}, False, 'declare integer')
test_hook('Bash', {'command': 'readonly VERSION=1.0; echo $VERSION'}, False, 'readonly safe var')

# === 6e: >() output process substitution ===
print("\n=== 6e: >() output process substitution ===")
test_hook('Bash', {'command': 'cat ' + S + ' > >(tee /tmp/leak)'}, True, '>() with cat .env')
test_hook('Bash', {'command': 'echo hello > >(cat ' + S + ')'}, True, '>() inner reads .env')
test_hook('Bash', {'command': 'echo hello > >(tee /tmp/safe.txt)'}, False, '>() safe')

# === 6f: Additional command wrappers ===
print("\n=== 6f: chroot wrapper ===")
test_hook('Bash', {'command': 'chroot /newroot cat ' + S}, True, 'chroot cat .env')
test_hook('Bash', {'command': 'chroot /newroot cat /tmp/safe.txt'}, False, 'chroot safe')

print("\n=== 6f: nsenter wrapper ===")
test_hook('Bash', {'command': 'nsenter -t 1234 --mount cat ' + S}, True, 'nsenter cat .env')
test_hook('Bash', {'command': 'nsenter --target=1234 -m cat ' + S}, True, 'nsenter --target= cat .env')
test_hook('Bash', {'command': 'nsenter -t 1234 ls /tmp'}, False, 'nsenter safe')

print("\n=== 6f: runuser wrapper ===")
test_hook('Bash', {'command': 'runuser -u nobody cat ' + S}, True, 'runuser cat .env')
test_hook('Bash', {'command': 'runuser -u nobody ls /tmp'}, False, 'runuser safe')

print("\n=== 6f: doas wrapper ===")
test_hook('Bash', {'command': 'doas cat ' + S}, True, 'doas cat .env')
test_hook('Bash', {'command': 'doas -u root cat ' + S}, True, 'doas -u root cat .env')
test_hook('Bash', {'command': 'doas ls /tmp'}, False, 'doas safe')

print("\n=== 6f: pkexec wrapper ===")
test_hook('Bash', {'command': 'pkexec cat ' + S}, True, 'pkexec cat .env')
test_hook('Bash', {'command': 'pkexec ls /tmp'}, False, 'pkexec safe')

print("\n=== 6f: setpriv wrapper ===")
test_hook('Bash', {'command': 'setpriv --reuid=nobody cat ' + S}, True, 'setpriv cat .env')
test_hook('Bash', {'command': 'setpriv --reuid=nobody ls /tmp'}, False, 'setpriv safe')

print("\n=== 6f: sg/newgrp wrapper ===")
test_hook('Bash', {'command': 'sg staff cat ' + S}, True, 'sg cat .env')
test_hook('Bash', {'command': 'newgrp staff cat ' + S}, True, 'newgrp cat .env')
test_hook('Bash', {'command': 'sg staff ls /tmp'}, False, 'sg safe')

print("\n=== 6f: su -c extraction ===")
test_hook('Bash', {'command': "su - nobody -c 'cat " + S + "'"}, True, 'su -c cat .env')
test_hook('Bash', {'command': 'su nobody -c "cat ' + S + '"'}, True, 'su -c with user')
test_hook('Bash', {'command': "su - nobody -c 'ls /tmp'"}, False, 'su -c safe')

print("\n=== 6f: systemd-run extraction ===")
test_hook('Bash', {'command': 'systemd-run --scope -- cat ' + S}, True, 'systemd-run -- cat .env')
test_hook('Bash', {'command': 'systemd-run --scope cat ' + S}, True, 'systemd-run cat .env')
test_hook('Bash', {'command': 'systemd-run --scope -- ls /tmp'}, False, 'systemd-run -- safe')

# Wrapper combinations
print("\n=== 6f: wrapper combinations ===")
test_hook('Bash', {'command': 'sudo nsenter -t 1 cat ' + S}, True, 'sudo nsenter cat .env')
test_hook('Bash', {'command': 'chroot /r doas cat ' + S}, True, 'chroot doas cat .env')

# === 6g: Crypto tools ===
print("\n=== 6g: Crypto tool file access ===")
test_hook('Bash', {'command': 'gpg --decrypt ' + HOME + '/.gnupg/private-keys/key.gpg'}, True, 'gpg --decrypt private key')
test_hook('Bash', {'command': 'gpg2 -d ' + HOME + '/.ssh/id_rsa'}, True, 'gpg2 -d ssh key')
test_hook('Bash', {'command': 'age -d -i ' + HOME + '/.ssh/id_ed25519 secret.age'}, True, 'age -i ssh key')
test_hook('Bash', {'command': 'ssh-keygen -f ' + HOME + '/.ssh/id_rsa -y'}, True, 'ssh-keygen -f private key')
# Safe crypto operations
test_hook('Bash', {'command': 'gpg --verify signature.sig document.txt'}, False, 'gpg --verify safe')
test_hook('Bash', {'command': 'age -e -r age1abc message.txt'}, False, 'age encrypt safe')
test_hook('Bash', {'command': 'ssh-keygen -t ed25519'}, False, 'ssh-keygen generate safe')

# === 6h: Deferred execution ===
print("\n=== 6h: Deferred execution blocking ===")
test_hook('Bash', {'command': 'at now'}, True, 'at now')
test_hook('Bash', {'command': 'at now + 5 minutes'}, True, 'at now + 5 minutes')
test_hook('Bash', {'command': 'batch'}, True, 'batch')
test_hook('Bash', {'command': 'crontab -e'}, True, 'crontab -e')
# crontab list/remove should be safe
test_hook('Bash', {'command': 'crontab -l'}, False, 'crontab -l (safe)')
test_hook('Bash', {'command': 'crontab -r'}, False, 'crontab -r (safe)')

# === 6i: expect interpreter ===
print("\n=== 6i: expect interpreter ===")
test_hook('Bash', {'command': 'expect -c "open \\"' + HOME + '/.env\\" r"'}, True, 'expect Tcl open .env')
test_hook('Bash', {'command': 'expect ' + S}, True, 'expect script .env')
test_hook('Bash', {'command': 'expect /tmp/safe_script.exp'}, False, 'expect safe script')

# === 6a: PostToolUse test_ exemption ===
print("\n=== 6a: PostToolUse test_ exemption tightening ===")
# Known test paths should still be exempt
test_warn_hook('Bash',
    {'command': 'python3 hooks/test_block_secrets.py'},
    'hvs.' + 'x' * 100,
    False,
    'test suite exempt')
test_warn_hook('Bash',
    {'command': 'python3 tests/test_report.py'},
    'hvs.' + 'x' * 100,
    False,
    'test suite path exempt')
# Arbitrary test_ script should NOT be exempt
test_warn_hook('Bash',
    {'command': 'python3 /tmp/test_exfil.py'},
    'hvs.' + 'x' * 100,
    True,
    'arbitrary test_ not exempt')
test_warn_hook('Bash',
    {'command': 'python3 my_test_script.py'},
    'hvs.' + 'x' * 100,
    True,
    'non-path test_ not exempt')

# === 6b: git output scanning ===
print("\n=== 6b: git output secret scanning ===")
# git diff output with a real token should warn
test_warn_hook('Bash',
    {'command': 'git diff HEAD'},
    '+API_KEY=hvs.' + 'a' * 100,
    True,
    'git diff leaks vault token')
test_warn_hook('Bash',
    {'command': 'git log -p'},
    'ghp_' + 'a' * 36,
    True,
    'git log leaks GitHub PAT')
test_warn_hook('Bash',
    {'command': 'git show HEAD'},
    '-----BEGIN RSA PRIVATE KEY-----',
    True,
    'git show leaks private key')
# git diff with normal output should pass clean
test_warn_hook('Bash',
    {'command': 'git diff HEAD'},
    '+def hello():\n-def world():',
    False,
    'git diff safe output')
test_warn_hook('Bash',
    {'command': 'git log --oneline'},
    'abc1234 fix: update readme',
    False,
    'git log safe output')
# grep output is now scanned (blanket exemption removed)
test_warn_hook('Bash',
    {'command': 'grep -r "pattern" .'},
    'hvs.' + 'a' * 100,
    True,
    'grep output with token scanned')


print("\n" + "=" * 60)
print(f"Results: {results['pass']} passed, {results['fail']} failed")
if results['fail'] == 0:
    print("ALL TESTS PASSED")
else:
    print(f"FAILURES: {results['fail']}")
    exit(1)
