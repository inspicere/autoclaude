#!/usr/bin/env python3
"""Test round 3 bypass fixes — 10 confirmed bypasses from 2026-05-10 red team."""

import json
import subprocess
import os

HOOK = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'block-secrets.py')
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


# === C1: git diff --no-index ===
print("=== C1: git diff --no-index reads sensitive files ===")
test_hook('Bash', {'command': 'git diff --no-index /dev/null ' + S}, True, 'git diff --no-index .env')
test_hook('Bash', {'command': 'git diff --no-index /dev/null ' + T}, True, 'git diff --no-index target .env')
test_hook('Bash', {'command': 'git diff --no-index /tmp/a.txt /tmp/b.txt'}, False, 'git diff --no-index safe files')
test_hook('Bash', {'command': 'git diff HEAD~1'}, False, 'git diff normal ref')
test_hook('Bash', {'command': 'git diff --stat'}, False, 'git diff --stat')

print("\n=== C1b: git hash-object ===")
test_hook('Bash', {'command': 'git hash-object ' + S}, True, 'git hash-object .env')
test_hook('Bash', {'command': 'git hash-object -w ' + T}, True, 'git hash-object -w target .env')
test_hook('Bash', {'command': 'git hash-object README.md'}, False, 'git hash-object safe')

print("\n=== C1c: git add ===")
test_hook('Bash', {'command': 'git add ' + S}, True, 'git add .env')
test_hook('Bash', {'command': 'git add README.md'}, False, 'git add safe file')

print("\n=== C1d: git archive ===")
test_hook('Bash', {'command': 'git archive HEAD -- ' + S}, True, 'git archive .env')
test_hook('Bash', {'command': 'git archive HEAD'}, False, 'git archive safe')

# Normal git operations should NOT be blocked
print("\n=== C1e: git safe operations ===")
test_hook('Bash', {'command': 'git status'}, False, 'git status')
test_hook('Bash', {'command': 'git log --oneline'}, False, 'git log')
test_hook('Bash', {'command': 'git show HEAD'}, False, 'git show ref')
test_hook('Bash', {'command': 'git commit -m "message"'}, False, 'git commit')
test_hook('Bash', {'command': 'git push origin main'}, False, 'git push')
test_hook('Bash', {'command': 'git branch -a'}, False, 'git branch')
test_hook('Bash', {'command': 'git stash'}, False, 'git stash')
test_hook('Bash', {'command': 'git diff HEAD~1 -- src/'}, False, 'git diff with safe path')
test_hook('Bash', {'command': 'git checkout main'}, False, 'git checkout')


# === C2: BASH_ENV auto-source ===
print("\n=== C2: BASH_ENV auto-source ===")
test_hook('Bash', {'command': 'BASH_ENV=' + S + " bash -c 'echo $SECRET'"}, True, 'BASH_ENV=.env')
test_hook('Bash', {'command': 'BASH_ENV=' + T + " bash -c 'env'"}, True, 'BASH_ENV=target .env')
test_hook('Bash', {'command': 'ENV=' + S + " sh -c 'echo hi'"}, True, 'ENV=.env')
test_hook('Bash', {'command': 'PYTHONSTARTUP=' + S + " python3 -c 'pass'"}, True, 'PYTHONSTARTUP=.env')
test_hook('Bash', {'command': 'NODE_OPTIONS=' + S + " node -e 'x'"}, True, 'NODE_OPTIONS=.env')
test_hook('Bash', {'command': 'LD_PRELOAD=' + S + " cat /etc/hostname"}, True, 'LD_PRELOAD=.env')
test_hook('Bash', {'command': 'PERL5OPT=' + S + " perl -e 1"}, True, 'PERL5OPT=.env')
test_hook('Bash', {'command': 'ZDOTDIR=' + HOME + '/.vault-token' + " zsh -c 'echo'"}, True, 'ZDOTDIR=vault-token')

# Safe env vars should NOT be blocked
test_hook('Bash', {'command': 'MYVAR=hello bash -c "echo $MYVAR"'}, False, 'safe env var')
test_hook('Bash', {'command': 'PATH=/usr/bin:/bin ls'}, False, 'PATH override')
test_hook('Bash', {'command': 'BASH_ENV=/tmp/safe.sh bash -c "echo hi"'}, False, 'BASH_ENV=safe file')
test_hook('Bash', {'command': 'LANG=en_US.UTF-8 python3 script.py'}, False, 'LANG override')


# === C3: env --split-string ===
print("\n=== C3: env --split-string ===")
test_hook('Bash', {'command': "env --split-string='cat " + S + "'"}, True, 'env --split-string=cat .env')
test_hook('Bash', {'command': "env --split-string='head " + T + "'"}, True, 'env --split-string=head target')
test_hook('Bash', {'command': "env -S'cat " + S + "'"}, True, 'env -Scat .env')
test_hook('Bash', {'command': 'env -S "cat ' + S + '"'}, True, 'env -S "cat .env"')
test_hook('Bash', {'command': "env --split-string='echo hello'"}, False, 'env --split-string safe')
test_hook('Bash', {'command': 'env -S "ls -la"'}, False, 'env -S safe')


# === H1: setsid ===
print("\n=== H1: setsid wrapper ===")
test_hook('Bash', {'command': 'setsid cat ' + S}, True, 'setsid cat .env')
test_hook('Bash', {'command': 'setsid head ' + T}, True, 'setsid head target .env')
test_hook('Bash', {'command': 'setsid --fork cat ' + S}, True, 'setsid --fork cat .env')
test_hook('Bash', {'command': 'setsid cat /tmp/safe.txt'}, False, 'setsid safe')


# === H2: flock ===
print("\n=== H2: flock wrapper ===")
test_hook('Bash', {'command': 'flock /tmp/x cat ' + S}, True, 'flock cat .env')
test_hook('Bash', {'command': 'flock /tmp/x head ' + T}, True, 'flock head target .env')
test_hook('Bash', {'command': 'flock -n /tmp/x cat ' + S}, True, 'flock -n cat .env')
test_hook('Bash', {'command': 'flock --timeout 5 /tmp/x cat ' + S}, True, 'flock --timeout 5 cat .env')
test_hook('Bash', {'command': 'flock -w 10 /tmp/x cat ' + S}, True, 'flock -w 10 cat .env')
test_hook('Bash', {'command': 'flock /tmp/x cat /tmp/safe.txt'}, False, 'flock safe')
test_hook('Bash', {'command': 'flock /tmp/x ls -la'}, False, 'flock ls')


# === H3: unshare ===
print("\n=== H3: unshare wrapper ===")
test_hook('Bash', {'command': 'unshare --map-root-user cat ' + S}, True, 'unshare cat .env')
test_hook('Bash', {'command': 'unshare -r cat ' + T}, True, 'unshare -r cat target .env')
test_hook('Bash', {'command': 'unshare --mount head ' + S}, True, 'unshare --mount head .env')
test_hook('Bash', {'command': 'unshare cat /tmp/safe.txt'}, False, 'unshare safe')


# === H4: find -exec ===
print("\n=== H4: find -exec sub-command parsing ===")
test_hook('Bash', {'command': r'find /tmp -name ".env" -exec cat {} \;'}, True, 'find -exec cat')
test_hook('Bash', {'command': r'find /tmp -name ".env" -exec head {} \;'}, True, 'find -exec head')
test_hook('Bash', {'command': r'find /tmp -name ".env" -execdir cat {} \;'}, True, 'find -execdir cat')
test_hook('Bash', {'command': 'find /tmp -name ".env" -exec cat {} +'}, True, 'find -exec cat +')
test_hook('Bash', {'command': r'find /tmp -name "*.txt" -exec ls {} \;'}, False, 'find -exec ls (safe)')
test_hook('Bash', {'command': 'find /tmp -name "*.log" -exec wc -l {} +'}, False, 'find -exec wc (safe)')
test_hook('Bash', {'command': 'find /tmp -type f -name "*.py"'}, False, 'find without -exec')
# find with sensitive path as search directory (dirs aren't file reads, so allowed)
test_hook('Bash', {'command': 'find ' + HOME + '/.ssh -type f'}, False, 'find in dir (not a file read)')


# === H5: coproc ===
print("\n=== H5: coproc keyword ===")
test_hook('Bash', {'command': 'coproc cat ' + S}, True, 'coproc cat .env')
test_hook('Bash', {'command': 'coproc head ' + T}, True, 'coproc head target .env')
test_hook('Bash', {'command': 'coproc cat /tmp/safe.txt'}, False, 'coproc safe')


# === H6: xargs sh/bash indirection ===
print("\n=== H6: xargs pipes to shell ===")
test_hook('Bash', {'command': "echo x | xargs -I{} sh -c 'cat " + S + "'"}, True, 'xargs sh -c')
test_hook('Bash', {'command': "echo x | xargs -I{} bash -c 'cat " + S + "'"}, True, 'xargs bash -c')
test_hook('Bash', {'command': "echo x | xargs sh"}, True, 'xargs sh (bare)')
test_hook('Bash', {'command': "echo x | xargs bash"}, True, 'xargs bash (bare)')
test_hook('Bash', {'command': "echo x | xargs zsh"}, True, 'xargs zsh (bare)')
test_hook('Bash', {'command': "echo x | xargs echo"}, False, 'xargs echo (safe)')
test_hook('Bash', {'command': "echo x | xargs ls"}, False, 'xargs ls (safe)')


# === H7: for-loop variable tracking ===
print("\n=== H7: for-loop variable tracking ===")
test_hook('Bash', {'command': 'for f in ' + S + '; do cat "$f"; done'}, True, 'for loop cat .env')
test_hook('Bash', {'command': 'for f in ' + T + '; do head "$f"; done'}, True, 'for loop head target')
test_hook('Bash', {'command': 'for f in /tmp/a.txt /tmp/b.txt; do cat "$f"; done'}, False, 'for loop safe files')
test_hook('Bash', {'command': 'for i in 1 2 3; do echo $i; done'}, False, 'for loop numbers')


# === Combination tests ===
print("\n=== Combination: wrappers + sensitive paths ===")
test_hook('Bash', {'command': 'sudo setsid cat ' + S}, True, 'sudo setsid cat .env')
test_hook('Bash', {'command': 'nohup flock /tmp/x cat ' + S}, True, 'nohup flock cat .env')
test_hook('Bash', {'command': 'timeout 5 unshare cat ' + S}, True, 'timeout unshare cat .env')

print("\n=== Combination: env -S with wrappers ===")
test_hook('Bash', {'command': "env --split-string='sort " + S + "'"}, True, 'env -S sort .env')
test_hook('Bash', {'command': "env -S 'diff " + S + " /tmp/x'"}, True, 'env -S diff .env')

print("\n=== Combination: git with wrappers ===")
test_hook('Bash', {'command': 'sudo git diff --no-index /dev/null ' + S}, True, 'sudo git diff --no-index .env')


print("\n" + "=" * 60)
print(f"Results: {results['pass']} passed, {results['fail']} failed")
if results['fail'] == 0:
    print("ALL TESTS PASSED")
else:
    print(f"FAILURES: {results['fail']}")
    exit(1)
