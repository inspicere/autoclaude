#!/usr/bin/env python3
"""Test round 2 bypass fixes."""

import json
import subprocess
import sys
import os

HOOK = '/home/terrabot/autoclaude/hooks/block-secrets.py'
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

print("=== R2-FIX 1: bash/sh/zsh heredoc ===")
test_hook('Bash', {'command': "bash << 'END'\ncat " + S + "\nEND"}, True, 'bash heredoc')
test_hook('Bash', {'command': "sh << 'END'\ncat " + S + "\nEND"}, True, 'sh heredoc')
test_hook('Bash', {'command': "zsh << 'END'\ncat " + S + "\nEND"}, True, 'zsh heredoc')
test_hook('Bash', {'command': "bash << 'END'\necho hello\nEND"}, False, 'bash heredoc safe')

print("\n=== R2-FIX 2: Backtick command substitution ===")
test_hook('Bash', {'command': 'echo `cat ' + S + '`'}, True, 'backtick cat .env')
test_hook('Bash', {'command': 'echo `head ' + S + '`'}, True, 'backtick head .env')
test_hook('Bash', {'command': 'echo `date`'}, False, 'backtick safe')

print("\n=== R2-FIX 3: stdbuf wrapper ===")
test_hook('Bash', {'command': 'stdbuf -oL cat ' + S}, True, 'stdbuf -oL cat .env')
test_hook('Bash', {'command': 'stdbuf -oL sort ' + S}, True, 'stdbuf -oL sort .env')
test_hook('Bash', {'command': 'stdbuf -oL cat /tmp/safe.txt'}, False, 'stdbuf safe')

print("\n=== R2-FIX 4: xargs -a / --arg-file ===")
test_hook('Bash', {'command': 'xargs -a ' + S + ' echo'}, True, 'xargs -a .env')
test_hook('Bash', {'command': 'xargs --arg-file=' + S + ' echo'}, True, 'xargs --arg-file=.env')
test_hook('Bash', {'command': 'xargs --arg-file ' + S + ' echo'}, True, 'xargs --arg-file .env')
test_hook('Bash', {'command': 'xargs -a /tmp/safe.txt echo'}, False, 'xargs -a safe')

print("\n=== R2-FIX 5: bash -c positional args ===")
test_hook('Bash', {'command': 'bash -c \'cat "$1"\' _ ' + S}, True, 'bash -c $1 positional .env')
test_hook('Bash', {'command': 'sh -c \'cat "$1"\' _ ' + S}, True, 'sh -c $1 positional .env')
test_hook('Bash', {'command': 'bash -c \'echo "$1"\' _ hello'}, False, 'bash -c positional safe')

print("\n=== R2-FIX 6: Long-form interpreter flags ===")
test_hook('Bash', {'command': 'node --eval \'require("fs").readFileSync("' + S + '")\''}, True, 'node --eval')
test_hook('Bash', {'command': 'node --eval \'console.log("hi")\''}, False, 'node --eval safe')

print("\n=== R2-FIX 7: SSH remote command ===")
test_hook('Bash', {'command': 'ssh localhost cat ' + S}, True, 'ssh cat .env')
test_hook('Bash', {'command': 'ssh -p 22 user@host cat ' + S}, True, 'ssh -p cat .env')
test_hook('Bash', {'command': 'ssh localhost ls /tmp'}, False, 'ssh safe command')

print("\n=== R2-FIX 8: Parenthesized subshell (doc agent fix) ===")
test_hook('Bash', {'command': '(cat ' + S + ')'}, True, '(cat .env)')
test_hook('Bash', {'command': '(cat ' + S + ') &'}, True, '(cat .env) &')
test_hook('Bash', {'command': '(echo hello)'}, False, '(echo hello) safe')

print("\n=== R2-FIX 9: Curly-brace group (doc agent fix) ===")
test_hook('Bash', {'command': '{ cat ' + S + '; }'}, True, '{ cat .env; }')
test_hook('Bash', {'command': '{ echo hello; }'}, False, '{ echo hello; } safe')

print("\n=== R2-FIX 10: Variable indirection (doc agent fix) ===")
test_hook('Bash', {'command': 'F=' + S + ' && cat "$F"'}, True, 'F=.env && cat $F')
test_hook('Bash', {'command': 'export F=' + S + ' && cat $F'}, True, 'export F=.env && cat $F')
test_hook('Bash', {'command': 'F=/tmp/safe.txt && cat "$F"'}, False, 'F=safe && cat $F')

print("\n=== R2-FIX 11: echo/printf | bash (doc agent fix) ===")
test_hook('Bash', {'command': "echo 'cat " + S + "' | bash"}, True, 'echo cat .env | bash')
test_hook('Bash', {'command': "printf 'cat " + S + "' | sh"}, True, 'printf cat .env | sh')
test_hook('Bash', {'command': "echo 'echo hi' | bash"}, False, 'echo safe | bash')

print("\n=== R2-FIX 12: Additional file readers (doc agent fix) ===")
for tool in ['shuf', 'unexpand', 'look', 'tsort', 'ptx', 'base32', 'zcat']:
    test_hook('Bash', {'command': tool + ' ' + S}, True, tool + ' .env')

print("\n=== R2-FIX 13: --from-file= long flags (doc agent fix) ===")
test_hook('Bash', {'command': 'diff --from-file=' + S + ' /dev/null'}, True, 'diff --from-file=.env')
test_hook('Bash', {'command': 'sort --files0-from=' + S}, True, 'sort --files0-from=.env')

print("\n=== R2-FIX 14: openssl -in (doc agent fix) ===")
test_hook('Bash', {'command': 'openssl enc -d -base64 -in ' + S}, True, 'openssl -in .env')

print("\n=== NON-SENSITIVE: Normal ops still work ===")
test_hook('Bash', {'command': 'cat /tmp/normal.txt'}, False, 'cat normal')
test_hook('Bash', {'command': 'bash -c "echo hello"'}, False, 'bash -c safe')
test_hook('Bash', {'command': 'stdbuf -oL ls /tmp'}, False, 'stdbuf ls safe')
test_hook('Bash', {'command': 'ssh localhost uptime'}, False, 'ssh uptime safe')
test_hook('Bash', {'command': 'xargs echo < /tmp/list.txt'}, False, 'xargs safe')
test_hook('Bash', {'command': 'git status'}, False, 'git status')
test_hook('Bash', {'command': 'python3 -c "print(42)"'}, False, 'python3 safe')

print(f"\n{'='*60}")
print(f"Results: {results['pass']} passed, {results['fail']} failed")
if results['fail'] > 0:
    print("SOME TESTS FAILED - review output above")
    sys.exit(1)
else:
    print("ALL TESTS PASSED")
