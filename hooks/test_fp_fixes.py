#!/usr/bin/env python3
"""Test false positive fixes for block-secrets.py hook."""

import json
import subprocess
import sys
import os

HOOK = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'block-secrets.py')
HOME = os.path.expanduser('~')
S = HOME + '/.env'

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


print("=== FP-FIX 1: find -name should not trigger ===")
test_hook('Bash', {'command': 'find . -name ".git*"'}, False, 'find -name .git*')
test_hook('Bash', {'command': 'find . -name "*.env"'}, False, 'find -name *.env')
test_hook('Bash', {'command': 'find . -iname "*.pem"'}, False, 'find -iname *.pem')
test_hook('Bash', {'command': 'find . -path "*/.ssh/*"'}, False, 'find -path */.ssh/*')
test_hook('Bash', {'command': 'find . -ipath "*/.env*"'}, False, 'find -ipath */.env*')
test_hook('Bash', {'command': 'find . -regex ".*\\.env"'}, False, 'find -regex .env')
test_hook('Bash', {'command': 'find . -name "*.txt"'}, False, 'find -name *.txt (safe)')
test_hook('Bash', {'command': 'find . -wholename "*/.env*"'}, False, 'find -wholename')
test_hook('Bash', {'command': 'find /home -name ".vault-token" -type f'}, False, 'find -name .vault-token')

# Bare * basename should not trigger glob detection
test_hook('Bash', {'command': 'cat /tmp/*'}, False, 'cat /tmp/* (bare glob)')
test_hook('Bash', {'command': 'cat /tmp/**'}, False, 'cat /tmp/** (bare double glob)')

# But real sensitive globs should still be blocked
test_hook('Bash', {'command': 'cat ' + HOME + '/.e*'}, True, 'cat ~/.e* (sensitive glob)')
test_hook('Bash', {'command': 'cat ' + HOME + '/.en[v]'}, True, 'cat ~/.en[v] (sensitive glob)')

# find with actual sensitive file path (not -name) should still be blocked
test_hook('Bash', {'command': 'find ' + S + ' -type f'}, True, 'find .env as target (blocked)')

print("\n=== FP-FIX 2: Write/Edit markdown should not trigger ===")
test_hook('Write', {'file_path': '/tmp/readme.md', 'content': 'cat server.pem to check certificate details'}, False, 'md prose with cat .pem')
test_hook('Write', {'file_path': '/tmp/docs.md', 'content': 'Use source .env to load environment'}, False, 'md prose with source .env')
test_hook('Write', {'file_path': '/tmp/notes.txt', 'content': 'Run head ~/.vault-token to verify'}, False, 'txt with head .vault-token')
test_hook('Write', {'file_path': '/tmp/config.yml', 'content': 'cat .env to see current settings'}, False, 'yml with cat .env')
test_hook('Write', {'file_path': '/tmp/readme.rst', 'content': 'diff .env /dev/null'}, False, 'rst with diff .env')
test_hook('Write', {'file_path': '/tmp/guide.html', 'content': 'cat ~/.ssh/id_rsa for testing'}, False, 'html prose')
test_hook('Write', {'file_path': '/tmp/notes.json', 'content': 'source .env before running'}, False, 'json prose')

# But script files should still be scanned
test_hook('Write', {'file_path': '/tmp/deploy.sh', 'content': 'cat ' + S}, True, 'sh with cat .env (blocked)')
test_hook('Write', {'file_path': '/tmp/script.py', 'content': 'source ' + S}, True, 'py with source .env (blocked)')
test_hook('Write', {'file_path': '/tmp/run', 'content': 'cat ' + S}, True, 'no-ext with cat .env (blocked)')
test_hook('Write', {'file_path': '/tmp/helper.bash', 'content': 'head ' + S}, True, 'bash with head .env (blocked)')
test_hook('Write', {'file_path': '/tmp/init.zsh', 'content': 'cat ' + S}, True, 'zsh with cat .env (blocked)')
test_hook('Write', {'file_path': '/tmp/setup.rb', 'content': 'source ' + S}, True, 'rb with source .env (blocked)')

# Write/Edit to a sensitive path should always be blocked regardless
test_hook('Write', {'file_path': S, 'content': 'something harmless'}, True, 'Write to .env path (blocked)')

print(f"\n{'='*60}")
print(f"Results: {results['pass']} passed, {results['fail']} failed")
if results['fail'] > 0:
    print("SOME TESTS FAILED - review output above")
    sys.exit(1)
else:
    print("ALL TESTS PASSED")
