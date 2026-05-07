#!/usr/bin/env python3
"""Test suite for warn-secrets-output.py PostToolUse hook."""

import json
import os
import subprocess
import sys

HOOK = os.path.join(os.path.dirname(__file__), 'warn-secrets-output.py')


def test_hook(tool_name, tool_input, tool_result, expect_warn):
    data = json.dumps({
        'tool_name': tool_name,
        'tool_input': tool_input,
        'tool_result': tool_result,
    })
    r = subprocess.run(
        ['python3', HOOK],
        input=data, capture_output=True, text=True, timeout=10
    )
    warned = bool(r.stdout.strip())
    status = 'PASS' if warned == expect_warn else 'FAIL'
    label = 'WARN' if expect_warn else 'ALLOW'
    desc = tool_input.get('command', tool_input.get('file_path', ''))[:60]
    print(f'{status} [{label}] {tool_name}: {desc}')
    if status == 'FAIL':
        print(f'       stdout={r.stdout.strip()[:100]}')
    return status == 'PASS'


def main():
    results = []
    fake_token = 'ghp_' + 'a' * 36

    print('=== PostToolUse: Bash output scanning ===')
    results.append(test_hook('Bash', {'command': 'vault kv get secret/x'}, fake_token, True))
    results.append(test_hook('Bash', {'command': 'echo hello'}, 'hello world', False))

    print('\n=== PostToolUse: Narrowed exemptions ===')
    results.append(test_hook('Bash', {'command': 'cat secrets.json'}, fake_token, True))
    results.append(test_hook('Bash', {'command': 'cat config.py'}, fake_token, True))
    results.append(test_hook('Bash', {'command': 'cat block-secrets.py'}, fake_token, False))
    results.append(test_hook('Bash', {'command': 'cat claude-approval-report.py'}, fake_token, False))
    results.append(test_hook('Bash', {'command': 'grep token file'}, fake_token, False))

    print('\n=== PostToolUse: Read/Edit output scanning (NEW) ===')
    results.append(test_hook('Read', {'file_path': '/tmp/config.txt'}, fake_token, True))
    results.append(test_hook('Read', {'file_path': '/tmp/safe.txt'}, 'normal content', False))
    results.append(test_hook('Edit', {'file_path': '/tmp/config.txt'}, fake_token, True))
    results.append(test_hook('Read', {'file_path': 'block-secrets.py'}, fake_token, False))

    print('\n=== PostToolUse: Ignored tools ===')
    results.append(test_hook('Write', {'file_path': '/tmp/x'}, fake_token, False))

    print()
    passed = sum(results)
    total = len(results)
    print(f'Results: {passed}/{total} passed')
    sys.exit(0 if passed == total else 1)


if __name__ == '__main__':
    main()
