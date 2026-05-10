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
    results.append(test_hook('Bash', {'command': 'grep token file'}, fake_token, True))

    print('\n=== PostToolUse: Read/Edit output scanning (NEW) ===')
    results.append(test_hook('Read', {'file_path': '/tmp/config.txt'}, fake_token, True))
    results.append(test_hook('Read', {'file_path': '/tmp/safe.txt'}, 'normal content', False))
    results.append(test_hook('Edit', {'file_path': '/tmp/config.txt'}, fake_token, True))
    results.append(test_hook('Read', {'file_path': 'block-secrets.py'}, fake_token, False))

    print('\n=== PostToolUse: Ignored tools ===')
    results.append(test_hook('Write', {'file_path': '/tmp/x'}, fake_token, False))

    # === PostToolUse: Correlation with PreToolUse warns ===
    print('\n=== PostToolUse: Correlation with PreToolUse warns ===')

    audit_log = os.path.expanduser('~/.claude/hook-audit.jsonl')
    os.makedirs(os.path.dirname(audit_log), exist_ok=True)

    import time
    ts_now = time.strftime("%Y-%m-%dT%H:%M:%S%z")

    # Write a fake warn audit entry
    warn_record = json.dumps({
        "ts": ts_now, "decision": "warn", "tool": "Bash",
        "reason": "FORGEJO_TOKEN will be set from a secret source at runtime",
        "command": "FORGEJO_TOKEN=$(vault kv get -field=api_token secret/forgejo) && curl http://x"
    })

    # Save existing audit log
    orig_content = None
    try:
        with open(audit_log, 'r') as f:
            orig_content = f.read()
    except FileNotFoundError:
        pass

    # Write test entry
    with open(audit_log, 'a') as f:
        f.write(warn_record + "\n")

    # Test: output with high-entropy string should trigger correlation
    high_entropy_output = "result: aB3xK9mZ2pQ7wR4vY1nL8cF5hD6jE0sT"
    data = json.dumps({
        'tool_name': 'Bash',
        'tool_input': {'command': 'curl http://example.com'},
        'tool_result': high_entropy_output,
    })
    r = subprocess.run(
        ['python3', HOOK], input=data, capture_output=True, text=True,
        timeout=10, env=dict(os.environ, HOOK_CORRELATE='1')
    )
    warned = bool(r.stdout.strip())
    ok = warned
    results.append(ok)
    print(f"{'PASS' if ok else 'FAIL'} [WARN] Correlation: high-entropy output after warn")
    if not ok:
        print(f"       stdout={r.stdout.strip()[:100]}")

    # Test: output without high-entropy string should not trigger
    data = json.dumps({
        'tool_name': 'Bash',
        'tool_input': {'command': 'curl http://example.com'},
        'tool_result': 'HTTP 200 OK\n{"status": "success"}',
    })
    r = subprocess.run(
        ['python3', HOOK], input=data, capture_output=True, text=True,
        timeout=10, env=dict(os.environ, HOOK_CORRELATE='1')
    )
    warned = bool(r.stdout.strip())
    ok = not warned
    results.append(ok)
    print(f"{'PASS' if ok else 'FAIL'} [ALLOW] Correlation: low-entropy output after warn")

    # Test: HOOK_CORRELATE=0 disables correlation
    data = json.dumps({
        'tool_name': 'Bash',
        'tool_input': {'command': 'curl http://example.com'},
        'tool_result': high_entropy_output,
    })
    r = subprocess.run(
        ['python3', HOOK], input=data, capture_output=True, text=True,
        timeout=10, env=dict(os.environ, HOOK_CORRELATE='0')
    )
    warned = bool(r.stdout.strip())
    ok = not warned
    results.append(ok)
    print(f"{'PASS' if ok else 'FAIL'} [ALLOW] Correlation disabled with HOOK_CORRELATE=0")

    # Restore original audit log
    if orig_content is not None:
        with open(audit_log, 'w') as f:
            f.write(orig_content)
    else:
        try:
            os.unlink(audit_log)
        except FileNotFoundError:
            pass

    print()
    passed = sum(results)
    total = len(results)
    print(f'Results: {passed}/{total} passed')
    sys.exit(0 if passed == total else 1)


if __name__ == '__main__':
    main()
