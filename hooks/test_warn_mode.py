#!/usr/bin/env python3
"""Test the new warn mode and hardened inline secret detection."""
import subprocess
import json
import os

HOOK = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'block-secrets.py')

tests = [
    # (description, command, expected_decision)
    # Runtime expansion warnings (previously silent allow, now ask)
    ("grep subshell in curl auth header",
     'curl -s -H "Authorization: Token $(grep API_KEY /tmp/test | cut -d= -f2)" http://example.com',
     "ask"),
    ("VAULT_TOKEN set from subshell",
     'VAULT_TOKEN=$(cat /opt/vault/data/root-token) vault policy write test -',
     "ask"),
    ("SECRET_TOKEN from vault kv get",
     'DD_TOKEN=$(vault kv get -field=admin_api_token secret/defectdojo) && curl http://example.com',
     "ask"),
    ("CF_TOKEN from vault with curl auth",
     'CF_TOKEN=$(vault kv get -field=cf_api_token secret/caddy) && curl -s -H "Authorization: Bearer $CF_TOKEN" https://api.cloudflare.com',
     "ask"),
    ("curl -u with $VAR password",
     'curl -u admin:$DB_PASSWORD http://example.com/api',
     "ask"),
    ("FORGEJO_TOKEN from ssh vault",
     'FORGEJO_TOKEN=$(ssh vault-01 vault kv get -field=api_token secret/forgejo) && curl http://git.local:3000/api -H "Authorization: token $FORGEJO_TOKEN"',
     "ask"),
    ("--password with $VAR",
     'mysql --password=$DB_PASS -u admin mydb',
     "ask"),

    # Hard blocks (literal secrets in command text)
    ("literal secret in API_KEY var",
     'FAKE_API_KEY=abc123def456ghi789 uv run python',
     "block"),
    ("curl --user with literal password",
     'curl --user admin:supersecret123 http://example.com/api',
     "block"),
    ("--password=literal",
     'mysql --password=supersecret123 -u admin mydb',
     "block"),
    ("--pass=literal",
     '--pass=mysupersecretvalue',
     "block"),
    ("testsaslauthd -p literal in ssh",
     "ssh 192.168.86.137 'sudo testsaslauthd -u health -p secretpass123 -s smtp'",
     "block"),

    # Safe commands (should pass through, no block or warn)
    ("git status",
     'git status',
     "allow"),
    ("ssh -p 22 (port, not password)",
     'ssh -p 22 user@host ls',
     "allow"),
    ("vault kv get alone",
     'vault kv get -field=password secret/db',
     "allow"),
    ("grep for token pattern",
     'grep API_KEY /tmp/config.yml',
     "allow"),
    ("ansible-playbook",
     'ansible-playbook playbooks/deploy.yml',
     "allow"),
    ("rsync files",
     'rsync -av src/ dest/',
     "allow"),
    ("curl without auth",
     'curl -s http://example.com',
     "allow"),
    ("python3 simple script",
     'python3 -c "print(1+1)"',
     "allow"),
    ("mkdir -p",
     'mkdir -p /tmp/testdir',
     "allow"),
    ("tar with -p (preserve, not password)",
     'tar -xpf archive.tar.gz',
     "allow"),
    ("git commit msg with auth example text (not a real secret)",
     'git commit -m "fix: handle Authorization: Token $TOKEN pattern"',
     "allow"),
    ("git commit msg with literal secret still blocks",
     'git commit -m "oops ghp_abcdefghijklmnopqrstuvwxyz1234567890"',
     "block"),
]

passed = 0
failed = 0
for desc, cmd, expected in tests:
    inp = json.dumps({"tool_name": "Bash", "tool_input": {"command": cmd}})
    result = subprocess.run(
        ["python3", HOOK],
        input=inp, capture_output=True, text=True
    )
    if result.returncode == 2:
        actual = "block"
    elif result.stdout.strip():
        try:
            data = json.loads(result.stdout)
            actual = data["hookSpecificOutput"]["permissionDecision"]
        except (json.JSONDecodeError, KeyError):
            actual = "unknown"
    else:
        actual = "allow"

    status = "PASS" if actual == expected else "FAIL"
    if status == "PASS":
        passed += 1
    else:
        failed += 1
        print(f"  {status}: {desc}")
        print(f"         expected={expected}, got={actual}")
        if result.stderr:
            print(f"         stderr: {result.stderr.strip()[:120]}")
        continue
    print(f"  {status}: {desc}")

# --- Confidence grading tests ---
# These check that warn messages contain confidence-appropriate text
confidence_tests = [
    ("echo $TOKEN is high confidence",
     'SECRET_TOKEN=$(vault kv get secret/x) && echo $SECRET_TOKEN',
     "likely to expose"),
    ("curl -H auth is low confidence",
     'curl -s -H "Authorization: Token $(grep API_KEY /tmp/test | cut -d= -f2)" http://example.com',
     "may expose"),
    ("curl -u is low confidence",
     'curl -u admin:$DB_PASSWORD http://example.com/api',
     "may expose"),
    ("--password is low confidence",
     'mysql --password=$DB_PASS -u admin mydb',
     "may expose"),
    ("printf $TOKEN is high confidence",
     'API_KEY=$(vault kv get secret/x) && printf "%s" $API_KEY',
     "likely to expose"),
    ("output to /dev/null is low confidence",
     'SECRET_TOKEN=$(vault kv get secret/x) && curl -o /dev/null -H "Auth: $SECRET_TOKEN" http://x',
     "may expose"),
]

for desc, cmd, expected_phrase in confidence_tests:
    inp = json.dumps({"tool_name": "Bash", "tool_input": {"command": cmd}})
    result = subprocess.run(
        ["python3", HOOK],
        input=inp, capture_output=True, text=True
    )
    try:
        data = json.loads(result.stdout)
        reason = data["hookSpecificOutput"]["permissionDecisionReason"]
        ok = expected_phrase in reason
    except (json.JSONDecodeError, KeyError):
        ok = False
        reason = ""

    status = "PASS" if ok else "FAIL"
    if ok:
        passed += 1
    else:
        failed += 1
        print(f"  {status}: {desc}")
        print(f"         expected phrase '{expected_phrase}' in reason")
        if reason:
            print(f"         got: {reason[:120]}")
        continue
    print(f"  {status}: {desc}")

print(f"\nResults: {passed}/{passed + failed} passed")
if failed:
    print(f"FAILURES: {failed}")
else:
    print("ALL TESTS PASSED")
