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

print("\n=== FP-FIX 3: jq accessors and templates (DefectDojo #3404, #3405) ===")
# DefectDojo #3404 — .key as a jq accessor inside a single-quoted filter must not
# look like a read of a `.key` file.
test_hook('Bash', {'command': "jq -r '.mcpServers.silverbullet | to_entries | map(.key + \": \" + (.value | type)) | .[]' ~/.mcp.json"}, False, 'jq map(.key) filter')
test_hook('Bash', {'command': "jq -r '.data.data | to_entries[] | .key + \": \" + (.value | type)'"}, False, 'jq to_entries[] | .key')
test_hook('Bash', {'command': "jq -r 'keys_unsorted[]'"}, False, 'jq keys_unsorted[]')
# DefectDojo #3405 — `<ident>=<template>` inside a single-quoted jq/awk/printf
# format string must not look like an inline secret assignment.
test_hook('Bash', {'command': "jq -r '.x[] | \"name=\\(.name)  enable_api_key_auth=\\(.enable_api_key_auth)  use_query_param_auth=\\(.use_query_param_auth)\"'"}, False, 'jq template w/ _auth= ident')
test_hook('Bash', {'command': "awk 'BEGIN{print \"name\\tapikey_auth\\tqparam_auth\"}{print}'"}, False, 'awk header w/ _auth ident')
test_hook('Bash', {'command': "echo 'enable_api_key_auth=true'"}, False, 'echo literal _auth=true demo string')
test_hook('Bash', {'command': "printf 'token=demo  auth_required=true\\n'"}, False, 'printf format w/ token=/auth_ idents')

# Positive controls — real exposure must still block.
test_hook('Bash', {'command': 'API_KEY=abcdefghijk1234567 curl http://x'}, True, 'real unquoted API_KEY= assignment (still blocks)')
test_hook('Bash', {'command': 'TOKEN=abcdefghijk1234567 curl http://x'}, True, 'real unquoted TOKEN= assignment (still blocks)')
test_hook('Bash', {'command': 'cat /etc/ssl/private/server.key'}, True, 'real /etc/.../server.key read (still blocks)')
test_hook('Bash', {'command': 'cat ./mycert.key'}, True, 'real ./mycert.key read (still blocks)')
test_hook('Bash', {'command': 'cat ~/.ssh/foo.pem'}, True, 'real ~/.ssh/foo.pem read (still blocks)')

print("\n=== FP-FIX 4: high-entropy benign tokens (Vikunja #758 — entropy over-reach) ===")
# The base64 entropy gate must not flag pure-alphabetic source identifiers
# (camelCase/PascalCase) or pure-hex git/sha digests. Strings are assembled at
# runtime so this test file holds no literal high-entropy blob.
import hashlib as _hl
_ident = "Android" + "Db" + "Passphrase" + "Provider" + "Factory"      # 34 chars, pure alpha
_sha256 = _hl.sha256(b"autoclaude").hexdigest()                        # 64 hex
_commit = _sha256[:40]                                                 # 40 hex
_realb64 = "aB3dE5fG7hJ9" + "kL1mN2pQ4rS6" + "tU8vW0xYzA12" + "cd34qZ"  # base64-shaped, has digits

# Bug A residual — >=32-char PascalCase identifier in a non-exempt command must NOT block
test_hook('Bash', {'command': f'echo {_ident}'}, False, 'echo >=32 PascalCase identifier (no block)')
test_hook('Bash', {'command': f'echo {_ident}Repository'}, False, 'echo longer PascalCase identifier (no block)')
# Bug B — git/sha hex digests must NOT block
test_hook('Bash', {'command': f'git checkout {_commit}'}, False, 'git checkout 40-hex commit (no block)')
test_hook('Bash', {'command': f'git show {_sha256}'}, False, 'git show 64-hex sha256 (no block)')
test_hook('Bash', {'command': f'echo {_sha256} >> notes.txt'}, False, 'echo 64-hex sha256 (no block)')
# Positive controls — a real high-entropy base64 blob (mixed alnum) must STILL block
test_hook('Bash', {'command': f'echo {_realb64}'}, True, 'bare base64-shaped blob w/ digits still blocks (entropy path)')
test_hook('Bash', {'command': f'export API_KEY={_realb64}'}, True, 'real API_KEY= assignment still blocks')

print("\n=== FP-FIX 5: deep relative paths must not trip the entropy gate (issue #5) ===")
# A deep relative path confined to [A-Za-z0-9/] (no '.' or '-') crosses the base64
# entropy threshold and was mistaken for a secret blob. Each path segment is a
# benign filename token, so the whole path must be exempt. Assemble at runtime so
# this file holds no literal high-entropy run.
_path1 = "ansible/" + "roles/" + "prometheus/" + "templates/"            # trailing slash
_path2 = "src/main/" + "java/com/" + "example/" + "service/AuthnController"
test_hook('Bash', {'command': f'git diff -- {_path1} > /tmp/out.patch'}, False, 'git diff -- deep relative path (no block)')
test_hook('Bash', {'command': f'ls {_path2}'}, False, 'ls deep relative path (no block)')
test_hook('Bash', {'command': f'find {_path1} -type f'}, False, 'find deep relative path (no block)')
# Positive controls — real base64 secrets must STILL block, even with a '/'.
_blob_noslash = "aB3dE5fG7hJ9" + "kL1mN2pQ4rS6" + "tU8vW0xYzA12" + "cd34qZ"  # >=32, digits
_blob_slash = "aB3dE5fG7hJ9kL1mN2pQ" + "/" + "rS6tU8vW0xYzA12cd34qZwE"        # blob w/ slash
test_hook('Bash', {'command': f'echo {_blob_noslash}'}, True, 'bare base64 blob (no slash) still blocks')
test_hook('Bash', {'command': f'echo {_blob_slash}'}, True, 'base64 blob containing slash still blocks')

print(f"\n{'='*60}")
print(f"Results: {results['pass']} passed, {results['fail']} failed")
if results['fail'] > 0:
    print("SOME TESTS FAILED - review output above")
    sys.exit(1)
else:
    print("ALL TESTS PASSED")
