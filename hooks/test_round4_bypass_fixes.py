#!/usr/bin/env python3
"""Round 4 bypass tests — H1 and H2 from 2026-05-16 project audit.

H1: docker run --mount type=bind,source=... was not detected.
H2: tar/zip --files-from=, --file=, -T, and bunched short flags like -cT
    were skipped because the handler treated all -prefixed args as no-ops.
"""

import json
import os
import subprocess
import sys

HOOK = os.path.join(os.path.dirname(__file__), 'block-secrets.py')
HOME = os.path.expanduser('~')


results = []


def check(condition, label):
    status = 'PASS' if condition else 'FAIL'
    results.append(condition)
    print(f'  {status}: {label}')


def run_hook(tool_name, tool_input):
    data = json.dumps({'tool_name': tool_name, 'tool_input': tool_input})
    r = subprocess.run(
        ['python3', HOOK],
        input=data, capture_output=True, text=True, timeout=10,
    )
    return r.returncode, r.stderr


def bash(cmd, expect_block, label=None):
    label = label or cmd[:60]
    code, stderr = run_hook('Bash', {'command': cmd})
    blocked = code == 2
    status = 'PASS' if blocked == expect_block else 'FAIL'
    results.append(blocked == expect_block)
    arrow = 'BLOCK' if expect_block else 'ALLOW'
    actual = 'blocked' if blocked else 'allowed'
    print(f'  {status} [{arrow}] {label}')
    if status == 'FAIL':
        print(f'         expected {arrow}, was {actual}. stderr={stderr.strip()[:150]}')


env = f'{HOME}/.env'
vault = f'{HOME}/.vault-token'
sshkey = f'{HOME}/.ssh/id_rsa'
sshdir = f'{HOME}/.ssh'


# =============================================================================
# H1 — docker run --mount type=bind,source=...
# =============================================================================
print('=== H1: docker run --mount bypass ===')

# --mount as next-arg form
bash(f'docker run --mount type=bind,source={sshkey},target=/mnt alpine cat /mnt',
     True, '--mount next-arg, source=sshkey')
bash(f'docker run --mount type=bind,source={env},target=/mnt alpine cat /mnt',
     True, '--mount next-arg, source=env')
bash(f'docker run --mount type=bind,source={sshdir},target=/mnt alpine ls /mnt',
     True, '--mount next-arg, source=sshdir')

# --mount with src= alias
bash(f'docker run --mount type=bind,src={vault},target=/mnt alpine cat /mnt',
     True, '--mount with src= alias')

# --mount=key=val (=-glued single arg)
bash(f'docker run --mount=type=bind,source={env},target=/mnt alpine cat /mnt',
     True, '--mount=type=bind,source=env (=-glued)')

# Different KV order — source first
bash(f'docker run --mount source={env},type=bind,target=/mnt alpine cat /mnt',
     True, '--mount source first then type')

# Allow benign mounts
bash('docker run --mount type=bind,source=/tmp/safe,target=/mnt alpine ls',
     False, '--mount of /tmp/safe is allowed')
bash('docker run --mount=type=volume,source=myvol,target=/data alpine ls',
     False, '--mount of named volume (not a host path)')

# Existing -v / --volume still works (regression for prior detection)
bash(f'docker run -v {sshdir}:/mnt alpine cat /mnt/id_rsa', True, '-v sshdir still blocks')


# =============================================================================
# H2 — tar/zip long-flag and bunched-flag bypasses
# =============================================================================
print('\n=== H2: tar/zip flag-value bypasses ===')

# --files-from=PATH (glued long-flag)
bash(f'tar --files-from={env} -cf /tmp/out.tar', True, '--files-from=env')
bash(f'tar --files-from={sshkey} -cf /tmp/out.tar', True, '--files-from=sshkey')

# --files-from PATH (next-arg long-flag)
bash(f'tar --files-from {vault} -cf /tmp/out.tar', True, '--files-from next-arg')

# --include-from=PATH and --exclude-from=PATH
bash(f'tar -cf /tmp/out.tar --include-from={env} /etc', True, '--include-from=env')
bash(f'tar -cf /tmp/out.tar --exclude-from={vault} /etc', True, '--exclude-from=vault')

# --file=PATH (archive treated as sensitive read on extract)
bash(f'tar --file={env} -x', True, '--file=env (extract treats archive as sensitive)')

# -T <path> (next-arg short flag)
bash(f'tar -T {env} -cf /tmp/out.tar', True, '-T env (next-arg)')

# -T<path> (glued short flag)
bash(f'tar -T{env} -cf /tmp/out.tar', True, '-Tenv (glued)')

# Bunched -cT<path>
bash(f'tar -cT{env} /tmp/out.tar', True, '-cT/path bunched glued')

# Bunched -cT <path>
bash(f'tar -cT {env} /tmp/out.tar', True, '-cT path bunched next-arg')

# Positional sensitive path still blocked (regression)
bash(f'tar -cf /tmp/out.tar {sshkey}', True, 'positional sshkey still blocks')
bash(f'zip /tmp/out.zip {env}', True, 'zip positional env still blocks')

# Allow benign tar/zip invocations
bash('tar -cf /tmp/out.tar /tmp/safe', False, 'tar of /tmp/safe allowed')
bash('tar --files-from=/tmp/list -cf /tmp/out.tar', False, '--files-from=/tmp/list allowed')
bash('tar -xf /tmp/in.tar -C /tmp', False, 'tar extract from /tmp/in.tar allowed')
bash('tar -T /tmp/files.txt -cf /tmp/out.tar', False, '-T /tmp/files.txt allowed')
bash('zip -r /tmp/out.zip /tmp/data', False, 'zip /tmp/data allowed')


# =============================================================================
# Summary
# =============================================================================
print("\n" + "=" * 70)
passed = sum(results)
total = len(results)
print(f"RESULTS: {passed}/{total} passed")
print("=" * 70)
sys.exit(0 if passed == total else 1)
