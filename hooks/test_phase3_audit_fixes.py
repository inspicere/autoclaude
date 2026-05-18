#!/usr/bin/env python3
"""Test suite for Phase 3 audit fixes (M4, M7, M8) from 2026-05-16 project audit.

Covers:
  M4 — audit log rotation is race-safe under parallel hook invocations
  M7 — single-backup retention (current overwrites .1); docs updated
  M8 — settings.json loads validate shape and emit warnings on bad input
"""

import concurrent.futures
import importlib.util
import json
import os
import subprocess
import sys
import tempfile

HOOK = os.path.join(os.path.dirname(__file__), 'block-secrets.py')
REPORT = os.path.join(os.path.dirname(__file__), '..', 'claude-approval-report.py')


def _load_module(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


report = _load_module('report', REPORT)


results = []


def check(condition, label):
    status = 'PASS' if condition else 'FAIL'
    results.append(condition)
    print(f'  {status}: {label}')


# =============================================================================
# M4 — race-safe rotation under parallel hook invocations
# =============================================================================
print('=== M4: race-safe audit log rotation ===')

def _spawn_audit_writer(tmpdir, payload, tag):
    """Run the hook once with HOME=tmpdir and HOOK_AUDIT=1. Returns (exit, stderr)."""
    env = os.environ.copy()
    env['HOME'] = tmpdir
    env['HOOK_AUDIT'] = '1'
    data = json.dumps({'tool_name': 'Bash', 'tool_input': {'command': f'ls {tag}'}})
    r = subprocess.run(['python3', HOOK], input=data,
                       capture_output=True, text=True, timeout=30, env=env)
    return r.returncode, r.stderr


with tempfile.TemporaryDirectory() as tmpdir:
    os.makedirs(os.path.join(tmpdir, '.claude'), exist_ok=True)
    log = os.path.join(tmpdir, '.claude', 'hook-audit.jsonl')
    backup = log + '.1'
    lock = log + '.lock'

    # Pre-populate the log to just over the rotation threshold so the very
    # next write triggers rotation. Use a content that won't match any
    # secret pattern so the hook treats it as an opaque blob.
    with open(log, 'wb') as f:
        f.write(b'{"ts":"x","decision":"allow","tool":"Bash","command":"ls"}\n' * 100000)
    pre_size = os.path.getsize(log)
    check(pre_size > 5_000_000,
          f"pre-populated log is > 5MB (got {pre_size} bytes)")

    # Spawn 8 parallel writers; one (or more) should win the rotation race.
    with concurrent.futures.ThreadPoolExecutor(max_workers=8) as ex:
        futures = [ex.submit(_spawn_audit_writer, tmpdir, '', i) for i in range(8)]
        outs = [f.result() for f in futures]

    # All writers must exit 0 (no crash)
    check(all(code == 0 for code, _ in outs),
          f"all 8 parallel writers exited 0 ({sum(1 for c, _ in outs if c != 0)} failed)")

    # Backup file exists (rotation happened at least once)
    check(os.path.exists(backup),
          f".jsonl.1 backup created (path={backup})")

    # Lockfile exists (and is empty / 0 bytes)
    check(os.path.exists(lock), f"sidecar .lock file present at {lock}")

    # Backup contains substantial data (the rotated content, not clobbered)
    if os.path.exists(backup):
        backup_size = os.path.getsize(backup)
        check(backup_size > 4_000_000,
              f".jsonl.1 has substantial content (got {backup_size} bytes, expected > 4MB)")

    # Current log is small (post-rotation writes only)
    if os.path.exists(log):
        cur_size = os.path.getsize(log)
        check(cur_size < 100_000,
              f"current log is small after rotation (got {cur_size} bytes, expected < 100KB)")

    # No orphan files (no .jsonl.tmp or unexpected siblings)
    sibs = sorted(os.listdir(os.path.join(tmpdir, '.claude')))
    expected = {'hook-audit.jsonl', 'hook-audit.jsonl.1', 'hook-audit.jsonl.lock'}
    unexpected = set(sibs) - expected
    check(len(unexpected) == 0,
          f"no orphan files in .claude/ (extras: {unexpected})")


# =============================================================================
# M7 — single-backup retention model (sanity)
# =============================================================================
print('\n=== M7: single-backup retention ===')

with tempfile.TemporaryDirectory() as tmpdir:
    os.makedirs(os.path.join(tmpdir, '.claude'), exist_ok=True)
    log = os.path.join(tmpdir, '.claude', 'hook-audit.jsonl')
    backup = log + '.1'

    # Write log above threshold three times, verify only .1 exists
    # (not .1, .2, .3 — those are not part of our model)
    for round_n in range(3):
        with open(log, 'wb') as f:
            f.write(f'round{round_n}-'.encode() + b'A' * 5_500_000)
        _spawn_audit_writer(tmpdir, '', f'round{round_n}')

    sibs = sorted(os.listdir(os.path.join(tmpdir, '.claude')))
    check('hook-audit.jsonl.1' in sibs, ".jsonl.1 backup exists after multiple rotations")
    check('hook-audit.jsonl.2' not in sibs and 'hook-audit.jsonl.3' not in sibs,
          f"no .2 or .3 generations created (siblings: {sibs})")


# =============================================================================
# M8 — settings.json schema validation
# =============================================================================
print('\n=== M8: settings.json schema validation ===')

with tempfile.TemporaryDirectory() as tmpdir:
    from pathlib import Path

    # Valid input — returns the data unchanged
    p = Path(tmpdir) / "valid.json"
    p.write_text(json.dumps({"permissions": {"allow": ["Bash(ls *)"], "deny": []}}))
    data = report._safe_load_settings(p)
    check(data.get("permissions", {}).get("allow") == ["Bash(ls *)"],
          "valid settings returned intact")

    # Non-existent path → empty dict
    p = Path(tmpdir) / "missing.json"
    data = report._safe_load_settings(p)
    check(data == {}, "non-existent path returns empty dict")

    # Malformed JSON → empty dict + stderr warning
    p = Path(tmpdir) / "malformed.json"
    p.write_text('{ "permissions": { "allow"::: ]')
    import io, contextlib
    err_buf = io.StringIO()
    with contextlib.redirect_stderr(err_buf):
        data = report._safe_load_settings(p)
    check(data == {}, "malformed JSON returns empty dict")
    check("invalid JSON" in err_buf.getvalue(),
          f"malformed JSON emits Warning (got stderr={err_buf.getvalue()!r})")

    # Root is a list, not an object → empty dict + warning
    p = Path(tmpdir) / "listroot.json"
    p.write_text(json.dumps([1, 2, 3]))
    err_buf = io.StringIO()
    with contextlib.redirect_stderr(err_buf):
        data = report._safe_load_settings(p)
    check(data == {}, "list-at-root returns empty dict")
    check("not a JSON object" in err_buf.getvalue(),
          f"list-at-root emits warning (got stderr={err_buf.getvalue()!r})")

    # permissions is a list (not a dict) → repaired to {} + warning
    p = Path(tmpdir) / "badperms.json"
    p.write_text(json.dumps({"permissions": ["Bash(ls *)"]}))
    err_buf = io.StringIO()
    with contextlib.redirect_stderr(err_buf):
        data = report._safe_load_settings(p)
    check(data.get("permissions") == {},
          f"non-dict permissions repaired to empty (got {data.get('permissions')!r})")
    check("'permissions' is not an object" in err_buf.getvalue(),
          "non-dict permissions emits warning")

    # permissions.allow is a string (not a list) → repaired to [] + warning
    p = Path(tmpdir) / "badallow.json"
    p.write_text(json.dumps({"permissions": {"allow": "Bash(ls *)"}}))
    err_buf = io.StringIO()
    with contextlib.redirect_stderr(err_buf):
        data = report._safe_load_settings(p)
    check(data.get("permissions", {}).get("allow") == [],
          f"non-list allow repaired to empty list (got {data['permissions']['allow']!r})")
    check("'permissions.allow' is not a list" in err_buf.getvalue(),
          "non-list allow emits warning")

    # permissions absent entirely → data returned as-is
    p = Path(tmpdir) / "noperms.json"
    p.write_text(json.dumps({"other": "field"}))
    data = report._safe_load_settings(p)
    check(data == {"other": "field"}, "absent permissions left intact")


# =============================================================================
# Summary
# =============================================================================
print("\n" + "=" * 70)
passed = sum(results)
total = len(results)
print(f"RESULTS: {passed}/{total} passed")
print("=" * 70)
sys.exit(0 if passed == total else 1)
