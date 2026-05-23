#!/usr/bin/env python3
"""Benchmark: realpath cost in hooks/block-secrets.py:_is_sensitive_path.

Compares two variants:
  CURRENT:   expanduser → realpath → regex match  (today's behaviour)
  PREFILTER: expanduser → regex match → (only if matched) realpath → regex

Measured 2026-05-22 on the development machine:
  CURRENT median:    36.1 s total (722 µs / call)
  PREFILTER median:  14.8 s total (296 µs / call)
  Speedup:           2.45×, saves ~10.7 ms per full hook subprocess

Tradeoff: PREFILTER loses symlink-to-sensitive detection — a symlink
whose un-resolved path doesn't match `_SENSITIVE_PATH_RE` is allowed
through. The current implementation catches such symlinks via realpath.
The Landlock prototype catches them at the kernel level, regardless of
how the path was derived.

Decision (audit 2026-05-22, item 2.1): retain CURRENT. 49 ms median
hook latency is acceptable for the protection; symlink coverage matters.
This script is checked in so future perf changes have a baseline.

Usage:
  python3 scripts/bench-realpath.py          # default 50,000 iterations
  python3 scripts/bench-realpath.py 10000    # custom iteration count
"""

import importlib.util
import os
import statistics
import sys
import tempfile
import time

# Resolve the hook path relative to this file so the script is portable.
HOOK_PATH = os.path.join(
    os.path.dirname(os.path.abspath(__file__)),
    '..', 'hooks', 'block-secrets.py',
)
HOOK_PATH = os.path.normpath(HOOK_PATH)
spec = importlib.util.spec_from_file_location('hook', HOOK_PATH)
hook = importlib.util.module_from_spec(spec)
spec.loader.exec_module(hook)


# Representative tokens that would flow through _is_sensitive_path in
# normal usage. Mostly non-sensitive — that's the common case the
# pre-filter would short-circuit.
NORMAL = [
    'README.md',
    'src/main.py',
    'hooks/test_phase7_audit_fixes.py',
    'package.json',
    '/usr/bin/ls',
    '/tmp/output.txt',
    'docs/cli-reference.md',
    'tests/test_report.py',
    '/etc/hostname',
    'CHANGELOG.md',
    '/home/terrabot/autoclaude/claude-approval-report.py',
    'pyproject.toml',
    '.gitignore',
    'scripts/ci-test-runner.py',
    '/var/log/syslog',
    'Makefile',
    'index.html',
    'config.yaml',
    '/opt/something/data.json',
    '/proc/self/status',
]

# Tokens that SHOULD match the sensitive regex. These are the cases where
# the pre-filter still does the realpath call.
SENSITIVE = [
    '~/.env',
    '/etc/shadow',
    '~/.ssh/id_rsa',
    '~/.aws/credentials',
    '/etc/group',  # would NOT match — gshadow does
]


def _bench(label, fn, n=50_000):
    """Run fn() n times, return (total_seconds, per_call_us)."""
    # Warmup
    for _ in range(1000):
        fn()
    start = time.perf_counter()
    for _ in range(n):
        fn()
    elapsed = time.perf_counter() - start
    return elapsed, (elapsed / n) * 1_000_000


def make_current_workload():
    """Each iteration runs _is_sensitive_path over the full token mix."""
    f = hook._is_sensitive_path
    tokens = NORMAL + SENSITIVE
    def go():
        for t in tokens:
            f(t)
    return go


def make_prefilter_variant():
    """Drop-in prefilter version. Skips realpath when un-resolved path
    doesn't already match _SENSITIVE_PATH_RE or a glob."""
    sensitive_re = hook._SENSITIVE_PATH_RE
    could_glob = hook._could_glob_match_sensitive
    strip_quotes = hook._strip_quotes

    def _is_sensitive_path_prefilter(path):
        path = strip_quotes(path)
        path = os.path.expanduser(path)
        # Fast reject: regex on un-resolved path. Symlink to sensitive
        # would slip through — that's the tradeoff we're measuring.
        if not sensitive_re.search(path) and not could_glob(path):
            return False
        path = os.path.realpath(path)
        if not path.startswith('/'):
            path = '/' + path
        basename = os.path.basename(path)
        if basename.endswith(('.example', '.sample', '.template')):
            return False
        if path.endswith('.pub'):
            return False
        if could_glob(path):
            return True
        return bool(sensitive_re.search(path))

    return _is_sensitive_path_prefilter


def main():
    n = int(sys.argv[1]) if len(sys.argv) > 1 else 50_000
    tokens = NORMAL + SENSITIVE
    print(f"Benchmark: {n:,} iterations × {len(tokens)} tokens = "
          f"{n * len(tokens):,} _is_sensitive_path calls per variant")
    print(f"Tokens: {len(NORMAL)} non-sensitive + {len(SENSITIVE)} sensitive")
    print()

    # --- Variant 1: CURRENT (realpath always) ---
    current_runs = []
    for trial in range(3):
        elapsed, per_us = _bench('current', make_current_workload(), n=n)
        current_runs.append((elapsed, per_us))
        print(f"  CURRENT  trial {trial+1}: {elapsed:6.3f}s total, "
              f"{per_us:6.2f} µs/call")

    # --- Variant 2: PREFILTER ---
    orig = hook._is_sensitive_path
    hook._is_sensitive_path = make_prefilter_variant()
    try:
        prefilter_runs = []
        for trial in range(3):
            elapsed, per_us = _bench('prefilter', make_current_workload(), n=n)
            prefilter_runs.append((elapsed, per_us))
            print(f"  PREFILTER trial {trial+1}: {elapsed:6.3f}s total, "
                  f"{per_us:6.2f} µs/call")
    finally:
        hook._is_sensitive_path = orig

    cur_med = statistics.median([t[0] for t in current_runs])
    pre_med = statistics.median([t[0] for t in prefilter_runs])
    cur_us = statistics.median([t[1] for t in current_runs])
    pre_us = statistics.median([t[1] for t in prefilter_runs])

    speedup = cur_med / pre_med if pre_med > 0 else float('inf')
    savings_us = cur_us - pre_us

    print()
    print("=" * 60)
    print(f"  CURRENT median:    {cur_med:6.3f}s ({cur_us:6.2f} µs/call)")
    print(f"  PREFILTER median:  {pre_med:6.3f}s ({pre_us:6.2f} µs/call)")
    print(f"  Speedup:           {speedup:.2f}×")
    print(f"  Savings per call:  {savings_us:.2f} µs")
    print()

    # --- Now sanity-check correctness: prefilter must agree on every input ---
    print("Correctness check (current vs prefilter on the workload):")
    pre = make_prefilter_variant()
    disagreements = []
    for t in tokens:
        if orig(t) != pre(t):
            disagreements.append((t, orig(t), pre(t)))
    if disagreements:
        print(f"  DISAGREEMENTS ({len(disagreements)}):")
        for t, c, p in disagreements:
            print(f"    {t!r}: current={c}, prefilter={p}")
    else:
        print("  ✓ No disagreements on this token set (no symlinks present)")

    # --- Targeted: introduce a symlink to a sensitive file ---
    with tempfile.TemporaryDirectory() as td:
        sensitive_target = os.path.expanduser('~/.env')
        symlink = os.path.join(td, 'looks-safe.txt')
        if os.path.exists(sensitive_target) or True:
            # Always create a symlink to /etc/shadow (exists by definition);
            # /etc/shadow regex matches. Then point looks-safe.txt at it.
            os.symlink('/etc/shadow', symlink)
            c_says = orig(symlink)
            p_says = pre(symlink)
            print()
            print("Symlink coverage test:")
            print(f"  Path: {symlink} → /etc/shadow")
            print(f"  CURRENT  detects as sensitive: {c_says}")
            print(f"  PREFILTER detects as sensitive: {p_says}")
            if c_says and not p_says:
                print("  ⚠ PREFILTER misses the symlinked sensitive file "
                      "(this is the documented tradeoff)")

    # --- Real-world latency: full hook subprocess startup ---
    print()
    print("Per-hook-call wall time (includes Python startup):")
    import json as _json
    import subprocess as _sub
    payload = _json.dumps({'tool_name': 'Bash', 'tool_input': {
        'command': 'ls -la /tmp/output.txt'
    }})
    times = []
    for _ in range(20):
        t0 = time.perf_counter()
        _sub.run(['python3', HOOK_PATH], input=payload,
                 capture_output=True, text=True)
        times.append((time.perf_counter() - t0) * 1000)
    print(f"  Full hook invocation median: {statistics.median(times):.1f} ms "
          f"(min {min(times):.1f}, max {max(times):.1f}, p95 "
          f"{sorted(times)[int(0.95 * len(times))]:.1f})")
    print(f"  Per-call _is_sensitive_path savings would shave "
          f"~{savings_us * len(tokens):.0f} µs off, i.e. "
          f"~{savings_us * len(tokens) / 1000:.2f} ms per full call.")


if __name__ == '__main__':
    main()
