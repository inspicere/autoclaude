#!/usr/bin/env python3
"""CI check: verify shared regex patterns are in sync across scripts.

Extracts named regex patterns from each file, strips comments and whitespace,
and verifies they are identical. Exits 1 on drift.
"""

import os
import re
import sys

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

TOKEN_FILES = [
    "claude-approval-report.py",
    "hooks/block-secrets.py",
    "hooks/warn-secrets-output.py",
]

TOKEN_PATTERNS = ["_PREFIXED_TOKEN_PATTERNS", "_RE_JWT"]

PAIR_CHECKS = [
    ("_SENSITIVE_PATH_RE", ["hooks/block-secrets.py", "hooks/landlock-sandbox.py"]),
]


def extract_pattern(source, var_name):
    """Extract a compiled regex definition from source, returning normalized form."""
    pattern = re.compile(
        rf'^{re.escape(var_name)}\s*=\s*re\.compile\(\s*\n(.*?)\n\)',
        re.MULTILINE | re.DOTALL,
    )
    m = pattern.search(source)
    if not m:
        return None
    raw = m.group(1)
    lines = []
    for line in raw.splitlines():
        stripped = re.sub(r'#.*$', '', line).strip()
        if stripped:
            lines.append(stripped)
    return "\n".join(lines)


def check_group(var_name, files):
    """Check a pattern is identical across a group of files. Returns (checks, drift)."""
    extracted = {}
    drift = False
    for rel_path in files:
        full = os.path.join(REPO_ROOT, rel_path)
        with open(full) as f:
            source = f.read()
        norm = extract_pattern(source, var_name)
        if norm is None:
            print(f"FAIL: {var_name} not found in {rel_path}")
            drift = True
            continue
        extracted[rel_path] = norm

    if len(extracted) >= 2:
        reference = list(extracted.values())[0]
        ref_file = list(extracted.keys())[0]
        for rel_path, norm in extracted.items():
            if norm != reference:
                print(f"DRIFT: {var_name} differs between {ref_file} and {rel_path}")
                drift = True

    return len(files), drift


def main():
    total_checks = 0
    any_drift = False

    for var_name in TOKEN_PATTERNS:
        checks, drift = check_group(var_name, TOKEN_FILES)
        total_checks += checks
        if drift:
            any_drift = True

    for var_name, files in PAIR_CHECKS:
        checks, drift = check_group(var_name, files)
        total_checks += checks
        if drift:
            any_drift = True

    if any_drift:
        print(f"\n0/{total_checks} passed")
        sys.exit(1)
    else:
        print(f"{total_checks}/{total_checks} passed")


if __name__ == "__main__":
    main()
