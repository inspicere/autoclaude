#!/usr/bin/env python3
"""CI check: verify token regex patterns are in sync across all three scripts.

Extracts the _PREFIXED_TOKEN_PATTERNS regex and _RE_JWT regex from each file,
strips comments and whitespace, and verifies they are identical. Exits 1 on drift.
"""

import os
import re
import sys

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

FILES = [
    "claude-approval-report.py",
    "hooks/block-secrets.py",
    "hooks/warn-secrets-output.py",
]

PATTERNS_TO_CHECK = ["_PREFIXED_TOKEN_PATTERNS", "_RE_JWT"]


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


def main():
    any_drift = False

    for var_name in PATTERNS_TO_CHECK:
        extracted = {}
        for rel_path in FILES:
            full = os.path.join(REPO_ROOT, rel_path)
            with open(full) as f:
                source = f.read()
            norm = extract_pattern(source, var_name)
            if norm is None:
                print(f"FAIL: {var_name} not found in {rel_path}")
                any_drift = True
                continue
            extracted[rel_path] = norm

        if len(extracted) < len(FILES):
            continue

        values = list(extracted.values())
        reference = values[0]
        for rel_path, norm in extracted.items():
            if norm != reference:
                print(f"DRIFT: {var_name} differs between {FILES[0]} and {rel_path}")
                any_drift = True

    checks = len(PATTERNS_TO_CHECK) * len(FILES)
    if any_drift:
        print(f"\n0/{checks} passed")
        sys.exit(1)
    else:
        print(f"{checks}/{checks} passed")


if __name__ == "__main__":
    main()
