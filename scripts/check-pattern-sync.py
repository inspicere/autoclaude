#!/usr/bin/env python3
"""CI check: verify shared regex patterns are in sync across scripts.

Extracts named regex patterns from each file, strips comments and whitespace,
and verifies they are identical. Exits 1 on drift.
"""

import json
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

SETTINGS_SYNC = [
    ("BASELINE_SAFE_ALLOW", "allow"),
    ("BASELINE_DENY_RULES", "deny"),
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


def extract_python_list(source, var_name):
    """Extract a Python list literal from source, returning sorted list of strings."""
    pattern = re.compile(
        rf'^{re.escape(var_name)}\s*=\s*\[(.*?)\]',
        re.MULTILINE | re.DOTALL,
    )
    m = pattern.search(source)
    if not m:
        return None
    raw = m.group(1)
    return sorted(s.strip().strip('"').strip("'") for s in raw.split(',') if s.strip().strip('"').strip("'"))


def check_settings_sync():
    """Check BASELINE lists in main script match recommended-deny.json. Returns (checks, drift)."""
    script_path = os.path.join(REPO_ROOT, "claude-approval-report.py")
    json_path = os.path.join(REPO_ROOT, "settings", "recommended-deny.json")
    drift = False
    checks = 0

    with open(script_path) as f:
        script_source = f.read()
    with open(json_path) as f:
        settings = json.load(f)

    for var_name, json_key in SETTINGS_SYNC:
        checks += 1
        script_list = extract_python_list(script_source, var_name)
        json_list = sorted(settings.get("permissions", {}).get(json_key, []))
        if script_list is None:
            print(f"FAIL: {var_name} not found in claude-approval-report.py")
            drift = True
            continue
        if script_list != json_list:
            only_script = set(script_list) - set(json_list)
            only_json = set(json_list) - set(script_list)
            print(f"DRIFT: {var_name} differs from settings/recommended-deny.json [{json_key}]")
            if only_script:
                print(f"  Only in script: {only_script}")
            if only_json:
                print(f"  Only in JSON: {only_json}")
            drift = True

    return checks, drift


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

    checks, drift = check_settings_sync()
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
