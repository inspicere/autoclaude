#!/usr/bin/env python3
"""Run all autoclaude test suites and output DefectDojo Generic Findings Import JSON.

Each test failure becomes a finding. When all tests pass, an empty findings
list is uploaded, which closes any previously-open failure findings.
"""
import json
import os
import re
import subprocess
import sys
from datetime import datetime, timezone

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

SUITES = [
    ("tests/test_report.py", "Report Script Tests"),
    ("hooks/test_block_secrets.py", "Block Secrets Hook Tests"),
    ("hooks/test_bypass_fixes.py", "Bypass Fixes Tests"),
    ("hooks/test_round2_bypass_fixes.py", "Round 2 Bypass Fixes Tests"),
    ("hooks/test_round3_bypass_fixes.py", "Round 3 Bypass Fixes Tests"),
    ("hooks/test_analysis_fixes.py", "Analysis Findings Fixes Tests"),
    ("hooks/test_fp_fixes.py", "False Positive Fixes Tests"),
    ("hooks/test_infra_usability.py", "Infrastructure Usability Tests"),
    ("hooks/test_warn_secrets.py", "Warn Secrets Output Tests"),
    ("hooks/test_warn_mode.py", "Warn Mode Tests"),
    ("hooks/test_warn_output_adversarial.py", "PostToolUse Adversarial Tests"),
    ("hooks/test_phase1_audit_fixes.py", "Phase 1 Audit Fixes Tests"),
    ("hooks/test_round4_bypass_fixes.py", "Round 4 Bypass Fixes Tests"),
    ("hooks/test_phase3_audit_fixes.py", "Phase 3 Audit Fixes Tests"),
    ("hooks/test_phase4_audit_fixes.py", "Phase 4 Audit Fixes Tests"),
    ("hooks/test_phase5_audit_fixes.py", "Phase 5 Audit Fixes Tests"),
    ("hooks/test_phase6_audit_fixes.py", "Phase 6 Audit Fixes Tests"),
    ("scripts/check-pattern-sync.py", "Token Pattern Sync Check"),
]

_RE_RESULTS_SLASH = re.compile(r'(\d+)/(\d+)\s+passed')
_RE_RESULTS_COMMA = re.compile(r'(\d+)\s+passed,\s+(\d+)\s+failed')
_RE_FAIL_LINE = re.compile(r'^\s*FAIL\S*:\s*(.+)', re.MULTILINE)


def run_suite(path, label):
    full_path = os.path.join(REPO_ROOT, path)
    if not os.path.exists(full_path):
        return {
            "passed": 0, "total": 0, "failures": [f"Test file not found: {path}"],
            "exit_code": 1, "output": "",
        }

    result = subprocess.run(
        [sys.executable, full_path],
        capture_output=True, text=True, timeout=120,
        cwd=REPO_ROOT,
    )

    output = result.stdout + result.stderr
    m = _RE_RESULTS_SLASH.search(output)
    if m:
        passed = int(m.group(1))
        total = int(m.group(2))
    else:
        m = _RE_RESULTS_COMMA.search(output)
        if m:
            passed = int(m.group(1))
            total = passed + int(m.group(2))
        else:
            passed = 0
            total = 0
    failures = _RE_FAIL_LINE.findall(output)

    return {
        "passed": passed,
        "total": total,
        "failures": failures,
        "exit_code": result.returncode,
        "output": output[-2000:],
    }


def to_generic_findings(results):
    findings = []
    for path, label, result in results:
        if result["exit_code"] == 0 and not result["failures"]:
            continue
        if result["failures"]:
            for failure in result["failures"]:
                findings.append({
                    "title": f"Test Failure: {failure.strip()[:120]}",
                    "severity": "Medium",
                    "description": (
                        f"**Suite:** {label} (`{path}`)\n\n"
                        f"**Failure:** {failure.strip()}\n\n"
                        f"**Results:** {result['passed']}/{result['total']} passed\n\n"
                        f"```\n{result['output'][-500:]}\n```"
                    ),
                    "file_path": path,
                    "date": datetime.now(timezone.utc).strftime("%Y-%m-%d"),
                    "active": True,
                    "verified": True,
                    "static_finding": True,
                })
        else:
            findings.append({
                "title": f"Test Suite Error: {label}",
                "severity": "High",
                "description": (
                    f"**Suite:** {label} (`{path}`)\n\n"
                    f"Exit code {result['exit_code']} with no parseable results.\n\n"
                    f"```\n{result['output'][-500:]}\n```"
                ),
                "file_path": path,
                "date": datetime.now(timezone.utc).strftime("%Y-%m-%d"),
                "active": True,
                "verified": True,
                "static_finding": True,
            })
    return {"findings": findings}


def main():
    results = []
    total_passed = 0
    total_tests = 0
    any_failure = False

    for path, label in SUITES:
        print(f"Running {label} ({path})...", file=sys.stderr)
        result = run_suite(path, label)
        results.append((path, label, result))
        total_passed += result["passed"]
        total_tests += result["total"]
        status = "PASS" if result["exit_code"] == 0 else "FAIL"
        if result["exit_code"] != 0:
            any_failure = True
        print(f"  {status}: {result['passed']}/{result['total']}", file=sys.stderr)

    print(f"\nTotal: {total_passed}/{total_tests} passed across {len(SUITES)} suites",
          file=sys.stderr)

    findings = to_generic_findings(results)
    json.dump(findings, sys.stdout, indent=2)
    print()

    if any_failure:
        print(f"\nFAILED: {len(findings['findings'])} finding(s)", file=sys.stderr)
        sys.exit(1)
    else:
        print("\nALL SUITES PASSED", file=sys.stderr)


if __name__ == "__main__":
    main()
