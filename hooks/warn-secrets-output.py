#!/usr/bin/env python3
"""PostToolUse hook — warns when command output contains secrets.

Scans Bash command output for known token patterns, JWTs, and private
key material. Cannot prevent the leak (command already ran) but alerts
Claude to avoid using the secret and warns the user to rotate.

Install by adding to hooks in ~/.claude/settings.json:
  "hooks": {
    "PostToolUse": [{
      "matcher": "Bash",
      "hooks": [{"type": "command", "command": "python3 /path/to/hooks/warn-secrets-output.py"}]
    }]
  }

Outputs JSON with decision/reason on detection. Exits 0 always.
"""

import json
import math
import re
import sys


_PREFIXED_TOKEN_PATTERNS = re.compile(
    r'(?:'
    r'ghp_[0-9a-zA-Z]{36}'
    r'|github_pat_\w{82}'
    r'|(?:ghu|ghs)_[0-9a-zA-Z]{36}'
    r'|glpat-[\w-]{20}'
    r'|sk-ant-(?:api03|admin01)-[a-zA-Z0-9_\-]{93}AA'
    r'|sk-(?:proj|svcacct|admin)-[A-Za-z0-9_\-]{58,}'
    r'|sk-[a-zA-Z0-9]{20}T3BlbkFJ[a-zA-Z0-9]{20}'
    r'|(?:A3T[A-Z0-9]|AKIA|ASIA|ABIA|ACCA)[A-Z2-7]{16}'
    r'|AIza[\w-]{35}'
    r'|hvs\.[\w-]{90,120}'
    r'|hvb\.[\w-]{138,300}'
    r'|xox[bpe]-[0-9]{10,13}-[\w-]+'
    r'|SG\.[\w=_\-.]{66}'
    r'|(?:sk|rk)_(?:test|live|prod)_[a-zA-Z0-9]{10,99}'
    r'|npm_[a-z0-9]{36}'
    r'|hf_[a-zA-Z]{34}'
    r'|pplx-[a-zA-Z0-9]{48}'
    r'|dop_v1_[a-f0-9]{64}'
    r'|ntn_[0-9]{11}[A-Za-z0-9]{35}'
    r'|glsa_[A-Za-z0-9]{32}_[A-Fa-f0-9]{8}'
    r'|pypi-AgEIcHlwaS5vcmc[\w-]{50,}'
    r'|HRKU-AA[0-9a-zA-Z_-]{58}'
    r')',
)

_RE_JWT = re.compile(
    r'\bey[a-zA-Z0-9]{17,}\.ey[a-zA-Z0-9/\\_-]{17,}\.[a-zA-Z0-9/\\_-]{10,}=?=?'
)

_RE_PRIVATE_KEY = re.compile(
    r'-----BEGIN[ A-Z0-9_-]{0,100}PRIVATE KEY(?:\s+BLOCK)?-----'
)

# Commands whose output is expected to contain secret-like patterns
_EXEMPT_COMMANDS = re.compile(
    r'^\s*(?:grep|egrep|fgrep|rg|ag|ack)\b'
    r'|^\s*(?:cat|head|tail|less)\s+.*(?:block-secrets|claude-approval-report|README|CLAUDE\.md|\.py\b|\.md\b|\.json\b)'
    r'|^\s*python3\s+.*(?:block-secrets|claude-approval-report|test_hook)'
    r'|^\s*git\s+(?:diff|log|show)\b'
)


def _shannon_entropy(data):
    if not data:
        return 0.0
    counts = {}
    for c in data:
        counts[c] = counts.get(c, 0) + 1
    length = len(data)
    return -sum((n / length) * math.log2(n / length) for n in counts.values())


def _scan_output(text):
    """Scan text for secrets. Returns list of detection descriptions."""
    findings = []

    if _PREFIXED_TOKEN_PATTERNS.search(text):
        findings.append("Known API token/key pattern")

    if _RE_JWT.search(text):
        findings.append("JWT token")

    if _RE_PRIVATE_KEY.search(text):
        findings.append("Private key material")

    return findings


def main():
    try:
        data = json.load(sys.stdin)
        if not isinstance(data, dict):
            sys.exit(0)
    except (json.JSONDecodeError, EOFError, ValueError):
        sys.exit(0)

    tool_name = data.get("tool_name", "")
    if tool_name != "Bash":
        sys.exit(0)

    command = data.get("tool_input", {}).get("command", "")
    if _EXEMPT_COMMANDS.search(command):
        sys.exit(0)

    result = data.get("tool_result", "")
    if isinstance(result, dict):
        result = json.dumps(result)
    if not isinstance(result, str):
        result = str(result)

    findings = _scan_output(result)
    if not findings:
        sys.exit(0)

    types = ", ".join(findings)
    response = {
        "decision": "block",
        "reason": (
            f"SECRET IN OUTPUT: {types}. "
            f"The command `{command[:80]}` produced output containing secrets. "
            f"These are now in the session transcript and were sent to the API. "
            f"Do NOT repeat, store, or use these values. "
            f"Advise the user to rotate the exposed credentials."
        ),
    }

    json.dump(response, sys.stdout)
    sys.exit(0)


if __name__ == "__main__":
    main()
