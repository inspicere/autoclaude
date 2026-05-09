#!/usr/bin/env python3
"""PostToolUse hook — warns when command output contains secrets.

Scans Bash command output for known token patterns, JWTs, and private
key material. Cannot prevent the leak (command already ran) but alerts
Claude to avoid using the secret and warns the user to rotate.

Install by adding to hooks in ~/.claude/settings.json:
  "hooks": {
    "PostToolUse": [{
      "matcher": "Bash|Read|Edit",
      "hooks": [{"type": "command", "command": "python3 /path/to/hooks/warn-secrets-output.py"}]
    }]
  }

Outputs JSON with decision/reason on detection. Exits 0 always.
"""

import json
import math
import os
import re
import sys
import time


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

_EXEMPT_COMMANDS = re.compile(
    r'^\s*(?:grep|egrep|fgrep|rg|ag|ack)\b'
    r'|^\s*(?:cat|head|tail|less)\s+.*(?:block-secrets|claude-approval-report|warn-secrets|README|CLAUDE\.md)'
    r'|^\s*python3\s+.*(?:block-secrets|claude-approval-report|test_hook)'
    r'|^\s*git\s+(?:diff|log|show)\b'
)

_EXEMPT_FILE_PATHS = re.compile(
    r'(?:block-secrets|claude-approval-report|warn-secrets|README|CLAUDE\.md)'
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


_AUDIT_LOG = os.path.join(os.path.expanduser("~"), ".claude", "hook-audit.jsonl")
_CORRELATE = os.environ.get("HOOK_CORRELATE", "1") == "1"
_RE_VAR_FROM_REASON = re.compile(r'^(\w+) will (?:be set|expand)')


def _read_recent_warns(max_age_seconds=10):
    """Read recent warn entries from the PreToolUse audit log."""
    try:
        size = os.path.getsize(_AUDIT_LOG)
    except OSError:
        return []
    read_bytes = min(size, 50_000)
    warns = []
    now = time.time()
    try:
        with open(_AUDIT_LOG, "r") as f:
            if read_bytes < size:
                f.seek(size - read_bytes)
                f.readline()
            for line in f:
                try:
                    rec = json.loads(line)
                except (json.JSONDecodeError, ValueError):
                    continue
                if rec.get("decision") != "warn":
                    continue
                try:
                    ts_str = rec["ts"]
                    if "+" in ts_str or ts_str.endswith("Z"):
                        from datetime import datetime, timezone
                        dt = datetime.fromisoformat(ts_str.replace("Z", "+00:00"))
                        rec_time = dt.timestamp()
                    else:
                        rec_time = time.mktime(time.strptime(
                            ts_str[:19], "%Y-%m-%dT%H:%M:%S"))
                except (KeyError, ValueError, OverflowError):
                    continue
                if now - rec_time <= max_age_seconds:
                    warns.append(rec)
    except OSError:
        pass
    return warns


def _extract_variable_names(warn_records):
    """Extract variable names from warn reason strings and commands."""
    names = set()
    for rec in warn_records:
        reason = rec.get("reason", "")
        m = _RE_VAR_FROM_REASON.match(reason)
        if m:
            names.add(m.group(1))
        cmd = rec.get("command", "")
        for m2 in re.finditer(r'\b(\w+)=\$\(', cmd):
            names.add(m2.group(1))
    return names


def _check_output_for_expanded_secrets(text, variable_names):
    """Check output for high-entropy strings that could be expanded secrets."""
    if not variable_names:
        return []
    findings = []
    for token in text.split():
        clean = token.strip("\"',;:()[]{}|")
        if len(clean) < 16:
            continue
        if clean.startswith(("/", ".", "~", "http")):
            continue
        ent = _shannon_entropy(clean)
        if ent >= 3.5:
            findings.append(
                f"High-entropy value in output (possible expanded secret from "
                f"flagged variable {'/'.join(sorted(variable_names)[:3])})")
            break
    return findings


def main():
    try:
        data = json.load(sys.stdin)
        if not isinstance(data, dict):
            sys.exit(0)
    except (json.JSONDecodeError, EOFError, ValueError):
        sys.exit(0)

    tool_name = data.get("tool_name", "")
    tool_input = data.get("tool_input", {})

    if tool_name == "Bash":
        command = tool_input.get("command", "")
        if _EXEMPT_COMMANDS.search(command):
            sys.exit(0)
        source_desc = f"The command `{command[:80]}`"
    elif tool_name in ("Read", "Edit"):
        file_path = tool_input.get("file_path", "")
        if file_path and _EXEMPT_FILE_PATHS.search(file_path):
            sys.exit(0)
        source_desc = f"Reading `{file_path}`"
    else:
        sys.exit(0)

    result = data.get("tool_result", "")
    if isinstance(result, dict):
        result = json.dumps(result)
    if not isinstance(result, str):
        result = str(result)

    findings = _scan_output(result)

    if not findings and _CORRELATE:
        recent_warns = _read_recent_warns()
        if recent_warns:
            var_names = _extract_variable_names(recent_warns)
            correlated = _check_output_for_expanded_secrets(result, var_names)
            findings.extend(correlated)

    if not findings:
        sys.exit(0)

    types = ", ".join(findings)
    response = {
        "decision": "block",
        "reason": (
            f"SECRET IN OUTPUT: {types}. "
            f"{source_desc} produced output containing secrets. "
            f"These are now in the session transcript and were sent to the API. "
            f"Do NOT repeat, store, or use these values. "
            f"Advise the user to rotate the exposed credentials."
        ),
    }

    json.dump(response, sys.stdout)
    sys.exit(0)


if __name__ == "__main__":
    main()
