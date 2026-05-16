#!/usr/bin/env python3
"""Test suite for claude-approval-report.py — tests pure functions without session data."""

import importlib.util
import io
import os
import sys
import unittest.mock

# Import the report module by file path (it has hyphens in the name)
spec = importlib.util.spec_from_file_location(
    "report", os.path.join(os.path.dirname(__file__), "..", "claude-approval-report.py")
)
report = importlib.util.module_from_spec(spec)
spec.loader.exec_module(report)

results = []


def check(condition, label):
    status = "PASS" if condition else "FAIL"
    results.append(condition)
    print(f"  {status}: {label}")
    if not condition:
        return False
    return True


# =============================================================================
# Shannon entropy
# =============================================================================
print("=== Shannon entropy ===")
check(report._shannon_entropy("") == 0.0, "empty string → 0.0")
check(report._shannon_entropy("aaaa") == 0.0, "uniform string → 0.0")
check(report._shannon_entropy("ab") == 1.0, "two equal chars → 1.0")
e = report._shannon_entropy("aB3$xZ9!")
check(e > 2.5, f"mixed chars → {e:.2f} > 2.5")
e_low = report._shannon_entropy("aaabbbccc")
check(e_low < 2.0, f"low-diversity string → {e_low:.2f} < 2.0")


# =============================================================================
# Secret detection
# =============================================================================
print("\n=== Secret detection (_has_secret_token) ===")
check(report._has_secret_token("ghp_" + "a" * 36), "GitHub PAT detected")
check(report._has_secret_token("sk-ant-api03-" + "a" * 93 + "AA"), "Anthropic key detected")
check(report._has_secret_token("xoxb-1234567890-abcdefghij"), "Slack token detected")
check(report._has_secret_token("AKIAIOSFODNN7EXAMPLE"), "AWS access key detected")
check(report._has_secret_token("eyJhbGciOiJIUzI1NiIsI.eyJzdWIiOiIxMjM0NTY3ODkwIiwidGVzdCI.aBcDeFgHiJkLmN0123"), "JWT detected")
check(report._has_secret_token("-----BEGIN RSA PRIVATE KEY-----"), "private key detected")
check(not report._has_secret_token("git push origin main"), "normal command not flagged")
check(not report._has_secret_token("echo hello world"), "echo not flagged")


# =============================================================================
# High entropy blob detection
# =============================================================================
print("\n=== High entropy blob detection ===")
check(report._has_high_entropy_blob(["aB3xZ9kLmN4pQ7rS0tU2vW5yA8cE1fGhI"]), "random base64 detected")
check(not report._has_high_entropy_blob(["aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"]), "uniform blob not flagged")
check(not report._has_high_entropy_blob(["short"]), "short token not flagged")
check(not report._has_high_entropy_blob(["/usr/local/bin/something1234567890abcdef"]), "path not flagged")
check(not report._has_high_entropy_blob(["./relative/path/with32charspaddd"]), "relative path not flagged")


# =============================================================================
# Secret redaction
# =============================================================================
print("\n=== Secret redaction ===")
r = report.redact_secrets("ghp_" + "a" * 36)
check("<REDACTED>" in r and "ghp_" not in r, "GitHub PAT redacted")
r = report.redact_secrets("eyJhbGciOiJIUzI1NiIsI.eyJzdWIiOiIxMjM0NTY3ODkwIiwidGVzdCI.aBcDeFgHiJkLmN0123")
check("<REDACTED" in r and "eyJ" not in r, "JWT redacted")
r = report.redact_secrets("API_KEY=supersecretvalue123")
check("API_KEY=<REDACTED>" in r and "supersecret" not in r, "secret assignment redacted")
r = report.redact_secrets("-H 'Authorization: Bearer sk-ant-api03-xxxx'")
check("<REDACTED>" in r and "sk-ant" not in r, "Bearer token redacted")
r = report.redact_secrets("echo hello world")
check(r == "echo hello world", "normal command unchanged")


# =============================================================================
# _cmd_has_secrets
# =============================================================================
print("\n=== _cmd_has_secrets ===")
check(report._cmd_has_secrets("curl -H 'Authorization: Bearer realtoken123'"), "curl with Bearer flagged")
check(report._cmd_has_secrets("export API_KEY=realsecretvalue123"), "secret assignment flagged")
check(report._cmd_has_secrets("vault write secret/x token=ghp_abcdef1234567890ABCDEF12345678"),
      "command with GitHub PAT flagged")
check(not report._cmd_has_secrets("git push origin main"), "git push not flagged")
check(not report._cmd_has_secrets("ls -la"), "ls not flagged")
check(not report._cmd_has_secrets("export API_KEY=changeme"), "placeholder value not flagged")
check(not report._cmd_has_secrets("export API_KEY=placeholder"), "placeholder literal not flagged")
check(not report._cmd_has_secrets("export API_KEY=$VAULT_TOKEN"), "variable reference not flagged")


# =============================================================================
# M1 (2026-05-16 audit): _RE_SECRET_ASSIGN captures quoted values with spaces
# =============================================================================
print("\n=== _RE_SECRET_ASSIGN quoted-value capture (M1) ===")
m = report._RE_SECRET_ASSIGN.search('API_KEY="value with spaces here"')
check(m is not None and m.group(2) == '"value with spaces here"',
      f"double-quoted value with spaces captured fully (got {m.group(2) if m else None!r})")
m = report._RE_SECRET_ASSIGN.search("VAULT_TOKEN='multi word secret'")
check(m is not None and m.group(2) == "'multi word secret'",
      f"single-quoted value with spaces captured fully (got {m.group(2) if m else None!r})")
m = report._RE_SECRET_ASSIGN.search("API_KEY=plainvalue")
check(m is not None and m.group(2) == "plainvalue",
      f"unquoted value still captured (got {m.group(2) if m else None!r})")
red = report.redact_secrets('export API_KEY="long secret with spaces"')
check("<REDACTED>" in red and "long secret" not in red,
      f"redaction covers full quoted span (got {red!r})")


# =============================================================================
# Risk classification
# =============================================================================
print("\n=== Risk classification ===")

check(report.classify_risk("Bash", {"command": "ls -la"}) == "read-only", "ls → read-only")
check(report.classify_risk("Bash", {"command": "cat README.md"}) == "read-only", "cat → read-only")
check(report.classify_risk("Bash", {"command": "grep -r TODO ."}) == "read-only", "grep → read-only")
check(report.classify_risk("Bash", {"command": "git status"}) == "read-only", "git status → read-only")
check(report.classify_risk("Bash", {"command": "git log --oneline"}) == "read-only", "git log → read-only")
check(report.classify_risk("Bash", {"command": "git diff HEAD"}) == "read-only", "git diff → read-only")

check(report.classify_risk("Bash", {"command": "git add ."}) == "mutating", "git add → mutating")
check(report.classify_risk("Bash", {"command": "git commit -m 'test'"}) == "mutating", "git commit → mutating")
check(report.classify_risk("Bash", {"command": "git push origin main"}) == "mutating", "git push → mutating")
check(report.classify_risk("Bash", {"command": "cp foo bar"}) == "mutating", "cp → mutating")
check(report.classify_risk("Bash", {"command": "mkdir -p /tmp/test"}) == "mutating", "mkdir → mutating")

check(report.classify_risk("Bash", {"command": "rm -rf /tmp/test"}) == "destructive", "rm -rf → destructive")
check(report.classify_risk("Bash", {"command": "git clean -f"}) == "destructive", "git clean -f → destructive")
check(report.classify_risk("Bash", {"command": "git push --force"}) == "destructive", "git push --force → destructive")

check(report.classify_risk("Bash", {"command": "find /tmp -name '*.log'"}) == "read-only",
      "find without -delete → read-only")
check(report.classify_risk("Bash", {"command": "find /tmp -name '*.log' -delete"}) == "destructive",
      "find -delete → destructive")
check(report.classify_risk("Bash", {"command": "find /tmp -exec chmod 644 {} +"}) == "mutating",
      "find -exec → mutating")

check(report.classify_risk("Bash", {"command": "sed 's/foo/bar/' file.txt"}) == "read-only",
      "sed without -i → read-only")
check(report.classify_risk("Bash", {"command": "sed -i 's/foo/bar/' file.txt"}) == "mutating",
      "sed -i → mutating")

check(report.classify_risk("Bash", {"command": "curl http://example.com"}) == "read-only",
      "curl GET → read-only")
check(report.classify_risk("Bash", {"command": "curl -X POST http://example.com"}) == "mutating",
      "curl POST → mutating")
check(report.classify_risk("Bash", {"command": "curl -X DELETE http://example.com/resource"}) == "destructive",
      "curl DELETE → destructive")

check(report.classify_risk("Bash", {"command": "ansible-playbook deploy.yml"}) == "mutating",
      "ansible-playbook → mutating")
check(report.classify_risk("Bash", {"command": "ansible-playbook deploy.yml --check"}) == "read-only",
      "ansible-playbook --check → read-only")
check(report.classify_risk("Bash", {"command": "git clean -n"}) == "read-only",
      "git clean --dry-run → read-only")

check(report.classify_risk("Read", {"file_path": "/tmp/file.txt"}) == "read-only", "Read → read-only")
check(report.classify_risk("Write", {"file_path": "/tmp/file.txt"}) == "mutating", "Write → mutating (not in DESTRUCTIVE)")
check(report.classify_risk("Bash", {"command": ""}) == "read-only", "empty command → read-only")
check(report.classify_risk("Bash", {"command": "# comment"}) == "read-only", "comment → read-only")

check(report.classify_risk("mcp__vault__vault_read", {}) == "mutating", "MCP tool → mutating")


# =============================================================================
# Command normalization
# =============================================================================
print("\n=== Command normalization ===")

check(report.normalize_command("ls -la") == "ls", "ls -la → ls")
check(report.normalize_command("git status") == "git status", "git status → git status")
check(report.normalize_command("git add .") == "git add", "git add → git add")
check(report.normalize_command("docker ps -a") == "docker ps", "docker ps → docker ps")
check(report.normalize_command("ssh user@192.168.86.100 uptime") == "ssh 192.168.86.100",
      "ssh strips user@ prefix")
check(report.normalize_command("cd /tmp && ls") == "ls", "cd prefix stripped")
check(report.normalize_command("FOO=bar ls") == "ls", "env prefix stripped")
check(report.normalize_command("") == "(empty)", "empty → (empty)")
check(report.normalize_command("# test") == "(comment/shebang)", "comment → (comment/shebang)")
check(report.normalize_command("/usr/local/bin/my-tool arg") == "my-tool", "path → basename")
check(report.normalize_command("terraform plan") == "terraform plan", "terraform plan preserved")
check(report.normalize_command("npm install express") == "npm install", "npm install preserved")
check(report.normalize_command("ssh -p 2222 host") == "ssh", "ssh with flag → ssh")
check(report.normalize_command("python3 script.py") == "python3 script.py", "python3 preserved")


# =============================================================================
# Pattern parsing and matching
# =============================================================================
print("\n=== Pattern parsing ===")

t, a = report.parse_permission_pattern("Bash(git add *)")
check(t == "Bash" and a == "git add *", "Bash(git add *) parsed")

t, a = report.parse_permission_pattern("Bash(git add:*)")
check(t == "Bash" and a == "git add:*", "Bash(git add:*) parsed")

t, a = report.parse_permission_pattern("Read(**/.env.example)")
check(t == "Read" and a == "**/.env.example", "Read(**/.env.example) parsed")

t, a = report.parse_permission_pattern("mcp__vault__vault_read")
check(t == "mcp__vault__vault_read" and a is None, "bare tool name parsed")

t, a = report.parse_permission_pattern("WebSearch")
check(t == "WebSearch" and a is None, "WebSearch parsed")


print("\n=== Pattern matching ===")

check(report.command_matches_pattern("Bash", {"command": "git add ."}, "Bash(git add *)"),
      "git add . matches Bash(git add *)")
check(report.command_matches_pattern("Bash", {"command": "git add README.md"}, "Bash(git add *)"),
      "git add README.md matches Bash(git add *)")
check(not report.command_matches_pattern("Bash", {"command": "git push"}, "Bash(git add *)"),
      "git push does NOT match Bash(git add *)")
check(not report.command_matches_pattern("Read", {"file_path": "/tmp/x"}, "Bash(ls *)"),
      "tool name mismatch → no match")
check(report.command_matches_pattern("Bash", {"command": "ls -la"}, "Bash(ls *)"),
      "ls -la matches Bash(ls *)")
check(report.command_matches_pattern("Bash", {"command": "cd /tmp && git status --short"}, "Bash(git status *)"),
      "cd prefix stripped for matching")
check(report.command_matches_pattern("Bash", {"command": "git add README.md"}, "Bash(git add:*)"),
      "colon-style pattern matches (: becomes space)")


# =============================================================================
# is_auto_allowed
# =============================================================================
print("\n=== is_auto_allowed ===")

patterns = ["Bash(git status *)", "Bash(ls *)", "Bash(grep *)"]
check(report.is_auto_allowed("Read", {"file_path": "/tmp/x"}, patterns),
      "Read always auto-allowed")
check(report.is_auto_allowed("Bash", {"command": "git status --short"}, patterns),
      "git status --short matches allowlist")
check(report.is_auto_allowed("Bash", {"command": "ls -la"}, patterns),
      "ls matches allowlist")
check(not report.is_auto_allowed("Bash", {"command": "rm -rf /"}, patterns),
      "rm not in allowlist")


# =============================================================================
# suggest_pattern
# =============================================================================
print("\n=== suggest_pattern ===")

check(report.suggest_pattern("Bash: git add") == "Bash(git add *)", "Bash git add suggestion")
check("ssh" in report.suggest_pattern("Bash: ssh 192.168.86.100"), "SSH suggestion contains ssh")
check(report.suggest_pattern("MCP vault: vault_read") == "mcp__vault__vault_read",
      "MCP suggestion correct")
check(report.suggest_pattern("WebSearch") == "WebSearch", "WebSearch suggestion")
check("Edit(" in report.suggest_pattern("Edit: ~/file.txt"), "Edit suggestion uses Edit()")
check("Write(" in report.suggest_pattern("Write: ~/file.txt"), "Write suggestion uses Write()")


# =============================================================================
# suggest_pattern_applicable
# =============================================================================
print("\n=== suggest_pattern_applicable ===")

check(report.suggest_pattern_applicable("Bash: git add") == "Bash(git add *)",
      "simple Bash pattern applicable")
check(report.suggest_pattern_applicable("Bash: ssh 192.168.86.100") is not None,
      "SSH pattern returns second option")
p = report.suggest_pattern_applicable("Bash: ssh 192.168.86.100")
if p:
    check("or" not in p, "applicable pattern has no 'or'")
check(report.suggest_pattern_applicable("MCP vault: vault_read") == "mcp__vault__vault_read",
      "MCP pattern applicable")


# =============================================================================
# shorten_path
# =============================================================================
print("\n=== shorten_path ===")

home = str(report.Path.home())
check(report.shorten_path(f"{home}/autoclaude/file.py") == "~/autoclaude/file.py",
      "home replaced with ~")
check(report.shorten_path("/tmp/file.txt") == "/tmp/file.txt", "non-home path unchanged")


# =============================================================================
# Duration and time helpers
# =============================================================================
print("\n=== Duration and time helpers ===")

check(report._is_duration("7d"), "7d is a duration")
check(report._is_duration("2w"), "2w is a duration")
check(report._is_duration("1m"), "1m is a duration")
check(not report._is_duration("2026-05-01"), "ISO date is not a duration")
check(not report._is_duration("foo"), "arbitrary string is not a duration")
check(not report._is_duration(""), "empty string is not a duration")

check(report._duration_to_days("7d") == 7, "7d → 7 days")
check(report._duration_to_days("2w") == 14, "2w → 14 days")
check(report._duration_to_days("1m") == 30, "1m → 30 days")
check(report._duration_to_days("bad") is None, "invalid → None")

check(report._auto_bucket(7) == "day", "7 days → day bucket")
check(report._auto_bucket(31) == "day", "31 days → day bucket")
check(report._auto_bucket(60) == "week", "60 days → week bucket")
check(report._auto_bucket(90) == "week", "90 days → week bucket")
check(report._auto_bucket(365) == "month", "365 days → month bucket")
check(report._auto_bucket(730) == "month", "730 days → month bucket")
check(report._auto_bucket(1000) == "quarter", "1000 days → quarter bucket")
check(report._auto_bucket(2000) == "year", "2000 days → year bucket")

from datetime import datetime, timezone
ts = report.parse_time_filter("7d")
check(ts is not None, "parse_time_filter('7d') returns datetime")
check(ts.tzinfo is not None, "parse_time_filter result is tz-aware")
ts2 = report.parse_time_filter("2026-05-01")
check(ts2 is not None, "parse_time_filter ISO date returns datetime")
check(ts2.year == 2026 and ts2.month == 5 and ts2.day == 1, "ISO date parsed correctly")


# =============================================================================
# _parse_ts
# =============================================================================
print("\n=== _parse_ts ===")

check(report._parse_ts(None) is None, "None → None")
check(report._parse_ts("") is None, "empty → None")
dt = report._parse_ts("2026-05-08T10:30:00+00:00")
check(dt is not None and dt.year == 2026 and dt.month == 5, "ISO with tz parsed")
dt2 = report._parse_ts("2026-05-08T10:30:00")
check(dt2 is not None, "ISO without tz parsed")


# =============================================================================
# extract_tool_calls_from_assistant
# =============================================================================
print("\n=== extract_tool_calls_from_assistant ===")

content = [
    {"type": "text", "text": "Let me check."},
    {"type": "tool_use", "id": "abc", "name": "Bash", "input": {"command": "ls"}},
    {"type": "tool_use", "id": "def", "name": "Read", "input": {"file_path": "/tmp/x"}},
]
calls = report.extract_tool_calls_from_assistant(content)
check(len(calls) == 2, f"extracted 2 tool calls from 3 content blocks")
check(calls[0]["name"] == "Bash", "first call is Bash")
check(calls[1]["name"] == "Read", "second call is Read")

check(report.extract_tool_calls_from_assistant("not a list") == [], "non-list → []")
check(report.extract_tool_calls_from_assistant([]) == [], "empty list → []")
check(report.extract_tool_calls_from_assistant([{"type": "text"}]) == [], "text only → []")


# =============================================================================
# get_tool_display
# =============================================================================
print("\n=== get_tool_display ===")

check(report.get_tool_display("Bash", {"command": "git status"}) == "Bash: git status",
      "Bash display correct")
check(report.get_tool_display("Read", {"file_path": f"{home}/autoclaude/CLAUDE.md"}).startswith("Read: "),
      "Read display starts with Read:")
check("~/" in report.get_tool_display("Read", {"file_path": f"{home}/autoclaude/CLAUDE.md"}),
      "Read display shortens path")


# =============================================================================
# _is_noise_command
# =============================================================================
print("\n=== _is_noise_command ===")

check(report._is_noise_command("Bash: (empty)"), "(empty) is noise")
check(report._is_noise_command("Bash: (comment/shebang)"), "(comment/shebang) is noise")
check(report._is_noise_command("Bash: -la"), "flag-like is noise")
check(report._is_noise_command("Bash: 192.168.1.1"), "IP address is noise")
check(not report._is_noise_command("Bash: git status"), "git status is not noise")


# =============================================================================
# filter_records
# =============================================================================
print("\n=== filter_records ===")

from datetime import timedelta
now = datetime.now(timezone.utc)
home_slug = report.HOME_SLUG
records = [
    {"timestamp": (now - timedelta(days=1)).isoformat(), "project": f"{home_slug}-proj-a"},
    {"timestamp": (now - timedelta(days=10)).isoformat(), "project": f"{home_slug}-proj-b"},
    {"timestamp": (now - timedelta(days=30)).isoformat(), "project": f"{home_slug}-proj-a"},
]
filtered = report.filter_records(records, since=now - timedelta(days=5))
check(len(filtered) == 1, f"since filter: 1 record within 5 days (got {len(filtered)})")
filtered = report.filter_records(records, project="proj-a")
check(len(filtered) == 2, f"project filter: 2 records for proj-a (got {len(filtered)})")
filtered = report.filter_records(records, since=now - timedelta(days=15), project="proj-a")
check(len(filtered) == 1, f"combined filter: 1 record (got {len(filtered)})")
filtered = report.filter_records(records)
check(len(filtered) == 3, "no filter returns all")


# =============================================================================
# render_json
# =============================================================================
print("\n=== render_json ===")

home_slug_for_records = report.HOME_SLUG
test_records = [
    {
        "timestamp": "2026-05-08T10:00:00+00:00",
        "tool_name": "Bash",
        "tool_input": {"command": "ls"},
        "display": "Bash: ls",
        "risk": "read-only",
        "auto_allowed": True,
        "prompted": False,
        "rejected": False,
        "project": f"{home_slug_for_records}-test",
    },
    {
        "timestamp": "2026-05-08T10:01:00+00:00",
        "tool_name": "Bash",
        "tool_input": {"command": "git push origin main"},
        "display": "Bash: git push",
        "risk": "mutating",
        "auto_allowed": False,
        "prompted": True,
        "rejected": False,
        "project": f"{home_slug_for_records}-test",
    },
]
buf = io.StringIO()
import json
report.render_json(test_records, out=buf)
output = json.loads(buf.getvalue())
check(isinstance(output, dict), "JSON output is a dict")
check("summary" in output, "JSON has summary key")
check(output["summary"]["total"] == 2, "JSON summary has correct total")
check(output["summary"]["auto_allowed"] == 1, "JSON summary has correct auto_allowed count")


# =============================================================================
# render_summary
# =============================================================================
print("\n=== render_summary ===")

buf = io.StringIO()
report.render_summary(test_records, out=buf)
summary = buf.getvalue()
check("APPROVAL SUMMARY" in summary, "summary has header")
check("auto" in summary.lower(), "summary mentions auto-allowed")


# =============================================================================
# render_trend
# =============================================================================
print("\n=== render_trend ===")

trend_records = []
for i in range(10):
    trend_records.append({
        "timestamp": (now - timedelta(days=i)).isoformat(),
        "tool_name": "Bash",
        "tool_input": {"command": "ls"},
        "display": "Bash: ls",
        "risk": "read-only",
        "auto_allowed": i % 3 != 0,
        "prompted": i % 3 == 0,
        "rejected": False,
        "project": f"{home_slug_for_records}-test",
    })

buf = io.StringIO()
report.render_trend(trend_records, bucket="day", out=buf)
trend_out = buf.getvalue()
check(len(trend_out) > 0, "trend output is non-empty")
check("TREND ANALYSIS" in trend_out, "trend has header")


# =============================================================================
# Token-attribution: read target normalization
# =============================================================================
print("\n=== Read target normalization ===")
home = os.path.expanduser("~")
check(report._normalize_read_target(home + "/autoclaude/x.py") == "~/autoclaude/x.py", "home -> ~")
check(report._normalize_read_target("/etc/passwd") == "/etc/passwd", "non-home path unchanged")
check(report._normalize_read_target("") == "", "empty -> empty")
check(report._normalize_read_target(None) == "", "None -> empty")


# =============================================================================
# Token-attribution: URL normalization
# =============================================================================
print("\n=== URL normalization ===")
check(report._normalize_url("HTTPS://Example.COM/path") == "https://example.com/path", "scheme+host lowercased")
check(report._normalize_url("https://example.com/x?q=1") == "https://example.com/x", "query stripped")
check(report._normalize_url("https://example.com/x#frag") == "https://example.com/x", "fragment stripped")
check(report._normalize_url("https://example.com/x?q=1#frag") == "https://example.com/x", "query+fragment stripped")
check(report._normalize_url("") == "", "empty -> empty")
check(report._normalize_url("not-a-url") == "not-a-url", "non-URL passes through")


# =============================================================================
# Token-attribution: input target extraction (dispatch)
# =============================================================================
print("\n=== Input target extraction ===")
check(report._extract_input_target("Read", {"file_path": home + "/x.py"}) == "~/x.py", "Read -> normalized path")
check(report._extract_input_target("Write", {"file_path": "/tmp/x"}) == "/tmp/x", "Write -> path")
check(report._extract_input_target("Edit", {"file_path": "/tmp/x"}) == "/tmp/x", "Edit -> path")
check(report._extract_input_target("WebFetch", {"url": "https://Example.com/?q=1"}) == "https://example.com/", "WebFetch -> normalized URL")
check(report._extract_input_target("Bash", {"command": "git status"}) == "git status", "Bash -> normalized command")
check(report._extract_input_target("WebSearch", {"query": "anything"}) == "", "WebSearch -> empty (no target)")
check(report._extract_input_target("Read", {}) == "", "missing field -> empty")
check(report._extract_input_target("Read", "not-a-dict") == "", "non-dict input -> empty")


# =============================================================================
# Token-attribution: result byte counting
# =============================================================================
print("\n=== Result byte counting ===")
check(report._compute_result_bytes({"stdout": "abc", "stderr": "de"}, None) == 5, "Bash dict stdout+stderr")
check(report._compute_result_bytes({"stdout": "abc"}, None) == 3, "Bash dict stdout only")
check(report._compute_result_bytes("hello", None) == 5, "string toolUseResult")
check(report._compute_result_bytes(None, "from-msg") == 8, "fallback to string msg.content")
check(report._compute_result_bytes(None, [{"type": "tool_result", "content": "abcdef"}]) == 6, "fallback to list msg.content (str)")
check(report._compute_result_bytes(None, [{"type": "tool_result", "content": [{"type": "text", "text": "abcd"}]}]) == 4, "fallback to list msg.content (list of text)")
check(report._compute_result_bytes(None, None) == 0, "no source -> 0")
check(report._compute_result_bytes({}, None) == 0, "empty dict -> 0")
check(report._compute_result_bytes({"interrupted": False, "stdout": "x"}, None) == 1, "ignores non-string fields")


# =============================================================================
# Token-attribution: byte->token fallback
# =============================================================================
print("\n=== Byte to token fallback ===")
check(report._estimate_tokens_from_bytes(0) == 0, "zero bytes -> 0 tokens")
check(report._estimate_tokens_from_bytes(4) == 1, "4 bytes -> 1 token")
check(report._estimate_tokens_from_bytes(100) == 25, "100 bytes -> 25 tokens")
check(report._estimate_tokens_from_bytes(-5) == 0, "negative clamped to 0")


# =============================================================================
# Token-attribution: proportional split + cap behavior
# =============================================================================
print("\n=== Token attribution (attribute_tool_result_tokens) ===")

# Single tool, modest delta below cap: gets full delta
recs = [{"_turn_uuid": "A", "_result_bytes": 3000}]
report.attribute_tool_result_tokens(recs, {"A": {}, "B": {"cache_creation_input_tokens": 500}}, ["A", "B"])
check(recs[0]["_result_tokens_est"] == 500, f"single tool, delta below cap -> 500 (got {recs[0]['_result_tokens_est']})")
check(recs[0]["_token_estimate_method"] == "usage_delta", "method=usage_delta when no cap")

# Single tool, delta above cap (cap = bytes/3 = 100): capped
recs = [{"_turn_uuid": "A", "_result_bytes": 300}]
report.attribute_tool_result_tokens(recs, {"A": {}, "B": {"cache_creation_input_tokens": 50000}}, ["A", "B"])
check(recs[0]["_result_tokens_est"] == 100, f"capped at bytes/3=100 (got {recs[0]['_result_tokens_est']})")
check(recs[0]["_token_estimate_method"] == "usage_delta_capped", "method=usage_delta_capped")

# Two tools in parallel, proportional split by bytes
recs = [
    {"_turn_uuid": "A", "_result_bytes": 9000},
    {"_turn_uuid": "A", "_result_bytes": 3000},
]
report.attribute_tool_result_tokens(recs, {"A": {}, "B": {"cache_creation_input_tokens": 1200}}, ["A", "B"])
check(recs[0]["_result_tokens_est"] == 900, f"75% share -> 900 (got {recs[0]['_result_tokens_est']})")
check(recs[1]["_result_tokens_est"] == 300, f"25% share -> 300 (got {recs[1]['_result_tokens_est']})")

# Last turn has no next-turn delta -> char/4 fallback
recs = [{"_turn_uuid": "Z", "_result_bytes": 400}]
report.attribute_tool_result_tokens(recs, {"Z": {}}, ["Z"])
check(recs[0]["_result_tokens_est"] == 100, f"last turn fallback char/4 -> 100 (got {recs[0]['_result_tokens_est']})")
check(recs[0]["_token_estimate_method"] == "char_div_4", "method=char_div_4 when last")

# Missing usage on next turn -> fallback
recs = [{"_turn_uuid": "A", "_result_bytes": 200}]
report.attribute_tool_result_tokens(recs, {"A": {}, "B": {}}, ["A", "B"])
check(recs[0]["_token_estimate_method"] == "char_div_4", "no cache_creation -> char/4 fallback")
check(recs[0]["_result_tokens_est"] == 50, "200 bytes -> 50 tokens fallback")

# Zero bytes + delta -> even split with usage_delta
recs = [
    {"_turn_uuid": "A", "_result_bytes": 0},
    {"_turn_uuid": "A", "_result_bytes": 0},
]
report.attribute_tool_result_tokens(recs, {"A": {}, "B": {"cache_creation_input_tokens": 100}}, ["A", "B"])
check(recs[0]["_result_tokens_est"] == 50 and recs[1]["_result_tokens_est"] == 50, "zero-bytes splits evenly")

# Records without _turn_uuid are ignored, not crashed
recs = [{"_result_bytes": 100}, {"_turn_uuid": "A", "_result_bytes": 100}]
report.attribute_tool_result_tokens(recs, {"A": {}}, ["A"])
check("_result_tokens_est" not in recs[0], "record without turn_uuid is skipped")
check(recs[1]["_token_estimate_method"] == "char_div_4", "tagged record is processed")


# =============================================================================
# Prose extraction: boilerplate stripping
# =============================================================================
print("\n=== Prose boilerplate stripping ===")
out = report._strip_prose_boilerplate("hello <system-reminder>noise</system-reminder> world")
check(out == "hello  world", f"system-reminder stripped (got {out!r})")
out = report._strip_prose_boilerplate("<command-name>foo</command-name>real text")
check(out == "real text", f"command-name stripped (got {out!r})")
out = report._strip_prose_boilerplate("<system-reminder>line1\nline2</system-reminder>kept")
check(out == "kept", f"multi-line system-reminder stripped (got {out!r})")
check(report._strip_prose_boilerplate("") == "", "empty -> empty")
check(report._strip_prose_boilerplate(None) == "", "None -> empty")
check(report._strip_prose_boilerplate("plain text") == "plain text", "plain text unchanged")


# =============================================================================
# Phase 2: annotate_next_turn_output
# =============================================================================
print("\n=== annotate_next_turn_output ===")
recs = [
    {"_turn_uuid": "A"},
    {"_turn_uuid": "B"},
]
report.annotate_next_turn_output(
    recs,
    {"A": {"output_tokens": 100}, "B": {"output_tokens": 50}},
    ["A", "B"],
)
check(recs[0]["_next_turn_output_tokens"] == 50, "turn A sees turn B output")
check(recs[1]["_next_turn_output_tokens"] == 0, "last turn -> 0")

# Records without turn_uuid are ignored without crashing
recs2 = [{"foo": "bar"}, {"_turn_uuid": "X"}]
report.annotate_next_turn_output(recs2, {"X": {"output_tokens": 10}}, ["X"])
check("_next_turn_output_tokens" not in recs2[0], "no turn_uuid -> no annotation")
check(recs2[1]["_next_turn_output_tokens"] == 0, "last turn fallback")


# =============================================================================
# Phase 2 Pattern A: find_repeated_reads
# =============================================================================
print("\n=== find_repeated_reads ===")

def _read_record(session, target, tokens, ts="2026-05-15T00:00:00Z", tool="Read"):
    return {
        "tool_name": tool, "session": session, "_input_target": target,
        "_result_tokens_est": tokens, "_kind": None, "timestamp": ts,
    }

# Below thresholds: not flagged
recs = [_read_record(f"s{i}", "~/x.py", 1000) for i in range(2)]
out = report.find_repeated_reads(recs, min_sessions=3, min_tokens=5000)
check(out == [], "2 sessions doesn't meet min_sessions=3")

# Meets sessions but not tokens
recs = [_read_record(f"s{i}", "~/x.py", 100) for i in range(3)]
out = report.find_repeated_reads(recs, min_sessions=3, min_tokens=5000)
check(out == [], "3 sessions, 300 tokens doesn't meet min_tokens=5000")

# Meets both
recs = [_read_record(f"s{i}", "~/x.py", 2000) for i in range(3)]
out = report.find_repeated_reads(recs, min_sessions=3, min_tokens=5000)
check(len(out) == 1 and out[0]["target"] == "~/x.py", "meets both -> finding")
check(out[0]["sum_tokens"] == 6000 and out[0]["occurrences"] == 3, "sum_tokens=6000 occ=3")
check(out[0]["distinct_sessions"] == 3, "distinct_sessions=3")
check(out[0]["kind"] == "repeated_read", "kind=repeated_read")
check(out[0]["avg_tokens"] == 2000, "avg_tokens=2000")

# WebFetch produces repeated_webfetch kind
recs = [_read_record(f"s{i}", "https://x.com/", 3000, tool="WebFetch") for i in range(3)]
out = report.find_repeated_reads(recs)
check(out[0]["kind"] == "repeated_webfetch", "WebFetch -> repeated_webfetch kind")

# Empty target ignored
recs = [_read_record(f"s{i}", "", 5000) for i in range(5)]
out = report.find_repeated_reads(recs)
check(out == [], "empty target ignored")

# Other tools ignored
recs = [{"tool_name": "Bash", "session": f"s{i}", "_input_target": "ls",
         "_result_tokens_est": 5000, "timestamp": "2026-05-15T00:00:00Z"} for i in range(5)]
out = report.find_repeated_reads(recs)
check(out == [], "Bash records ignored")

# Prose records ignored
recs = [{"_kind": "prose", "tool_name": None, "session": f"s{i}",
         "_input_target": "~/x.py", "_result_tokens_est": 5000} for i in range(5)]
out = report.find_repeated_reads(recs)
check(out == [], "prose records ignored")

# Sorted by sum_tokens descending
recs = (
    [_read_record(f"a{i}", "~/big", 3000) for i in range(3)] +
    [_read_record(f"b{i}", "~/small", 2000) for i in range(3)]
)
out = report.find_repeated_reads(recs, min_tokens=5000)
check(out[0]["target"] == "~/big" and out[1]["target"] == "~/small", "sorted by sum_tokens desc")

# Sample sessions truncated to 5
recs = [_read_record(f"s{i}", "~/x", 1000) for i in range(8)]
out = report.find_repeated_reads(recs, min_tokens=5000)
check(len(out[0]["sample_session_ids"]) == 5, "sample_session_ids capped at 5")


# =============================================================================
# Phase 2 Pattern B: find_recipe_ngrams
# =============================================================================
print("\n=== find_recipe_ngrams ===")

def _step_rec(session, tool, target, idx, ts_minute=0):
    return {
        "tool_name": tool, "session": session, "project": "p",
        "_input_target": target, "_turn_index": idx,
        "_result_tokens_est": 100,
        "timestamp": f"2026-05-15T00:{ts_minute:02d}:00Z",
    }

# Build same Read-Edit-Read recipe across 3 sessions, 6 times each = 18 occurrences
recs = []
for s in ("s1", "s2", "s3"):
    for cycle in range(6):
        base = cycle * 3
        recs.append(_step_rec(s, "Read", "~/a", base + 0, base))
        recs.append(_step_rec(s, "Edit", "~/a", base + 1, base))
        recs.append(_step_rec(s, "Read", "~/a", base + 2, base))
out = report.find_recipe_ngrams(recs, min_occurrences=5, min_sessions=2)
# After collapse_runs the sequence is Read,Edit,Read,Edit,Read,Edit,...
check(any("Read → Edit → Read" in f["target"] for f in out), "Read→Edit→Read recipe found")

# Single-step n-gram (A,A,A) rejected
recs = []
for s in ("s1", "s2", "s3"):
    for i in range(15):
        recs.append(_step_rec(s, "Read", "~/x", i, i))
out = report.find_recipe_ngrams(recs, min_occurrences=3, min_sessions=2)
check(out == [], "all-same-step n-gram rejected (collapses to 1 distinct)")

# Idle gap segmentation: gap > 10 min splits sequences
recs = []
# Session with two segments: [Read,Edit,Read] then 11min gap then [Read,Edit,Read]
seq_a = [("Read","~/a",0,0), ("Edit","~/a",1,0), ("Read","~/a",2,0)]
seq_b = [("Read","~/b",3,11), ("Edit","~/b",4,11), ("Read","~/b",5,11)]
for tool, tgt, idx, mn in seq_a + seq_b:
    recs.append(_step_rec("s1", tool, tgt, idx, mn))
# Add same pattern in 2 more sessions to meet min_occurrences=2
for s in ("s2", "s3"):
    for tool, tgt, idx, mn in seq_a + seq_b:
        recs.append(_step_rec(s, tool, tgt, idx, mn))
out = report.find_recipe_ngrams(recs, min_occurrences=3, min_sessions=2)
# Each session contributes 2 segments × the same 3-step recipe = 6 occurrences across 3 sessions
check(any("Read → Edit → Read" in f["target"] for f in out), "idle-gap segments still produce ngrams")

# All-safe-allow rejection: cat→ls→pwd should be filtered
recs = []
for s in ("s1", "s2", "s3"):
    for cycle in range(6):
        base = cycle * 3
        recs.append(_step_rec(s, "Bash", "cat", base + 0, base))
        recs.append(_step_rec(s, "Bash", "ls",  base + 1, base))
        recs.append(_step_rec(s, "Bash", "pwd", base + 2, base))
out = report.find_recipe_ngrams(recs, min_occurrences=3, min_sessions=2)
check(out == [], "all-baseline-safe-allow chain rejected")

# Below min_occurrences: not flagged
recs = []
for s in ("s1", "s2"):
    recs.append(_step_rec(s, "Read", "~/a", 0, 0))
    recs.append(_step_rec(s, "Edit", "~/a", 1, 0))
    recs.append(_step_rec(s, "Read", "~/a", 2, 0))
out = report.find_recipe_ngrams(recs, min_occurrences=5, min_sessions=2)
check(out == [], "1 occ per session, 2 sessions < min_occurrences=5")

# Single session: rejected by min_sessions
recs = []
for cycle in range(10):
    base = cycle * 3
    recs.append(_step_rec("s1", "Read", "~/a", base+0, base))
    recs.append(_step_rec("s1", "Edit", "~/a", base+1, base))
    recs.append(_step_rec("s1", "Read", "~/a", base+2, base))
out = report.find_recipe_ngrams(recs, min_occurrences=3, min_sessions=2)
check(out == [], "single session rejected by min_sessions=2")

# Empty input
check(report.find_recipe_ngrams([]) == [], "empty records -> []")

# Run-collapsing: A,A,B,B,C
check(report._collapse_runs(["A","A","B","B","C"]) == ["A","B","C"], "_collapse_runs basic")
check(report._collapse_runs([]) == [], "_collapse_runs empty")
check(report._collapse_runs(["X"]) == ["X"], "_collapse_runs single")


# =============================================================================
# Phase 2 Pattern C: find_repeated_prose
# =============================================================================
print("\n=== find_repeated_prose ===")

def _prose_rec(session, text):
    return {"_kind": "prose", "session": session, "text": text, "_char_len": len(text)}

para = "Hello world. " * 50  # ~650 chars
recs = [_prose_rec(f"s{i}", para) for i in range(3)]
out = report.find_repeated_prose(recs, min_occurrences=3, min_chars=400)
check(len(out) == 1, f"3 identical paragraphs -> 1 finding (got {len(out)})")
check(out[0]["occurrences"] == 3 and out[0]["distinct_sessions"] == 3, "occ=3 sessions=3")

# Short paragraphs ignored
recs = [_prose_rec(f"s{i}", "short.") for i in range(5)]
out = report.find_repeated_prose(recs, min_chars=400)
check(out == [], "short paragraphs ignored")

# Below min_occurrences
recs = [_prose_rec(f"s{i}", para) for i in range(2)]
out = report.find_repeated_prose(recs, min_occurrences=3, min_chars=400)
check(out == [], "below min_occurrences -> []")

# Numeric tokens normalized: same paragraph differing only in numbers should cluster
para_with_dates = "Today is " + "2026-05-15. " * 50
recs = []
for s, ymd in [("s1", "2026-05-15"), ("s2", "2026-06-20"), ("s3", "2027-01-01")]:
    recs.append(_prose_rec(s, "Today is " + (ymd + ". ") * 50))
out = report.find_repeated_prose(recs, min_occurrences=3, min_chars=400)
check(len(out) == 1, "date variants normalize to same hash")

# Non-prose records ignored
recs = [{"_kind": "tool_call", "session": "s1", "text": para}]
out = report.find_repeated_prose(recs, min_chars=400)
check(out == [], "non-prose ignored")

# Multi-paragraph splits on blank lines
multi = para + "\n\n" + ("Other long paragraph. " * 50)
recs = [_prose_rec(f"s{i}", multi) for i in range(3)]
out = report.find_repeated_prose(recs, min_occurrences=3, min_chars=400)
check(len(out) == 2, f"2 distinct paragraphs -> 2 findings (got {len(out)})")

# Empty input
check(report.find_repeated_prose([]) == [], "empty records -> []")

# _normalize_prose_text spot checks
check(report._normalize_prose_text("Hello   World") == "hello world", "whitespace collapsed")
check(report._normalize_prose_text("ID 12345 here") == "id <N> here", "numbers replaced")
check(report._normalize_prose_text("") == "", "empty -> empty")
check(report._normalize_prose_text(None) == "", "None -> empty")


# =============================================================================
# Phase 2 Pattern D: find_resummarized_outputs
# =============================================================================
print("\n=== find_resummarized_outputs ===")

def _output_rec(session, target, bytes_, est_tokens, next_out_tokens, tool="Read"):
    return {
        "tool_name": tool, "session": session, "_input_target": target,
        "_result_bytes": bytes_, "_result_tokens_est": est_tokens,
        "_next_turn_output_tokens": next_out_tokens,
    }

# Large output, tiny next-turn summary -> flagged
recs = [_output_rec(f"s{i}", "~/big", 50000, 12000, 500) for i in range(3)]
out = report.find_resummarized_outputs(recs, min_bytes=8000, max_narrow_ratio=0.25, min_occurrences=3)
check(len(out) == 1 and out[0]["target"] == "~/big", "large output + tiny summary flagged")
check(out[0]["_raw"]["narrow_ratio"] < 0.25, f"narrow_ratio < 0.25 (got {out[0]['_raw']['narrow_ratio']})")

# Below min_bytes
recs = [_output_rec(f"s{i}", "~/small", 1000, 250, 10) for i in range(3)]
out = report.find_resummarized_outputs(recs, min_bytes=8000)
check(out == [], "below min_bytes ignored")

# Ratio above threshold (large output, large summary too)
recs = [_output_rec(f"s{i}", "~/x", 50000, 12000, 8000) for i in range(3)]
out = report.find_resummarized_outputs(recs, max_narrow_ratio=0.25)
check(out == [], "ratio above threshold not flagged")

# Below min_occurrences
recs = [_output_rec(f"s{i}", "~/x", 50000, 12000, 100) for i in range(2)]
out = report.find_resummarized_outputs(recs, min_occurrences=3)
check(out == [], "below min_occurrences not flagged")

# Zero next_out_tokens (no following turn) -> skipped
recs = [_output_rec(f"s{i}", "~/x", 50000, 12000, 0) for i in range(5)]
out = report.find_resummarized_outputs(recs)
check(out == [], "zero next_out skipped")

# Zero result_tokens_est -> skipped (would div by zero)
recs = [_output_rec(f"s{i}", "~/x", 50000, 0, 100) for i in range(5)]
out = report.find_resummarized_outputs(recs)
check(out == [], "zero result_tokens skipped")

# Prose records skipped
recs = [{"_kind": "prose", "session": f"s{i}", "_input_target": "x", "_result_bytes": 50000,
         "_result_tokens_est": 12000, "_next_turn_output_tokens": 100} for i in range(5)]
out = report.find_resummarized_outputs(recs)
check(out == [], "prose records skipped")

# Aggregation: same target across 3 sessions
recs = [_output_rec(f"s{i}", "~/big", 50000, 12000, 500) for i in range(3)]
out = report.find_resummarized_outputs(recs, min_occurrences=3)
check(out[0]["distinct_sessions"] == 3, "distinct_sessions counted across records")
check(out[0]["sum_tokens"] == 36000, "sum_tokens aggregated")


# =============================================================================
# Phase 3: stability factor mapping
# =============================================================================
print("\n=== _stability_from_commit_count ===")
check(report._stability_from_commit_count(0) == 1.0, "0 commits -> 1.0")
check(report._stability_from_commit_count(1) == 0.8, "1 commit -> 0.8")
check(report._stability_from_commit_count(3) == 0.8, "3 commits -> 0.8")
check(report._stability_from_commit_count(4) == 0.5, "4 commits -> 0.5")
check(report._stability_from_commit_count(10) == 0.5, "10 commits -> 0.5")
check(report._stability_from_commit_count(11) == 0.25, "11 commits -> 0.25")
check(report._stability_from_commit_count(30) == 0.25, "30 commits -> 0.25")
check(report._stability_from_commit_count(31) == 0.1, "31 commits -> 0.1")
check(report._stability_from_commit_count(999) == 0.1, "999 commits -> 0.1")


# =============================================================================
# Phase 3: mtime-based stability
# =============================================================================
print("\n=== _stability_from_mtime ===")
import time as _t
now = _t.time()
check(report._stability_from_mtime(now - 3 * 86400) == 0.5, "3 days old -> 0.5")
check(report._stability_from_mtime(now - 14 * 86400) == 0.7, "14 days old -> 0.7")
check(report._stability_from_mtime(now - 60 * 86400) == 1.0, "60 days old -> 1.0")


# =============================================================================
# Phase 3: target path resolution
# =============================================================================
print("\n=== _resolve_target_path ===")
home = os.path.expanduser("~")
check(report._resolve_target_path("~/x.py") == home + "/x.py", "~ expansion")
check(report._resolve_target_path("/etc/passwd") == "/etc/passwd", "absolute path passthrough")
check(report._resolve_target_path("relative") is None, "relative -> None")
check(report._resolve_target_path("") is None, "empty -> None")
check(report._resolve_target_path(None) is None, "None -> None")
check(report._resolve_target_path("https://x.com/") is None, "URL -> None")


# =============================================================================
# Phase 3: compute_stability_factor dispatch (no subprocess for these branches)
# =============================================================================
print("\n=== compute_stability_factor (kind dispatch) ===")
check(report.compute_stability_factor("anything", "repeated_prose") == 1.0, "prose -> 1.0")
check(report.compute_stability_factor("https://x.com/", "repeated_webfetch") == 0.7, "webfetch -> 0.7")
check(report.compute_stability_factor("Read → Edit", "recipe_ngram") == 1.0, "recipe -> 1.0")
check(report.compute_stability_factor("not-a-path", "repeated_read") == 0.7, "unresolvable target -> 0.7")
check(report.compute_stability_factor("/nonexistent/file/here", "repeated_read") == 0.7, "missing file (no git result) -> 0.7")


# =============================================================================
# Phase 3: _git_commit_count with mocked subprocess
# =============================================================================
print("\n=== _git_commit_count (mocked) ===")
report._git_commit_count.cache_clear()


class _MockResult:
    def __init__(self, returncode, stdout):
        self.returncode = returncode
        self.stdout = stdout
        self.stderr = ""


with unittest.mock.patch.object(report.subprocess, "run") as mock_run:
    mock_run.return_value = _MockResult(0, "abc def\nghi jkl\nmno pqr\n")
    n = report._git_commit_count("/tmp/fake-test-path-1.txt")
    check(n == 3, f"3 lines -> count 3 (got {n})")

report._git_commit_count.cache_clear()
with unittest.mock.patch.object(report.subprocess, "run") as mock_run:
    mock_run.return_value = _MockResult(0, "")
    n = report._git_commit_count("/tmp/fake-test-path-2.txt")
    check(n == 0, "empty stdout -> count 0")

report._git_commit_count.cache_clear()
with unittest.mock.patch.object(report.subprocess, "run") as mock_run:
    mock_run.return_value = _MockResult(128, "")  # not a git repo
    n = report._git_commit_count("/tmp/fake-test-path-3.txt")
    check(n is None, "non-zero returncode -> None")

report._git_commit_count.cache_clear()
with unittest.mock.patch.object(report.subprocess, "run") as mock_run:
    import subprocess as _sub
    mock_run.side_effect = _sub.TimeoutExpired("git", 2)
    n = report._git_commit_count("/tmp/fake-test-path-4.txt")
    check(n is None, "subprocess timeout -> None")

report._git_commit_count.cache_clear()
with unittest.mock.patch.object(report.subprocess, "run") as mock_run:
    mock_run.side_effect = FileNotFoundError("git not installed")
    n = report._git_commit_count("/tmp/fake-test-path-5.txt")
    check(n is None, "git missing -> None")

report._git_commit_count.cache_clear()
n = report._git_commit_count("")
check(n is None, "empty path -> None (no subprocess)")


# =============================================================================
# Phase 3: score_finding
# =============================================================================
print("\n=== score_finding ===")
check(report.score_finding({"occurrences": 10, "avg_tokens": 100}, 1.0) == 1000, "stable -> full score")
check(report.score_finding({"occurrences": 10, "avg_tokens": 100}, 0.1) == 100, "volatile -> 10x discount")
check(report.score_finding({"occurrences": 10, "avg_tokens": 100}, 0.5) == 500, "mid -> half")
check(report.score_finding({"occurrences": 0, "avg_tokens": 100}, 1.0) == 0, "zero occ -> 0")
check(report.score_finding({}, 1.0) == 0, "empty finding -> 0")
# Floor: stability < 0.1 clamps to 0.1 (defensive)
check(report.score_finding({"occurrences": 10, "avg_tokens": 100}, 0.05) == 100, "below 0.1 floor")


# =============================================================================
# Phase 3: rank_findings (full pipeline w/ mocked git)
# =============================================================================
print("\n=== rank_findings ===")
report._git_commit_count.cache_clear()
findings = [
    # Volatile: should drop to bottom
    {"kind": "repeated_read", "target": "/tmp/volatile.py",
     "occurrences": 100, "avg_tokens": 1000, "distinct_sessions": 5,
     "sum_tokens": 100000, "sample_session_ids": [], "_raw": {}},
    # Stable file: full credit
    {"kind": "repeated_read", "target": "/tmp/stable.py",
     "occurrences": 50, "avg_tokens": 1000, "distinct_sessions": 5,
     "sum_tokens": 50000, "sample_session_ids": [], "_raw": {}},
    # Recipe: always 1.0
    {"kind": "recipe_ngram", "target": "Read -> Edit",
     "occurrences": 60, "avg_tokens": 800, "distinct_sessions": 5,
     "sum_tokens": 48000, "sample_session_ids": [], "_raw": {"n": 2}},
]


def _mock_run(cmd, **kwargs):
    if "/tmp/volatile.py" in cmd:
        return _MockResult(0, "\n".join("c" * 50) + "\n")  # 50 commits -> 0.1
    if "/tmp/stable.py" in cmd:
        return _MockResult(0, "")  # 0 commits -> 1.0
    return _MockResult(128, "")


with unittest.mock.patch.object(report.subprocess, "run", side_effect=_mock_run):
    ranked = report.rank_findings(findings)

# Annotations applied
check(all("_stability_factor" in f for f in ranked), "all findings annotated with _stability_factor")
check(all("_score" in f for f in ranked), "all findings annotated with _score")
# Scores: stable=50000, volatile=10000, recipe=48000 -> stable > recipe > volatile
check(ranked[0]["target"] == "/tmp/stable.py", f"stable file ranks #1 (got {ranked[0]['target']})")
check(ranked[2]["target"] == "/tmp/volatile.py", f"volatile file ranks last (got {ranked[2]['target']})")
check(ranked[0]["_stability_factor"] == 1.0, "stable factor 1.0")
check(ranked[2]["_stability_factor"] == 0.1, "volatile factor 0.1")

report._git_commit_count.cache_clear()


# =============================================================================
# Phase 4: suggestion dispatch
# =============================================================================
print("\n=== _suggestion_headline / _suggestion_type / _suggestion_body ===")

def _f(kind, target="t", n=3):
    return {"kind": kind, "target": target, "_raw": {"n": n, "steps": ["A", "B"], "exemplar_full": "x", "narrow_ratio": 0.1, "avg_input_bytes": 10000}}

check(report._suggestion_type(_f("repeated_read")) == "reference_md", "type: reference_md")
check(report._suggestion_type(_f("repeated_webfetch")) == "reference_md_external", "type: reference_md_external")
check(report._suggestion_type(_f("recipe_ngram", n=3)) == "slash_command", "type: slash_command for n=3")
check(report._suggestion_type(_f("recipe_ngram", n=5)) == "skill", "type: skill for n>=5")
check(report._suggestion_type(_f("repeated_prose")) == "claude_md_addition", "type: claude_md_addition")
check(report._suggestion_type(_f("resummarized_output")) == "wrapper_script", "type: wrapper_script")
check(report._suggestion_type(_f("unknown")) == "", "type: unknown -> empty")

check("slash command" in report._suggestion_headline(_f("recipe_ngram", n=3)), "headline: slash command for n=3")
check("skill" in report._suggestion_headline(_f("recipe_ngram", n=5)), "headline: skill for n=5")
check(".claude/refs/" in report._suggestion_headline(_f("repeated_read")), "headline: refs for read")

check(".claude/refs/" in report._suggestion_body(_f("repeated_read", target="~/x.py")), "body: read mentions refs/")
check("CLAUDE.md" in report._suggestion_body(_f("repeated_prose")), "body: prose mentions CLAUDE.md")
check("scripts/" in report._suggestion_body(_f("resummarized_output", target="~/x")), "body: resummarized mentions scripts/")
check("snapshot" in report._suggestion_body(_f("repeated_webfetch", target="https://x")), "body: webfetch mentions snapshot")
body = report._suggestion_body(_f("recipe_ngram", n=5))
check("skills/" in body, "body: 5+ step recipe -> skill path")


# =============================================================================
# Phase 4: _compute_token_findings
# =============================================================================
print("\n=== _compute_token_findings ===")

# Build records that trigger Pattern A
recs = [{"tool_name": "Read", "session": f"s{i}", "_input_target": "~/x.py",
         "_result_tokens_est": 5000, "timestamp": "2026-05-15T00:00:00Z"} for i in range(3)]
out = report._compute_token_findings(recs, [])
check(len(out) >= 1, "produces at least one finding")
check(all("_score" in f and "_stability_factor" in f for f in out), "findings are ranked (have _score + _stability_factor)")

# top=N truncates
recs_many = []
for j in range(10):
    for i in range(3):
        recs_many.append({"tool_name": "Read", "session": f"s{j}_{i}",
                          "_input_target": f"~/file{j}.py", "_result_tokens_est": 5000,
                          "timestamp": "2026-05-15T00:00:00Z"})
out = report._compute_token_findings(recs_many, [], top=5)
check(len(out) == 5, f"top=5 truncates (got {len(out)})")

# top=None returns all
out = report._compute_token_findings(recs_many, [], top=None)
check(len(out) >= 5, "top=None returns all findings")

# Empty input is graceful
check(report._compute_token_findings([], []) == [], "empty input -> []")
check(report._compute_token_findings([], None) == [], "None prose -> []")


# =============================================================================
# Phase 4: render_token_report (text)
# =============================================================================
print("\n=== render_token_report (text) ===")

# Empty report
buf = io.StringIO()
report.render_token_report([], [], top=10, out=buf)
out_text = buf.getvalue()
check("CLAUDE CODE TOKEN-CONSUMPTION REPORT" in out_text, "header rendered")
check("No findings above threshold" in out_text, "empty -> no-findings line")

# With findings
recs = []
for j in range(4):
    for i in range(3):
        recs.append({"tool_name": "Read", "session": f"s{j}_{i}",
                     "_input_target": f"~/file{j}.py", "_result_tokens_est": 3000,
                     "timestamp": "2026-05-15T00:00:00Z"})
buf = io.StringIO()
report.render_token_report(recs, [], top=10, detail_top=2, out=buf)
out_text = buf.getvalue()
check("Records scanned:" in out_text, "scanned line present")
check("repeated_read" in out_text, "kind appears in table")
check("DETAILS (top 2)" in out_text, "DETAILS section labelled with detail_top")
check(out_text.count("[1]") >= 1 and out_text.count("[2]") >= 1, "detail entries [1] and [2]")
# Header columns present
for col in ("KIND", "OCC", "SESS", "AVG_TOK", "SCORE", "STAB", "TARGET", "SUGGESTION"):
    check(col in out_text, f"header has {col}")

# Long target truncated with ellipsis
recs_long = [{"tool_name": "Read", "session": f"s{i}",
              "_input_target": "/very/long/path/" + "x" * 100,
              "_result_tokens_est": 3000, "timestamp": "2026-05-15T00:00:00Z"} for i in range(3)]
buf = io.StringIO()
report.render_token_report(recs_long, [], out=buf)
check("…" in buf.getvalue(), "long target truncated with ellipsis")


# =============================================================================
# Phase 4: render_token_report_json
# =============================================================================
print("\n=== render_token_report_json ===")
import json as _json

# Empty
buf = io.StringIO()
report.render_token_report_json([], [], out=buf)
payload = _json.loads(buf.getvalue())
check("generated_at" in payload, "JSON has generated_at")
check("filters" in payload and "summary" in payload and "findings" in payload, "JSON has top-level keys")
check(payload["findings"] == [], "empty findings list")

# With findings
buf = io.StringIO()
report.render_token_report_json(recs, [], top=5, filters={"project": "p"}, out=buf)
payload = _json.loads(buf.getvalue())
check(payload["filters"] == {"project": "p"}, "filters echoed")
check(payload["summary"]["records_scanned"] == len(recs), "records_scanned in summary")
check(payload["summary"]["top"] == 5, "top in summary")
check(len(payload["findings"]) >= 1, "findings present")

f0 = payload["findings"][0]
for key in ("rank", "kind", "target", "occurrences", "distinct_sessions",
            "avg_tokens", "sum_tokens", "stability_factor", "score",
            "sample_session_ids", "suggestion", "raw"):
    check(key in f0, f"finding has {key}")
check(f0["rank"] == 1, "first finding rank=1")
check(isinstance(f0["suggestion"], dict), "suggestion is dict")
for key in ("type", "headline", "body"):
    check(key in f0["suggestion"], f"suggestion has {key}")
check(isinstance(f0["stability_factor"], float), "stability_factor is float")
check(isinstance(f0["score"], (int, float)), "score is numeric")

# Findings are sorted by rank (ascending) which corresponds to score (descending)
buf = io.StringIO()
report.render_token_report_json(recs, [], top=20, out=buf)
payload = _json.loads(buf.getvalue())
ranks = [f["rank"] for f in payload["findings"]]
check(ranks == sorted(ranks), "ranks ascending")
scores = [f["score"] for f in payload["findings"]]
check(scores == sorted(scores, reverse=True), "scores descending")


# =============================================================================
# SUMMARY
# =============================================================================
print("\n" + "=" * 70)
passed = sum(results)
total = len(results)
print(f"RESULTS: {passed}/{total} passed")
print("=" * 70)
sys.exit(0 if passed == total else 1)
