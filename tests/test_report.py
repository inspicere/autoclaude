#!/usr/bin/env python3
"""Test suite for claude-approval-report.py — tests pure functions without session data."""

import importlib.util
import io
import os
import sys

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
# SUMMARY
# =============================================================================
print("\n" + "=" * 70)
passed = sum(results)
total = len(results)
print(f"RESULTS: {passed}/{total} passed")
print("=" * 70)
sys.exit(0 if passed == total else 1)
