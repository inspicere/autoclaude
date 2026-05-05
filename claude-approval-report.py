#!/usr/bin/env python3
"""Analyze Claude Code session data to find which commands required the most user approval."""

import argparse
import json
import glob
import os
import re
import sys
from collections import defaultdict, Counter
from datetime import datetime, timezone
from pathlib import Path
from fnmatch import fnmatch

CLAUDE_DIR = Path.home() / ".claude"
PROJECTS_DIR = CLAUDE_DIR / "projects"

# --- Allowlist pattern matching ---

def load_global_settings():
    path = CLAUDE_DIR / "settings.json"
    if path.exists():
        with open(path) as f:
            return json.load(f)
    return {}

def load_project_settings(project_name):
    """Load settings.local.json from project source directories and from ~/.claude/projects/."""
    patterns = []

    # Check ~/.claude/projects/<project>/settings.json
    proj_settings = PROJECTS_DIR / project_name / "settings.json"
    if proj_settings.exists():
        try:
            with open(proj_settings) as f:
                data = json.load(f)
            patterns.extend(data.get("permissions", {}).get("allow", []))
        except (json.JSONDecodeError, KeyError):
            pass

    # Derive the source directory path from project name
    # Project names encode paths: /home/user/myproject -> -home-user-myproject
    # Use home dir to find the reliable split point, then treat the remainder
    # as the project directory name (which may contain hyphens)
    home_slug = "-" + str(Path.home()).lstrip("/").replace("/", "-")
    if project_name.startswith(home_slug + "-"):
        project_subdir = project_name[len(home_slug) + 1:]
        source_dir = str(Path.home() / project_subdir)
    elif project_name == home_slug:
        source_dir = str(Path.home())
    else:
        source_dir = "/" + project_name.lstrip("-").replace("-", "/")

    settings_local = Path(source_dir) / ".claude" / "settings.local.json"
    if settings_local.exists():
        try:
            with open(settings_local) as f:
                data = json.load(f)
            patterns.extend(data.get("permissions", {}).get("allow", []))
        except (json.JSONDecodeError, KeyError):
            pass

    return patterns


def parse_permission_pattern(pattern):
    """Parse a Claude Code permission pattern into (tool_name, arg_pattern)."""
    # Patterns like: Bash(git add:*), Bash(git add *), Read(**/.env.example),
    # mcp__vault__vault_read, WebFetch(domain:example.com), WebSearch
    m = re.match(r'^(\w+)\((.+)\)$', pattern)
    if m:
        return m.group(1), m.group(2)
    return pattern, None


def command_matches_pattern(tool_name, tool_input, pattern):
    """Check if a tool call matches an allowlist pattern."""
    pat_tool, pat_arg = parse_permission_pattern(pattern)

    if pat_tool != tool_name:
        return False

    if pat_arg is None:
        return True

    if tool_name == "Bash":
        cmd = tool_input.get("command", "")
        # Pattern uses : or space as separator, and * for glob
        # "git add:*" or "git add *" both match "git add foo.txt"
        pat_normalized = pat_arg.replace(":", " ")
        # Convert glob pattern to regex
        # Handle ** as "match anything including /"
        regex = re.escape(pat_normalized).replace(r"\*\*", ".*").replace(r"\*", ".*")
        return bool(re.match(regex, cmd))

    elif tool_name in ("Read", "Write", "Edit"):
        file_path = tool_input.get("file_path", "")
        # Glob pattern on file path
        # Remove leading // that some patterns have
        pat_clean = pat_arg.lstrip("/")
        path_clean = file_path.lstrip("/")
        return fnmatch(path_clean, pat_clean)

    elif tool_name == "WebFetch":
        if pat_arg.startswith("domain:"):
            domain = pat_arg[7:]
            url = tool_input.get("url", "")
            return domain in url
        return False

    elif tool_name == "WebSearch":
        return True

    return False


def is_auto_allowed(tool_name, tool_input, allow_patterns):
    """Check if a tool call would be auto-allowed by any pattern in the allowlist."""
    # Read tool is always auto-allowed (except denied paths, which we skip for simplicity)
    if tool_name == "Read":
        return True

    for pattern in allow_patterns:
        if command_matches_pattern(tool_name, tool_input, pattern):
            return True
    return False


# --- Session parsing ---

def extract_tool_calls_from_assistant(content):
    """Extract tool_use entries from an assistant message's content."""
    if not isinstance(content, list):
        return []
    return [c for c in content if isinstance(c, dict) and c.get("type") == "tool_use"]


def normalize_command(cmd):
    """Extract a groupable prefix from a bash command."""
    cmd = cmd.strip()
    # Strip leading cd ... &&
    cmd = re.sub(r'^cd\s+\S+\s*&&\s*', '', cmd)
    # Strip leading env var assignments
    cmd = re.sub(r'^(\w+=\S+\s+)+', '', cmd)
    # Get the base command (first word or two)
    parts = cmd.split()
    if not parts:
        return "(empty)"

    base = parts[0]

    # Skip comment-only lines and shebangs
    if base.startswith("#"):
        return "(comment/shebang)"

    # For well-known commands, include the subcommand
    multi_word = {
        "git", "ansible", "ansible-playbook", "ansible-vault",
        "docker", "kubectl", "terraform", "npm", "pip", "pip3",
        "python3", "ssh", "scp", "rsync", "curl", "wget",
        "systemctl", "journalctl", "gh",
    }

    if base == "ssh" and len(parts) > 1:
        # Normalize ssh targets: strip user@ prefix for grouping
        target = parts[1]
        if target.startswith("-"):
            return "ssh"
        target = re.sub(r'^[\w]+@', '', target)
        return f"ssh {target}"

    if base in multi_word and len(parts) > 1:
        sub = parts[1]
        if sub.startswith("-"):
            return base
        return f"{base} {sub}"

    # For path-based commands
    if "/" in base:
        base = os.path.basename(base)

    return base


def shorten_path(fp):
    """Shorten a file path for display."""
    home = str(Path.home())
    if fp.startswith(home):
        fp = "~" + fp[len(home):]
    return fp


def get_tool_display(tool_name, tool_input):
    """Get a human-readable description of a tool call."""
    if tool_name == "Bash":
        cmd = tool_input.get("command", "")
        return f"Bash: {normalize_command(cmd)}"
    elif tool_name in ("Read", "Write", "Edit"):
        fp = tool_input.get("file_path", "")
        return f"{tool_name}: {shorten_path(fp)}"
    elif tool_name == "WebFetch":
        url = tool_input.get("url", "")
        return f"WebFetch: {url[:80]}"
    elif tool_name == "WebSearch":
        q = tool_input.get("query", "")
        return f"WebSearch: {q[:60]}"
    elif tool_name.startswith("mcp__"):
        # MCP tool - show readable name
        parts = tool_name.split("__")
        if len(parts) >= 3:
            return f"MCP {parts[1]}: {parts[2]}"
        return tool_name
    else:
        return tool_name


def get_tool_full_command(tool_name, tool_input):
    """Get the full command string for detailed display."""
    if tool_name == "Bash":
        return tool_input.get("command", "")[:150]
    elif tool_name in ("Read", "Write", "Edit"):
        return tool_input.get("file_path", "")
    return ""


def process_session(jsonl_path, allow_patterns, project_name):
    """Process a single session JSONL file. Returns list of tool call records."""
    records = []

    try:
        with open(jsonl_path) as f:
            lines = list(f)
    except Exception:
        return records

    # Index assistant messages by UUID for lookup
    assistant_by_uuid = {}
    for line in lines:
        try:
            obj = json.loads(line)
        except json.JSONDecodeError:
            continue

        if obj.get("type") == "assistant":
            assistant_by_uuid[obj.get("uuid")] = obj

    # Process user records that have tool results
    for line in lines:
        try:
            obj = json.loads(line)
        except json.JSONDecodeError:
            continue

        if obj.get("type") != "user":
            continue

        src_uuid = obj.get("sourceToolAssistantUUID")
        if not src_uuid:
            continue

        # Find the assistant message that made this tool call
        assistant_msg = assistant_by_uuid.get(src_uuid)
        if not assistant_msg:
            continue

        tool_use_id = obj.get("toolUseID")
        tool_result_content = obj.get("toolUseResult", "")

        # Determine rejection status
        is_rejected = False
        if isinstance(tool_result_content, str) and "rejected" in tool_result_content.lower():
            is_rejected = True
        else:
            msg_content = obj.get("message", {}).get("content", [])
            if isinstance(msg_content, list):
                for c in msg_content:
                    if isinstance(c, dict) and c.get("type") == "tool_result":
                        if c.get("is_error") and "rejected" in str(c.get("content", "")).lower():
                            is_rejected = True

        # Find the specific tool_use in the assistant message
        ast_content = assistant_msg.get("message", {}).get("content", [])
        tool_calls = extract_tool_calls_from_assistant(ast_content)

        # Match by tool_use_id if available, otherwise take all
        matched_tools = []
        if tool_use_id:
            matched_tools = [t for t in tool_calls if t.get("id") == tool_use_id]

        if not matched_tools:
            # If we can't match by ID, use the tool_result's tool_use_id from message content
            msg_content = obj.get("message", {}).get("content", [])
            if isinstance(msg_content, list):
                for c in msg_content:
                    if isinstance(c, dict) and c.get("type") == "tool_result":
                        tuid = c.get("tool_use_id")
                        if tuid:
                            matched_tools = [t for t in tool_calls if t.get("id") == tuid]
                            break

        if not matched_tools and tool_calls:
            matched_tools = tool_calls[:1]

        for tool in matched_tools:
            tool_name = tool.get("name", "unknown")
            tool_input = tool.get("input", {})

            auto = is_auto_allowed(tool_name, tool_input, allow_patterns)

            records.append({
                "project": project_name,
                "session": os.path.basename(jsonl_path),
                "tool_name": tool_name,
                "tool_input": tool_input,
                "display": get_tool_display(tool_name, tool_input),
                "full_command": get_tool_full_command(tool_name, tool_input),
                "rejected": is_rejected,
                "auto_allowed": auto,
                "timestamp": obj.get("timestamp", ""),
            })

    return records


# --- Report rendering ---

def render_report(all_records, out=None):
    """Render the analysis report. Writes to out (file object) or stdout."""
    if out is None:
        out = sys.stdout
    _print = lambda *args, **kwargs: print(*args, file=out, **kwargs)
    total = len(all_records)
    auto = [r for r in all_records if r["auto_allowed"]]
    prompted = [r for r in all_records if not r["auto_allowed"] and not r["rejected"]]
    rejected = [r for r in all_records if r["rejected"]]

    _print("=" * 70)
    _print("  CLAUDE CODE APPROVAL ANALYSIS")
    _print("=" * 70)
    _print()
    _print(f"  Total tool calls analyzed:  {total:,}")
    _print(f"  Auto-allowed (no prompt):   {len(auto):,}")
    _print(f"  User prompted & approved:   {len(prompted):,}")
    _print(f"  User rejected:              {len(rejected):,}")
    _print()

    # --- Most prompted commands ---
    _print("=" * 70)
    _print("  MOST PROMPTED COMMANDS (top 25)")
    _print("  Commands that required user approval most often")
    _print("=" * 70)
    prompt_counts = Counter(r["display"] for r in prompted)
    _print(f"  {'Rank':<6} {'Count':<8} {'Command'}")
    _print(f"  {'----':<6} {'-----':<8} {'-------'}")
    for i, (cmd, count) in enumerate(prompt_counts.most_common(25), 1):
        _print(f"  {i:<6} {count:<8} {cmd}")
    _print()

    # --- Most rejected ---
    if rejected:
        _print("=" * 70)
        _print("  MOST REJECTED COMMANDS (top 15)")
        _print("  Commands the user denied")
        _print("=" * 70)
        reject_counts = Counter(r["display"] for r in rejected)
        _print(f"  {'Rank':<6} {'Count':<8} {'Command'}")
        _print(f"  {'----':<6} {'-----':<8} {'-------'}")
        for i, (cmd, count) in enumerate(reject_counts.most_common(15), 1):
            _print(f"  {i:<6} {count:<8} {cmd}")
        _print()

        # Show full commands for top rejected
        _print("  --- Full rejected commands (top 10 unique) ---")
        seen = set()
        shown = 0
        for r in sorted(rejected, key=lambda x: x["timestamp"]):
            fc = r["full_command"]
            if fc and fc not in seen:
                seen.add(fc)
                _print(f"  [{r['project']}] {r['tool_name']}: {fc}")
                shown += 1
                if shown >= 10:
                    break
        _print()

    # --- Suggested allowlist additions ---
    _print("=" * 70)
    _print("  SUGGESTED ALLOWLIST ADDITIONS")
    _print("  Frequently approved commands that could be auto-allowed")
    _print("=" * 70)

    # Group by project and command pattern
    by_project = defaultdict(lambda: Counter())
    for r in prompted:
        by_project[r["project"]][r["display"]] += 1

    suggestions = []
    skip_patterns = {"(comment/shebang)", "(empty)"}
    for project, counts in by_project.items():
        for cmd, count in counts.most_common():
            if count >= 3:
                cmd_suffix = cmd.split(": ", 1)[1] if ": " in cmd else cmd
                if cmd_suffix in skip_patterns:
                    continue
                pattern = suggest_pattern(cmd)
                suggestions.append((count, project, cmd, pattern))

    suggestions.sort(key=lambda x: -x[0])

    _print(f"  {'Count':<8} {'Project':<30} {'Suggested Pattern'}")
    _print(f"  {'-----':<8} {'-------':<30} {'-----------------'}")
    for count, project, cmd, pattern in suggestions[:20]:
        proj_short = project.split("-")[-1] if "-" in project else project
        _print(f"  {count:<8} {proj_short:<30} {pattern}")
    _print()

    # --- Per-project summary ---
    _print("=" * 70)
    _print("  PER-PROJECT SUMMARY")
    _print("=" * 70)

    projects = sorted(set(r["project"] for r in all_records))
    _print(f"  {'Project':<35} {'Total':>8} {'Auto':>8} {'Prompted':>8} {'Rejected':>8}")
    _print(f"  {'-'*35:<35} {'-----':>8} {'----':>8} {'--------':>8} {'--------':>8}")
    for proj in projects:
        proj_records = [r for r in all_records if r["project"] == proj]
        p_auto = sum(1 for r in proj_records if r["auto_allowed"])
        p_prompted = sum(1 for r in proj_records if not r["auto_allowed"] and not r["rejected"])
        p_rejected = sum(1 for r in proj_records if r["rejected"])
        # Strip the home dir prefix from project names for display
        # Project names encode paths: /home/terrabot/laima -> -home-terrabot-laima
        home_slug = "-" + str(Path.home()).lstrip("/").replace("/", "-")
        if proj == home_slug:
            proj_short = "(home)"
        elif proj.startswith(home_slug + "-"):
            proj_short = proj[len(home_slug) + 1:]
        else:
            proj_short = proj
        _print(f"  {proj_short:<35} {len(proj_records):>8} {p_auto:>8} {p_prompted:>8} {p_rejected:>8}")
    _print()

    # --- Tool type breakdown ---
    _print("=" * 70)
    _print("  TOOL TYPE BREAKDOWN (prompted only)")
    _print("=" * 70)
    tool_type_counts = Counter()
    for r in prompted:
        tool_type_counts[r["tool_name"]] += 1
    _print(f"  {'Tool':<30} {'Prompted Count':>15}")
    _print(f"  {'-'*30:<30} {'-'*15:>15}")
    for tool, count in tool_type_counts.most_common():
        _print(f"  {tool:<30} {count:>15}")
    _print()


def suggest_pattern(display):
    """Suggest an allowlist pattern from a display string."""
    if display.startswith("Bash: "):
        cmd = display[6:]
        # For ssh, suggest a host-scoped pattern
        m = re.match(r'^ssh ([\d.]+)$', cmd)
        if m:
            return f"Bash(ssh *@{m.group(1)} *) or Bash(ssh {m.group(1)} *)"
        return f"Bash({cmd} *)"
    elif display.startswith("MCP "):
        m = re.match(r'MCP (\w+): (\w+)', display)
        if m:
            return f"mcp__{m.group(1)}__{m.group(2)}"
    elif display.startswith("Edit: "):
        path = display[6:]
        if "~/" in path:
            path = path.replace("~/", "**/")
        return f"Edit({path})"
    elif display.startswith("Write: "):
        path = display[7:]
        if "~/" in path:
            path = path.replace("~/", "**/")
        return f"Write({path})"
    elif display.startswith("WebSearch"):
        return "WebSearch"
    elif display.startswith("WebFetch"):
        return display.replace("WebFetch: ", "WebFetch(url:") + ")"
    return display


# --- Main ---

def default_output_path():
    ts = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H%M%SZ")
    return f"claude-approval-report-{ts}.txt"


def main():
    parser = argparse.ArgumentParser(description="Analyze Claude Code approval data")
    parser.add_argument(
        "-o", "--output",
        nargs="?",
        const="auto",
        default=None,
        help="Write report to file. No value = auto-named ISO 8601 file in current directory. "
             "Or pass a path explicitly.",
    )
    args = parser.parse_args()

    print("Scanning Claude Code session data...\n")

    global_settings = load_global_settings()
    global_allow = global_settings.get("permissions", {}).get("allow", [])

    all_records = []
    project_dirs = sorted(PROJECTS_DIR.iterdir()) if PROJECTS_DIR.exists() else []

    for project_dir in project_dirs:
        if not project_dir.is_dir():
            continue

        project_name = project_dir.name

        project_allow = load_project_settings(project_name)
        combined_allow = global_allow + project_allow

        jsonl_files = sorted(project_dir.glob("*.jsonl"))
        for jsonl_file in jsonl_files:
            records = process_session(str(jsonl_file), combined_allow, project_name)
            all_records.extend(records)

    if not all_records:
        print("No tool call data found.")
        sys.exit(1)

    if args.output is None:
        render_report(all_records)
    else:
        if args.output == "auto":
            out_path = default_output_path()
        elif os.path.isdir(args.output):
            out_path = os.path.join(args.output, default_output_path())
        else:
            out_path = args.output
        with open(out_path, "w") as f:
            render_report(all_records, out=f)
        print(f"Report written to {out_path}")


if __name__ == "__main__":
    main()
