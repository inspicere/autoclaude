#!/usr/bin/env python3
"""Analyze Claude Code session data to find which commands required the most user approval."""

import argparse
import json
import glob
import os
import re
import sys
from collections import defaultdict, Counter
from datetime import datetime, timedelta, timezone
from pathlib import Path
from fnmatch import fnmatch

CLAUDE_DIR = Path.home() / ".claude"
PROJECTS_DIR = CLAUDE_DIR / "projects"

# --- Risk classification ---

DESTRUCTIVE_COMMANDS = {
    "rm", "rmdir", "shred", "srm", "wipe", "unlink",
    "mkfs", "mkfs.ext4", "mkfs.xfs", "mkfs.btrfs", "mkfs.vfat", "mkfs.ntfs",
    "mkswap", "dd", "wipefs", "blkdiscard", "sgdisk", "sfdisk", "cfdisk", "parted",
    "dropdb", "dropuser", "mysqladmin",
    "reboot", "shutdown", "halt", "poweroff", "init", "telinit",
    "userdel", "groupdel", "deluser", "delgroup",
    "iptables-restore", "cryptsetup",
}

MUTATING_COMMANDS = {
    "mv", "cp", "install", "touch", "mkdir", "mktemp", "tee", "truncate",
    "ln", "patch", "perl", "python", "python3", "ruby", "node",
    "bash", "sh", "zsh", "sudo", "su", "doas",
    "xargs", "nohup", "chroot",
    "chmod", "chown", "chgrp", "chattr", "setfacl",
    "tar", "zip", "unzip", "gzip", "gunzip", "bzip2", "xz", "7z",
    "apt", "apt-get", "dpkg", "yum", "dnf", "rpm", "pacman", "apk",
    "snap", "flatpak", "brew", "port", "nix",
    "pip", "pip3", "pipx", "conda", "uv", "poetry",
    "npm", "npx", "yarn", "pnpm", "bun", "deno",
    "cargo", "rustup", "go", "gem", "bundle", "composer",
    "systemctl", "service", "mount", "umount",
    "fdisk", "gdisk", "lvm", "mdadm", "zpool", "zfs", "btrfs",
    "kill", "killall", "pkill",
    "useradd", "usermod", "adduser", "groupadd", "passwd",
    "iptables", "ip6tables", "nft", "firewall-cmd", "ufw",
    "ip", "ifconfig", "nmcli", "ethtool",
    "docker", "podman", "kubectl", "helm", "terraform", "tofu", "pulumi",
    "vagrant", "packer",
    "ansible", "ansible-playbook", "ansible-vault", "ansible-galaxy",
    "aws", "gcloud", "az", "doctl", "heroku", "vercel", "flyctl", "wrangler",
    "psql", "mysql", "mongosh", "redis-cli", "sqlite3",
    "curl", "wget", "scp", "rsync", "ssh", "sftp",
    "make", "cmake", "ninja", "gradle", "mvn",
    "crontab", "at",
    "sed", "awk",
    "gpg", "openssl", "ssh-keygen", "ssh-add", "certbot",
    "modprobe", "insmod", "rmmod", "sysctl",
    "gh", "glab",
    "eval", "export", "vault",
    "hermes", "hermes-bin",
    "Write", "Edit", "NotebookEdit", "Agent", "WebFetch", "WebSearch",
}

READ_ONLY_COMMANDS = {
    "ls", "dir", "tree", "cat", "head", "tail", "less", "more", "bat",
    "nl", "tac", "rev", "od", "xxd", "hexdump", "strings",
    "file", "stat", "readlink", "realpath", "basename", "dirname",
    "grep", "egrep", "fgrep", "rg", "ag", "ack",
    "find", "fd", "locate", "which", "whereis", "whatis", "type",
    "wc", "sort", "uniq", "cut", "paste", "tr", "fold", "fmt", "column",
    "comm", "diff", "cmp", "md5sum", "sha256sum", "shasum",
    "base64", "jq", "yq",
    "printf", "echo", "expr", "bc", "seq",
    "du", "df", "lsblk", "blkid", "findmnt", "lsof",
    "uname", "hostname", "arch", "nproc", "lscpu", "lsmem", "lspci", "lsusb",
    "uptime", "date", "cal",
    "ps", "top", "htop", "vmstat", "iostat", "free", "pmap", "pstree",
    "w", "who", "whoami", "id", "groups", "last", "users",
    "ss", "netstat", "ping", "traceroute", "tracepath", "mtr",
    "dig", "nslookup", "host", "whois", "nmap",
    "man", "info", "help", "history", "alias",
    "printenv", "env", "true", "false", "test", "time", "sleep",
    "pwd", "dirs", "tty",
    "pytest", "ruff", "mypy", "semgrep", "sg", "namei", "getent",
    "journalctl", "ansible-doc", "ssh-keyscan",
    "Read", "Skill", "ToolSearch", "TaskCreate", "TaskUpdate", "TaskList",
    "TaskGet", "TaskOutput", "EnterPlanMode", "ExitPlanMode", "AskUserQuestion",
    "Glob", "Grep",
}

# Git subcommands that override the base "mutating" classification
GIT_DESTRUCTIVE_SUBCMDS = {
    "push --force", "push -f", "push --force-with-lease",
    "reset --hard", "clean -f", "clean -fd", "clean -fx",
    "branch -D",
}
GIT_READ_ONLY_SUBCMDS = {
    "status", "log", "diff", "show", "branch", "tag", "remote",
    "blame", "shortlog", "describe", "rev-parse", "rev-list",
    "ls-files", "ls-tree", "ls-remote", "cat-file", "reflog",
    "for-each-ref", "count-objects", "fsck", "whatchanged",
    "check-ignore", "help", "version",
}


def classify_risk(tool_name, tool_input):
    """Classify a tool call as destructive/mutating/read-only."""
    if tool_name == "Bash":
        cmd = tool_input.get("command", "").strip()
        cmd = re.sub(r'^cd\s+\S+\s*&&\s*', '', cmd)
        cmd = re.sub(r'^(\w+=\S+\s+)+', '', cmd)
        # Strip leading shell operators from compound commands
        cmd = re.sub(r'^[&|;]+\s*', '', cmd)
        parts = cmd.split()
        if not parts or parts[0].startswith("#"):
            return "read-only"

        base = os.path.basename(parts[0])
        # Strip trailing punctuation from parsing artifacts
        base = base.rstrip('"\')}')

        # Detect secret/key material exposure (not in grep/search contexts)
        if base not in ("grep", "egrep", "fgrep", "rg", "ag", "ack", "find"):
            for token in parts[1:]:
                clean = token.strip("\"'")
                # Standalone base64 blobs that look like keys (no path separators)
                if len(clean) >= 40 and "/" not in clean and re.match(r'^[A-Za-z0-9+/=]+$', clean):
                    return "destructive"
                # Inline secret assignments: VAR=<value> where VAR names a secret
                if re.match(r'^([\w]*)(API_KEY|SECRET|TOKEN|PASSWORD|PRIVATE_KEY|CREDENTIAL)([\w]*)=.+', clean, re.IGNORECASE):
                    return "destructive"

        # Git subcommand-aware classification
        if base == "git" and len(parts) > 1:
            subcmd = parts[1]
            # Check for destructive flag combos
            rest = " ".join(parts[1:])
            for pattern in GIT_DESTRUCTIVE_SUBCMDS:
                if rest.startswith(pattern):
                    return "destructive"
            if subcmd in GIT_READ_ONLY_SUBCMDS:
                return "read-only"
            return "mutating"

        # find with -delete or -exec
        if base == "find":
            rest = " ".join(parts[1:])
            if "-delete" in rest:
                return "destructive"
            if "-exec" in rest or "-execdir" in rest:
                return "mutating"
            return "read-only"

        # sed with -i is mutating, otherwise read-only
        if base == "sed":
            if "-i" in parts:
                return "mutating"
            return "read-only"

        # ansible-playbook with --check/--syntax-check is read-only
        if base == "ansible-playbook":
            rest = " ".join(parts[1:])
            if "--check" in rest or "--syntax-check" in rest or "--list-tasks" in rest or "--list-hosts" in rest:
                return "read-only"
            return "mutating"

        # curl: check method
        if base == "curl":
            rest = " ".join(parts[1:])
            if "-X DELETE" in rest or "--request DELETE" in rest:
                return "destructive"
            if any(f in rest for f in ["-X POST", "-X PUT", "-X PATCH", "--data", "-d ", "-F "]):
                return "mutating"
            return "read-only"

        if base in DESTRUCTIVE_COMMANDS:
            return "destructive"
        if base in READ_ONLY_COMMANDS:
            return "read-only"
        if base in MUTATING_COMMANDS:
            return "mutating"
        # Shell builtins/syntax that aren't real commands
        if base in ("for", "while", "if", "else", "then", "do", "done",
                    "fi", "case", "esac", "{", "}", "[[", "(("):
            return "read-only"
        # Flags, IP addresses, user@host, and other parsing artifacts
        if base.startswith("-") or re.match(r'^\d+\.\d+\.\d+\.\d+', base):
            return "read-only"
        if re.match(r'^[\w]+@[\d.]+$', base):
            return "mutating"
        # Shell scripts (.sh) are mutating by default
        if base.endswith(".sh"):
            return "mutating"
        # Bare key material / secret references parsed as "commands"
        clean_base = base.strip("\"'^)")
        if len(clean_base) >= 40 and re.match(r'^[A-Za-z0-9+/=]+$', clean_base):
            return "destructive"
        if re.search(r'(API_KEY|SECRET|TOKEN|PASSWORD|PRIVATE_KEY|CREDENTIAL)', clean_base.upper()):
            return "destructive"
        return "unknown"

    # Non-Bash tools
    if tool_name in DESTRUCTIVE_COMMANDS:
        return "destructive"
    if tool_name in READ_ONLY_COMMANDS:
        return "read-only"
    if tool_name in MUTATING_COMMANDS:
        return "mutating"
    if tool_name.startswith("mcp__"):
        return "mutating"
    return "unknown"


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

    settings_path = project_settings_path(project_name)
    settings_local = settings_path if settings_path else Path("/nonexistent")
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
            risk = classify_risk(tool_name, tool_input)

            records.append({
                "project": project_name,
                "session": os.path.basename(jsonl_path),
                "tool_name": tool_name,
                "tool_input": tool_input,
                "display": get_tool_display(tool_name, tool_input),
                "full_command": get_tool_full_command(tool_name, tool_input),
                "rejected": is_rejected,
                "auto_allowed": auto,
                "risk": risk,
                "timestamp": obj.get("timestamp", ""),
            })

    return records


# --- Report rendering ---

NOISE_SUFFIXES = {
    "(comment/shebang)", "(empty)",
    "&&", "for", "if", "while", "else", "then", "do", "done", "fi", "{", "}",
}


def _is_noise_command(display):
    """Check if a display string is a noise entry (not a real command)."""
    suffix = display.split(": ", 1)[1] if ": " in display else display
    if suffix in NOISE_SUFFIXES:
        return True
    if suffix.startswith("-") or re.match(r'^\d+\.\d+\.\d+\.\d+', suffix):
        return True
    return False


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
    shown = 0
    for cmd, count in prompt_counts.most_common():
        if _is_noise_command(cmd):
            continue
        shown += 1
        _print(f"  {shown:<6} {count:<8} {cmd}")
        if shown >= 25:
            break
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

    suggestions = build_suggestions(all_records)

    _print(f"  {'Count':<8} {'Risk':<14} {'Project':<18} {'Suggested Pattern'}")
    _print(f"  {'-----':<8} {'----':<14} {'-------':<18} {'-----------------'}")
    for count, project, cmd, pattern, risk in suggestions[:20]:
        proj_short = project.split("-")[-1] if "-" in project else project
        _print(f"  {count:<8} {risk:<14} {proj_short:<18} {pattern}")
    _print()

    # --- Risk breakdown ---
    _print("=" * 70)
    _print("  RISK BREAKDOWN")
    _print("=" * 70)

    risk_counts = Counter(r["risk"] for r in all_records)
    for level in ["destructive", "mutating", "read-only", "unknown"]:
        count = risk_counts.get(level, 0)
        pct = (count / total * 100) if total else 0
        _print(f"  {level:<15} {count:>8,}  ({pct:>5.1f}%)")
    _print()

    # --- High-risk approvals ---
    destructive_approved = [r for r in all_records if r["risk"] == "destructive" and not r["rejected"]]
    if destructive_approved:
        _print("=" * 70)
        _print("  DESTRUCTIVE COMMANDS APPROVED (all)")
        _print("  Commands classified as destructive that were approved")
        _print("=" * 70)
        destr_counts = Counter(r["display"] for r in destructive_approved)
        _print(f"  {'Rank':<6} {'Count':<8} {'Command'}")
        _print(f"  {'----':<6} {'-----':<8} {'-------'}")
        for i, (cmd, count) in enumerate(destr_counts.most_common(20), 1):
            _print(f"  {i:<6} {count:<8} {cmd}")
        _print()

    # --- Auto-allowed mutating/destructive ---
    risky_auto = [r for r in all_records if r["auto_allowed"] and r["risk"] in ("destructive", "mutating")]
    if risky_auto:
        _print("=" * 70)
        _print("  AUTO-ALLOWED RISKY COMMANDS")
        _print("  Mutating/destructive commands that bypassed approval prompts")
        _print("=" * 70)
        risky_auto_counts = Counter(
            (r["display"], r["risk"]) for r in risky_auto
        )
        _print(f"  {'Count':<8} {'Risk':<14} {'Command'}")
        _print(f"  {'-----':<8} {'----':<14} {'-------'}")
        for (cmd, risk), count in risky_auto_counts.most_common(20):
            _print(f"  {count:<8} {risk:<14} {cmd}")
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
    """Suggest an allowlist pattern from a display string. Returns a display string (may contain 'or')."""
    if display.startswith("Bash: "):
        cmd = display[6:]
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


def suggest_pattern_applicable(display):
    """Return a single pattern suitable for writing to settings.local.json."""
    pattern = suggest_pattern(display)
    # For compound suggestions, pick the simpler one
    if " or " in pattern:
        pattern = pattern.split(" or ")[1]
    return pattern


def build_suggestions(all_records):
    """Build the list of allowlist suggestions from prompted records.

    Returns list of (count, project_name, display, pattern, risk) tuples.
    """
    prompted = [r for r in all_records if not r["auto_allowed"] and not r["rejected"]]

    by_project = defaultdict(lambda: Counter())
    risk_by_key = defaultdict(lambda: Counter())
    for r in prompted:
        key = (r["project"], r["display"])
        by_project[r["project"]][r["display"]] += 1
        risk_by_key[key][r["risk"]] += 1

    suggestions = []
    skip_patterns = {"(comment/shebang)", "(empty)"}
    for project, counts in by_project.items():
        for cmd, count in counts.most_common():
            if count >= 3:
                cmd_suffix = cmd.split(": ", 1)[1] if ": " in cmd else cmd
                if cmd_suffix in skip_patterns:
                    continue
                pattern = suggest_pattern(cmd)
                risk = risk_by_key[(project, cmd)].most_common(1)[0][0]
                suggestions.append((count, project, cmd, pattern, risk))

    suggestions.sort(key=lambda x: -x[0])
    return suggestions


def project_settings_path(project_name):
    """Get the settings.local.json path for a project.

    Falls back to scanning home directory if the slug doesn't resolve
    (e.g. dots in directory names become dashes in the slug).
    """
    home_slug = "-" + str(Path.home()).lstrip("/").replace("/", "-")
    if project_name == home_slug:
        return Path.home() / ".claude" / "settings.local.json"

    if not project_name.startswith(home_slug + "-"):
        return None

    project_subdir = project_name[len(home_slug) + 1:]
    candidate = Path.home() / project_subdir
    if candidate.is_dir():
        return candidate / ".claude" / "settings.local.json"

    # Slug doesn't map directly — scan home for dirs whose slugified name matches
    for entry in Path.home().iterdir():
        if not entry.is_dir() or entry.name.startswith("."):
            continue
        if entry.name.replace(".", "-") == project_subdir:
            return entry / ".claude" / "settings.local.json"

    return None


def apply_suggestions(all_records, risk_level="read-only", dry_run=False):
    """Apply suggested allowlist patterns to project settings.local.json files."""
    suggestions = build_suggestions(all_records)

    allowed_risks = {"read-only"}
    if risk_level == "mutating":
        allowed_risks.add("mutating")

    # Group applicable suggestions by project
    by_project = defaultdict(list)
    for count, project, cmd, pattern, risk in suggestions:
        if risk not in allowed_risks:
            continue
        applicable = suggest_pattern_applicable(cmd)
        by_project[project].append((applicable, count, risk))

    if not by_project:
        print("No applicable suggestions found.", file=sys.stderr)
        return

    total_added = 0
    for project, patterns in sorted(by_project.items()):
        settings_path = project_settings_path(project)
        if settings_path is None:
            continue

        # Load existing settings
        if settings_path.exists():
            try:
                with open(settings_path) as f:
                    settings = json.load(f)
            except (json.JSONDecodeError, OSError):
                settings = {}
        else:
            settings = {}

        existing = set(settings.get("permissions", {}).get("allow", []))

        new_patterns = []
        for pattern, count, risk in patterns:
            if pattern not in existing:
                new_patterns.append((pattern, count, risk))

        if not new_patterns:
            continue

        home_slug = "-" + str(Path.home()).lstrip("/").replace("/", "-")
        if project == home_slug:
            proj_short = "(home)"
        elif project.startswith(home_slug + "-"):
            proj_short = project[len(home_slug) + 1:]
        else:
            proj_short = project

        print(f"\n  {proj_short}: {settings_path}", file=sys.stderr)
        for pattern, count, risk in new_patterns:
            print(f"    + {pattern}  ({count} approvals, {risk})", file=sys.stderr)

        if not dry_run:
            if "permissions" not in settings:
                settings["permissions"] = {}
            if "allow" not in settings["permissions"]:
                settings["permissions"]["allow"] = []

            for pattern, count, risk in new_patterns:
                settings["permissions"]["allow"].append(pattern)

            if not settings_path.parent.exists():
                print(f"    Skipping: {settings_path.parent} does not exist", file=sys.stderr)
                continue
            with open(settings_path, "w") as f:
                json.dump(settings, f, indent=2)
                f.write("\n")

        total_added += len(new_patterns)

    action = "Would add" if dry_run else "Added"
    print(f"\n  {action} {total_added} patterns across {len(by_project)} projects.", file=sys.stderr)


# --- Main ---

def parse_time_filter(value):
    """Parse --since value. Accepts ISO date (2026-05-01) or relative (7d, 2w, 1m)."""
    # Relative: 7d, 2w, 1m
    m = re.match(r'^(\d+)([dwm])$', value)
    if m:
        num = int(m.group(1))
        unit = m.group(2)
        now = datetime.now(timezone.utc)
        if unit == "d":
            cutoff = now - timedelta(days=num)
        elif unit == "w":
            cutoff = now - timedelta(weeks=num)
        elif unit == "m":
            cutoff = now - timedelta(days=num * 30)
        return cutoff

    # ISO date
    try:
        dt = datetime.fromisoformat(value)
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return dt
    except ValueError:
        print(f"Error: invalid time filter '{value}'. Use ISO date (2026-05-01) or relative (7d, 2w, 1m).")
        sys.exit(1)


def filter_records(records, since=None, project=None):
    """Filter records by time and/or project."""
    if since:
        cutoff_str = since.isoformat()
        records = [r for r in records if r["timestamp"] >= cutoff_str]
    if project:
        home_slug = "-" + str(Path.home()).lstrip("/").replace("/", "-")
        full_name = home_slug + "-" + project
        records = [r for r in records if r["project"] == full_name]
    return records


def render_json(all_records, out=None):
    """Render the analysis as JSON."""
    if out is None:
        out = sys.stdout

    total = len(all_records)
    auto = [r for r in all_records if r["auto_allowed"]]
    prompted = [r for r in all_records if not r["auto_allowed"] and not r["rejected"]]
    rejected = [r for r in all_records if r["rejected"]]

    prompt_counts = Counter(r["display"] for r in prompted)
    reject_counts = Counter(r["display"] for r in rejected)
    risk_counts = Counter(r["risk"] for r in all_records)
    tool_counts = Counter(r["tool_name"] for r in prompted)

    home_slug = "-" + str(Path.home()).lstrip("/").replace("/", "-")
    projects = {}
    for proj in sorted(set(r["project"] for r in all_records)):
        proj_records = [r for r in all_records if r["project"] == proj]
        if proj == home_slug:
            proj_short = "(home)"
        elif proj.startswith(home_slug + "-"):
            proj_short = proj[len(home_slug) + 1:]
        else:
            proj_short = proj
        projects[proj_short] = {
            "total": len(proj_records),
            "auto_allowed": sum(1 for r in proj_records if r["auto_allowed"]),
            "prompted": sum(1 for r in proj_records if not r["auto_allowed"] and not r["rejected"]),
            "rejected": sum(1 for r in proj_records if r["rejected"]),
        }

    report = {
        "summary": {
            "total": total,
            "auto_allowed": len(auto),
            "prompted": len(prompted),
            "rejected": len(rejected),
        },
        "risk": {level: risk_counts.get(level, 0) for level in ["destructive", "mutating", "read-only", "unknown"]},
        "most_prompted": [{"command": cmd, "count": n} for cmd, n in prompt_counts.most_common(25)],
        "most_rejected": [{"command": cmd, "count": n} for cmd, n in reject_counts.most_common(15)],
        "tool_types": {tool: n for tool, n in tool_counts.most_common()},
        "projects": projects,
    }

    json.dump(report, out, indent=2)
    out.write("\n")


def render_summary(all_records, out=None):
    """Render a compact dashboard summary."""
    if out is None:
        out = sys.stdout
    _print = lambda *a, **kw: print(*a, file=out, **kw)

    total = len(all_records)
    auto = sum(1 for r in all_records if r["auto_allowed"])
    prompted = [r for r in all_records if not r["auto_allowed"] and not r["rejected"]]
    rejected = sum(1 for r in all_records if r["rejected"])
    risk_counts = Counter(r["risk"] for r in all_records)

    _print("CLAUDE CODE APPROVAL SUMMARY")
    _print(f"  Calls: {total:,} total | {auto:,} auto | {len(prompted):,} prompted | {rejected:,} rejected")
    _print(f"  Risk:  {risk_counts.get('destructive',0)} destructive | {risk_counts.get('mutating',0):,} mutating | {risk_counts.get('read-only',0):,} read-only | {risk_counts.get('unknown',0)} unknown")

    secret_count = sum(1 for r in all_records
                       if r["risk"] == "destructive" and not r["rejected"]
                       and re.search(r'(API_KEY|SECRET|TOKEN|PASSWORD|PRIVATE_KEY|CREDENTIAL)',
                                     r.get("full_command", ""), re.IGNORECASE))
    if secret_count:
        _print(f"  Secrets: {secret_count} secret-exposure commands approved")

    prompt_counts = Counter(r["display"] for r in prompted)
    _print("\n  Top prompted:")
    shown = 0
    for cmd, count in prompt_counts.most_common():
        if _is_noise_command(cmd):
            continue
        shown += 1
        _print(f"    {shown}. {cmd:<40} ({count}x)")
        if shown >= 5:
            break

    suggestions = build_suggestions(all_records)
    if suggestions:
        _print("\n  Top suggestions:")
        for i, (count, project, cmd, pattern, risk) in enumerate(suggestions[:3], 1):
            _print(f"    {i}. {pattern:<40} ({count} approvals, {risk})")


def render_why(query, all_records):
    """Look up why a specific command gets prompted and how to fix it."""
    q = query.lower()
    matched = [r for r in all_records if q in r["display"].lower()]
    if not matched:
        matched = [r for r in all_records if q in r.get("full_command", "").lower()]

    if not matched:
        print(f"No records found matching '{query}'.", file=sys.stderr)
        return

    displays = Counter(r["display"] for r in matched)
    top_display = displays.most_common(1)[0][0]
    top_records = [r for r in matched if r["display"] == top_display]
    sample = top_records[0]

    auto_count = sum(1 for r in top_records if r["auto_allowed"])
    prompted_count = sum(1 for r in top_records if not r["auto_allowed"] and not r["rejected"])
    rejected_count = sum(1 for r in top_records if r["rejected"])

    print(f"WHY: {top_display}")
    print(f"  Risk:         {sample['risk']}")
    print(f"  Prompted:     {prompted_count}x  |  Auto-allowed: {auto_count}x  |  Rejected: {rejected_count}x")

    global_settings = load_global_settings()
    global_allow = global_settings.get("permissions", {}).get("allow", [])
    home_slug = "-" + str(Path.home()).lstrip("/").replace("/", "-")

    projects = sorted(set(r["project"] for r in top_records))
    status_parts = []
    for proj in projects:
        proj_allow = load_project_settings(proj)
        combined = global_allow + proj_allow
        matching_pattern = None
        for pat in combined:
            if command_matches_pattern(sample["tool_name"], sample["tool_input"], pat):
                matching_pattern = pat
                break
        if proj == home_slug:
            proj_short = "(home)"
        elif proj.startswith(home_slug + "-"):
            proj_short = proj[len(home_slug) + 1:]
        else:
            proj_short = proj
        if matching_pattern:
            status_parts.append(f"YES in {proj_short} ({matching_pattern})")
        else:
            status_parts.append(f"NO in {proj_short}")
    print(f"  Auto-allowed: {', '.join(status_parts)}")

    pattern = suggest_pattern(top_display)
    print(f"  To auto-allow: {pattern}")

    if len(displays) > 1:
        print(f"\n  Also matched:")
        for cmd, count in displays.most_common()[1:5]:
            print(f"    {cmd} ({count}x)")


def resolve_session(session_arg, project_filter=None):
    """Resolve --session argument to JSONL file paths."""
    if not PROJECTS_DIR.exists():
        return []

    home_slug = "-" + str(Path.home()).lstrip("/").replace("/", "-")
    project_dirs = [d for d in sorted(PROJECTS_DIR.iterdir()) if d.is_dir()]
    if project_filter:
        full_name = home_slug + "-" + project_filter
        project_dirs = [d for d in project_dirs if d.name == full_name]

    all_jsonl = []
    for d in project_dirs:
        all_jsonl.extend(d.glob("*.jsonl"))

    if not all_jsonl:
        return []

    if session_arg == "current":
        return [max(all_jsonl, key=lambda p: p.stat().st_mtime)]

    target = session_arg if session_arg.endswith(".jsonl") else session_arg + ".jsonl"
    matches = [p for p in all_jsonl if p.name == target]
    if matches:
        return matches

    return [p for p in all_jsonl if session_arg in p.name]


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
    parser.add_argument(
        "--since",
        default=None,
        help="Only include records after this time. ISO date (2026-05-01) or relative (7d, 2w, 1m).",
    )
    parser.add_argument(
        "--project",
        default=None,
        help="Filter to a single project by name (e.g. 'laima', 'vsdx-forge').",
    )
    parser.add_argument(
        "--json",
        action="store_true",
        default=False,
        help="Output as JSON instead of text tables.",
    )
    parser.add_argument(
        "--apply",
        nargs="?",
        const="read-only",
        default=None,
        choices=["read-only", "mutating"],
        help="Write suggested patterns to settings.local.json. "
             "Default: only read-only commands. 'mutating' includes mutating too. "
             "Never auto-applies destructive patterns.",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        default=False,
        help="With --apply, show what would be added without writing.",
    )
    parser.add_argument(
        "--summary", "--brief",
        action="store_true",
        default=False,
        help="Compact dashboard instead of full report.",
    )
    parser.add_argument(
        "--why",
        default=None,
        metavar="COMMAND",
        help="Look up why a command is prompted and how to auto-allow it.",
    )
    parser.add_argument(
        "--session",
        default=None,
        metavar="ID",
        help="Analyze a specific session. 'current' for most recent, or a session UUID.",
    )
    args = parser.parse_args()

    since = parse_time_filter(args.since) if args.since else None

    print("Scanning Claude Code session data...", file=sys.stderr)

    global_settings = load_global_settings()
    global_allow = global_settings.get("permissions", {}).get("allow", [])

    all_records = []

    session_files = None
    if args.session:
        session_files = resolve_session(args.session, project_filter=args.project)
        if not session_files:
            print(f"No session found matching '{args.session}'.", file=sys.stderr)
            sys.exit(1)
        for sf in session_files:
            print(f"Session: {sf.name}", file=sys.stderr)

    if session_files:
        for sf in session_files:
            project_name = sf.parent.name
            project_allow = load_project_settings(project_name)
            records = process_session(str(sf), global_allow + project_allow, project_name)
            all_records.extend(records)
    else:
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

    all_records = filter_records(all_records, since=since, project=args.project)

    if not all_records:
        print("No tool call data found.", file=sys.stderr)
        sys.exit(1)

    active_filters = []
    if args.since:
        active_filters.append(f"since {args.since}")
    if args.project:
        active_filters.append(f"project={args.project}")
    if args.session:
        active_filters.append(f"session={args.session}")
    if active_filters:
        print(f"Filters: {', '.join(active_filters)}", file=sys.stderr)

    if args.why:
        render_why(args.why, all_records)
        return

    if args.apply is not None:
        apply_suggestions(all_records, risk_level=args.apply, dry_run=args.dry_run)
    else:
        if args.summary:
            renderer = render_summary
        elif args.json:
            renderer = render_json
        else:
            renderer = render_report

        if args.output is None:
            renderer(all_records)
        else:
            if args.output == "auto":
                ext = ".json" if args.json else ".txt"
                out_path = f"claude-approval-report-{datetime.now(timezone.utc).strftime('%Y-%m-%dT%H%M%SZ')}{ext}"
            elif os.path.isdir(args.output):
                ext = ".json" if args.json else ".txt"
                out_path = os.path.join(args.output, f"claude-approval-report-{datetime.now(timezone.utc).strftime('%Y-%m-%dT%H%M%SZ')}{ext}")
            else:
                out_path = args.output
            with open(out_path, "w") as f:
                renderer(all_records, out=f)
            print(f"Report written to {out_path}", file=sys.stderr)


if __name__ == "__main__":
    main()
