#!/usr/bin/env python3
"""Analyze Claude Code session data to find which commands required the most user approval."""

import argparse
import json
import math
import os
import re
import sys
import tempfile
from collections import defaultdict, Counter
from datetime import datetime, timedelta, timezone
from pathlib import Path
from fnmatch import fnmatch

CLAUDE_DIR = Path.home() / ".claude"
PROJECTS_DIR = CLAUDE_DIR / "projects"
HOME_SLUG = "-" + str(Path.home()).lstrip("/").replace("/", "-")

_RE_CD_PREFIX = re.compile(r'^(cd\s+(?:\S+|"[^"]*"|\'[^\']*\')\s*&&\s*)+')
_RE_ENV_PREFIX = re.compile(r'^(\w+=(?:\S+|"[^"]*"|\'[^\']*\')\s+)+')
_RE_SHELL_OPS = re.compile(r'^[&|;]+\s*')

# --- Secret detection (patterns derived from gitleaks) ---

_RE_SECRET_ASSIGN = re.compile(
    r'\b(\w{0,50}(?:API_KEY|SECRET|TOKEN|PASSWORD|PRIVATE_KEY|CREDENTIAL|_AUTH|AUTH_)\w*)'
    r'=\s*(\S+)',
    re.IGNORECASE,
)

# Tokens with unique prefixes — zero false positives, no entropy check needed
_PREFIXED_TOKEN_PATTERNS = re.compile(
    r'(?:'
    r'ghp_[0-9a-zA-Z]{36}'                           # GitHub PAT
    r'|github_pat_\w{82}'                             # GitHub fine-grained PAT
    r'|(?:ghu|ghs)_[0-9a-zA-Z]{36}'                  # GitHub app tokens
    r'|glpat-[\w-]{20}'                               # GitLab PAT
    r'|sk-ant-(?:api03|admin01)-[a-zA-Z0-9_\-]{93}AA' # Anthropic API key
    r'|sk-(?:proj|svcacct|admin)-[A-Za-z0-9_\-]{58,}'  # OpenAI API key (prefix)
    r'|sk-[a-zA-Z0-9]{20}T3BlbkFJ[a-zA-Z0-9]{20}'   # OpenAI API key (legacy)
    r'|(?:A3T[A-Z0-9]|AKIA|ASIA|ABIA|ACCA)[A-Z2-7]{16}' # AWS access key
    r'|AIza[\w-]{35}'                                 # GCP API key
    r'|hvs\.[\w-]{90,120}'                            # Vault service token
    r'|hvb\.[\w-]{138,300}'                           # Vault batch token
    r'|xox[bpe]-[0-9]{10,13}-[\w-]+'                  # Slack tokens
    r'|SG\.[\w=_\-.]{66}'                             # SendGrid API key
    r'|(?:sk|rk)_(?:test|live|prod)_[a-zA-Z0-9]{10,99}' # Stripe key
    r'|npm_[a-z0-9]{36}'                              # npm access token
    r'|hf_[a-zA-Z]{34}'                               # HuggingFace token
    r'|pplx-[a-zA-Z0-9]{48}'                          # Perplexity API key
    r'|dop_v1_[a-f0-9]{64}'                           # DigitalOcean PAT
    r'|ntn_[0-9]{11}[A-Za-z0-9]{35}'                  # Notion API token
    r'|glsa_[A-Za-z0-9]{32}_[A-Fa-f0-9]{8}'           # Grafana service account
    r'|pypi-AgEIcHlwaS5vcmc[\w-]{50,}'                # PyPI upload token
    r'|HRKU-AA[0-9a-zA-Z_-]{58}'                      # Heroku API key
    r')',
)

_RE_JWT = re.compile(
    r'\bey[a-zA-Z0-9]{17,}\.ey[a-zA-Z0-9/\\_-]{17,}\.[a-zA-Z0-9/\\_-]{10,}=?=?'
)

_RE_PRIVATE_KEY = re.compile(
    r'-----BEGIN[ A-Z0-9_-]{0,100}PRIVATE KEY(?:\s+BLOCK)?-----'
)

_RE_CURL_AUTH = re.compile(
    r'\bcurl\b.*?\s(?:-H|--header)\s*[=\s]*["\']'
    r'(?:Authorization:\s*(?:Basic\s+|(?:Bearer|Token)\s+))',
    re.IGNORECASE,
)

_RE_BASE64_BLOB = re.compile(r'[A-Za-z0-9+/=]{32,}')
_RE_BEARER = re.compile(r'(Bearer\s+)\S+', re.IGNORECASE)


def _shannon_entropy(data):
    if not data:
        return 0.0
    counts = {}
    for c in data:
        counts[c] = counts.get(c, 0) + 1
    length = len(data)
    return -sum((n / length) * math.log2(n / length) for n in counts.values())


def _has_secret_token(text):
    """Check if text contains a known secret pattern. Returns True if found."""
    if _PREFIXED_TOKEN_PATTERNS.search(text):
        return True
    if _RE_JWT.search(text):
        return True
    if _RE_PRIVATE_KEY.search(text):
        return True
    return False


def _has_high_entropy_blob(tokens):
    """Check if any token looks like a high-entropy secret (base64 blob with entropy >= 3.5)."""
    for token in tokens:
        clean = token.strip("\"'")
        if clean.startswith(("/", ".", "~")):
            continue
        if len(clean) >= 32 and re.match(r'^[A-Za-z0-9+/=]+$', clean):
            ent = _shannon_entropy(clean)
            if ent >= 3.5:
                return True
            if ent >= 3.0:
                unique_ratio = len(set(clean)) / len(clean)
                max_freq = max(clean.count(c) for c in set(clean)) / len(clean)
                if unique_ratio >= 0.4 and max_freq <= 0.15:
                    return True
    return False


def redact_secrets(text):
    """Redact likely secrets from command text."""
    text = _PREFIXED_TOKEN_PATTERNS.sub('<REDACTED>', text)
    text = _RE_JWT.sub('<REDACTED-JWT>', text)
    text = _RE_SECRET_ASSIGN.sub(lambda m: f'{m.group(1)}=<REDACTED>', text)
    text = _RE_BEARER.sub(r'\1<REDACTED>', text)
    def _redact_b64(m):
        val = m.group(0)
        if val.startswith(("/", ".", "~")):
            return val
        ent = _shannon_entropy(val)
        if ent >= 3.5:
            return '<REDACTED>'
        if ent >= 3.0 and len(val) >= 32:
            unique_ratio = len(set(val)) / len(val)
            max_freq = max(val.count(c) for c in set(val)) / len(val)
            if unique_ratio >= 0.4 and max_freq <= 0.15:
                return '<REDACTED>'
        return val
    text = _RE_BASE64_BLOB.sub(_redact_b64, text)
    return text


def short_project_name(project):
    """Convert a project slug to a human-readable short name."""
    if project == HOME_SLUG:
        return "(home)"
    if project.startswith(HOME_SLUG + "-"):
        return project[len(HOME_SLUG) + 1:]
    return project

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
GIT_DESTRUCTIVE_FLAGS = {
    "push": {"--force", "-f", "--force-with-lease"},
    "reset": {"--hard"},
    "clean": {"--force", "-f"},
    "branch": {"-D"},
}
GIT_READ_ONLY_SUBCMDS = {
    "status", "log", "diff", "show", "branch", "tag", "remote",
    "blame", "shortlog", "describe", "rev-parse", "rev-list",
    "ls-files", "ls-tree", "ls-remote", "cat-file", "reflog",
    "for-each-ref", "count-objects", "fsck", "whatchanged",
    "check-ignore", "help", "version",
}


def _cmd_has_secrets(raw_cmd):
    """Check if a raw Bash command contains secret material."""
    if _has_secret_token(raw_cmd):
        return True
    if _RE_CURL_AUTH.search(raw_cmd):
        return True
    m = _RE_SECRET_ASSIGN.search(raw_cmd)
    if m:
        val = m.group(2).strip("\"'")
        if (len(val) > 8
                and not val.startswith(('$', '{', 'http://', 'https://', '/'))
                and val.lower() not in (
                    'changeme', 'password', 'placeholder', 'example',
                    'your-token-here', 'your_token_here', 'replace-me',
                    'xxxxxxxx', 'test1234', 'password123', 'true', 'false',
                    'none', 'null',
                )):
            return True
    parts = raw_cmd.split()
    if len(parts) > 1 and _has_high_entropy_blob(parts[1:]):
        return True
    return False


def classify_risk(tool_name, tool_input):
    """Classify a tool call as destructive/mutating/read-only."""
    if tool_name == "Bash":
        raw_cmd = tool_input.get("command", "").strip()
        cmd = _RE_CD_PREFIX.sub('', raw_cmd)
        cmd = _RE_ENV_PREFIX.sub('', cmd)
        cmd = _RE_SHELL_OPS.sub('', cmd)
        parts = cmd.split()
        if not parts or parts[0].startswith("#"):
            return "read-only"

        base = os.path.basename(parts[0])
        # Strip trailing punctuation from parsing artifacts
        base = base.rstrip('"\')}')

        if base not in ("grep", "egrep", "fgrep", "rg", "ag", "ack", "find", "sed", "awk"):
            if _cmd_has_secrets(raw_cmd):
                return "destructive"

        # Git subcommand-aware classification
        if base == "git" and len(parts) > 1:
            subcmd = parts[1]
            if subcmd in GIT_DESTRUCTIVE_FLAGS:
                rest_args = parts[2:]
                if subcmd == "clean" and any(a in ('-n', '--dry-run') for a in rest_args):
                    return "read-only"
                for arg in rest_args:
                    if arg in GIT_DESTRUCTIVE_FLAGS[subcmd]:
                        return "destructive"
                    if subcmd == "clean" and arg.startswith("-") and not arg.startswith("--") and "f" in arg:
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

        # sed with -i (including -i.bak, -ni, etc.) is mutating, otherwise read-only
        if base == "sed":
            for arg in parts[1:]:
                if arg == "--in-place":
                    return "mutating"
                if arg.startswith("-") and not arg.startswith("--") and "i" in arg:
                    return "mutating"
            return "read-only"

        # ansible-playbook with --check/--syntax-check is read-only
        if base == "ansible-playbook":
            for arg in parts[1:]:
                if arg in ("--check", "-C", "--syntax-check", "--list-tasks", "--list-hosts"):
                    return "read-only"
            return "mutating"

        # curl: check method
        if base == "curl":
            rest = " ".join(parts[1:])
            if re.search(r'-X\s*DELETE|--request\s+DELETE', rest, re.IGNORECASE):
                return "destructive"
            if re.search(r'-X\s*(?:POST|PUT|PATCH)|--request\s+(?:POST|PUT|PATCH)|--data\b|-d\s|-F\s', rest, re.IGNORECASE):
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
        if _PREFIXED_TOKEN_PATTERNS.match(clean_base):
            return "destructive"
        if len(clean_base) >= 32 and re.match(r'^[A-Za-z0-9+/=]+$', clean_base):
            if _shannon_entropy(clean_base) >= 3.5:
                return "destructive"
        if re.match(r'^[\w]*(API_KEY|_SECRET|_TOKEN|_PASSWORD|PRIVATE_KEY|CREDENTIAL)[\w]*$', clean_base.upper()):
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
        cmd = tool_input.get("command", "").strip()
        cmd = _RE_CD_PREFIX.sub('', cmd)
        cmd = _RE_ENV_PREFIX.sub('', cmd)
        pat_normalized = pat_arg.replace(":", " ")
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
    cmd = _RE_CD_PREFIX.sub('', cmd)
    cmd = _RE_ENV_PREFIX.sub('', cmd)
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
        name = normalize_command(cmd)
        base = cmd.split()[0] if cmd.split() else ""
        if base not in ("grep", "egrep", "fgrep", "rg", "ag", "ack", "find", "sed", "awk"):
            if _cmd_has_secrets(cmd):
                name += " [secrets]"
        return f"Bash: {name}"
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
    """Get the full command string for detailed display (secrets redacted)."""
    if tool_name == "Bash":
        return redact_secrets(tool_input.get("command", "")[:300])
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

    objects = []
    for line in lines:
        try:
            objects.append(json.loads(line))
        except json.JSONDecodeError:
            continue

    assistant_by_uuid = {}
    for obj in objects:
        if obj.get("type") == "assistant":
            assistant_by_uuid[obj.get("uuid")] = obj

    for obj in objects:
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
            if len(tool_result_content) < 200:
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
            if is_rejected:
                auto = False
            risk = classify_risk(tool_name, tool_input)

            has_secrets = (tool_name == "Bash"
                          and _cmd_has_secrets(tool_input.get("command", "")))

            redacted_input = tool_input
            if tool_name == "Bash" and "command" in tool_input:
                redacted_input = dict(tool_input)
                redacted_input["command"] = redact_secrets(tool_input["command"])

            records.append({
                "project": project_name,
                "session": os.path.basename(jsonl_path),
                "tool_name": tool_name,
                "tool_input": redacted_input,
                "display": get_tool_display(tool_name, tool_input),
                "full_command": get_tool_full_command(tool_name, tool_input),
                "rejected": is_rejected,
                "auto_allowed": auto,
                "risk": risk,
                "timestamp": obj.get("timestamp", ""),
                "_has_secrets": has_secrets,
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


_SECRET_KEYWORDS_RE = re.compile(
    r'(API_KEY|SECRET|TOKEN|PASSWORD|PRIVATE_KEY|CREDENTIAL)', re.IGNORECASE
)


def _find_secret_exposures(records):
    """Find records where secrets were exposed in commands.

    Returns list of (record, category) tuples where category is one of:
    token, jwt, private_key, auth_header, secret_assign, high_entropy.
    Uses pre-computed _has_secrets flag and redacted command for categorization.
    """
    results = []
    for r in records:
        if r["rejected"]:
            continue
        if r["tool_name"] != "Bash":
            continue
        if not r.get("_has_secrets"):
            continue

        cmd = r["tool_input"].get("command", "")
        if _PREFIXED_TOKEN_PATTERNS.search(cmd):
            results.append((r, "token"))
        elif _RE_JWT.search(cmd):
            results.append((r, "jwt"))
        elif _RE_PRIVATE_KEY.search(cmd):
            results.append((r, "private_key"))
        elif _RE_CURL_AUTH.search(cmd):
            results.append((r, "auth_header"))
        elif _RE_SECRET_ASSIGN.search(cmd):
            results.append((r, "secret_assign"))
        else:
            results.append((r, "high_entropy"))

    return results


def _count_secret_exposures(records):
    """Count records where secrets were exposed in command arguments."""
    return len(_find_secret_exposures(records))


SECRET_WARNING = (
    "WARNING: These secrets are already written to disk in session JSONL files\n"
    "  (~/.claude/projects/) and were sent to the Claude API. They should be\n"
    "  rotated and considered compromised."
)


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
                _print(f"  [{short_project_name(r['project'])}] {r['tool_name']}: {fc}")
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
        _print(f"  {count:<8} {risk:<14} {short_project_name(project):<18} {pattern}")
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

    secret_count = _count_secret_exposures(all_records)
    if secret_count:
        _print()
        _print(f"  Secret exposures: {secret_count} commands contained secrets/keys/tokens")
        _print(f"  {SECRET_WARNING}")
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
        _print(f"  {short_project_name(proj):<35} {len(proj_records):>8} {p_auto:>8} {p_prompted:>8} {p_rejected:>8}")
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
    """Return a single pattern suitable for writing to settings.local.json, or None if invalid."""
    pattern = suggest_pattern(display)
    if " or " in pattern:
        pattern = pattern.split(" or ")[1]
    if not re.match(r'^[\w]+(\(.*\))?$', pattern):
        return None
    m = re.match(r'^Bash\((.+)\)$', pattern)
    if m:
        inner = m.group(1)
        cmd_name = inner.split()[0] if inner.split() else ''
        if cmd_name.startswith(('-', '(', '[')) or not cmd_name:
            return None
        if cmd_name in ('*', '**'):
            return None
    return pattern


def build_suggestions(all_records, min_approvals=3):
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
            if count >= min_approvals:
                cmd_suffix = cmd.split(": ", 1)[1] if ": " in cmd else cmd
                if cmd_suffix in skip_patterns:
                    continue
                if cmd_suffix.endswith(" [secrets]"):
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
    if project_name == HOME_SLUG:
        return Path.home() / ".claude" / "settings.local.json"

    if not project_name.startswith(HOME_SLUG + "-"):
        return None

    project_subdir = project_name[len(HOME_SLUG) + 1:]
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


MIN_PROJECTS_FOR_GLOBAL = 3


def _collect_applicable(all_records, risk_level="read-only", min_approvals=3):
    """Collect applicable suggestions grouped by project. Returns (by_project, pattern_projects).

    by_project: {project: [(pattern, count, risk), ...]}
    pattern_projects: {pattern: set of projects} — how many projects use each pattern
    """
    suggestions = build_suggestions(all_records, min_approvals=min_approvals)

    allowed_risks = {"read-only"}
    if risk_level == "mutating":
        allowed_risks.add("mutating")

    by_project = defaultdict(list)
    pattern_projects = defaultdict(set)
    for count, project, cmd, pattern, risk in suggestions:
        if risk not in allowed_risks:
            continue
        applicable = suggest_pattern_applicable(cmd)
        if applicable is None:
            continue
        by_project[project].append((applicable, count, risk))
        pattern_projects[applicable].add(project)

    return by_project, pattern_projects


def _atomic_write(out_path, write_fn, mode=0o644):
    """Write to out_path atomically via tempfile + rename."""
    dir_path = os.path.dirname(os.path.abspath(out_path))
    fd, tmp_path = tempfile.mkstemp(dir=dir_path, suffix=".tmp")
    try:
        with os.fdopen(fd, "w") as f:
            write_fn(f)
            f.flush()
            os.fsync(f.fileno())
        os.chmod(tmp_path, mode)
        os.rename(tmp_path, str(out_path))
    except BaseException:
        try:
            os.unlink(tmp_path)
        except OSError:
            pass
        raise


def _write_settings(path, settings, dry_run):
    """Write settings JSON to path unless dry_run."""
    if dry_run:
        return
    if not path.parent.exists():
        print(f"    Skipping: {path.parent} does not exist", file=sys.stderr)
        return
    def _do_write(f):
        json.dump(settings, f, indent=2)
        f.write("\n")
    _atomic_write(path, _do_write, mode=0o600)


def _load_settings(path):
    """Load JSON settings from path, returning empty dict on missing/invalid."""
    if path.exists():
        try:
            with open(path) as f:
                return json.load(f)
        except (json.JSONDecodeError, OSError):
            pass
    return {}


def apply_suggestions(all_records, risk_level="read-only", dry_run=False, scope="project", quiet=False, min_approvals=3):
    """Apply suggested allowlist patterns to settings files.

    scope: 'project' — per-project settings.local.json only (default)
           'global'  — patterns in 3+ projects go to ~/.claude/settings.json
           'both'    — global patterns to settings.json, remainder to settings.local.json
    """
    by_project, pattern_projects = _collect_applicable(all_records, risk_level, min_approvals=min_approvals)

    _log = (lambda *a, **kw: None) if quiet else (lambda *a, **kw: print(*a, file=sys.stderr, **kw))

    if not by_project:
        _log("No applicable suggestions found.")
        return

    global_patterns = set()
    if scope in ("global", "both"):
        global_patterns = {p for p, projs in pattern_projects.items()
                          if len(projs) >= MIN_PROJECTS_FOR_GLOBAL}

    total_added = 0

    # --- Global settings ---
    if global_patterns:
        global_path = CLAUDE_DIR / "settings.json"
        global_settings = _load_settings(global_path)
        existing_global = set(global_settings.get("permissions", {}).get("allow", []))

        new_global = sorted(global_patterns - existing_global)
        if new_global:
            project_count = {p: len(pattern_projects[p]) for p in new_global}
            _log(f"\n  GLOBAL: {global_path}")
            for pattern in new_global:
                _log(f"    + {pattern}  ({project_count[pattern]} projects)")

            if not dry_run:
                if "permissions" not in global_settings:
                    global_settings["permissions"] = {}
                if "allow" not in global_settings["permissions"]:
                    global_settings["permissions"]["allow"] = []
                global_settings["permissions"]["allow"].extend(new_global)
                _write_settings(global_path, global_settings, dry_run)

            total_added += len(new_global)

    # --- Per-project settings ---
    if scope in ("project", "both"):
        for project, patterns in sorted(by_project.items()):
            settings_path = project_settings_path(project)
            if settings_path is None:
                continue

            settings = _load_settings(settings_path)
            existing = set(settings.get("permissions", {}).get("allow", []))

            new_patterns = []
            for pattern, count, risk in patterns:
                if scope == "both" and pattern in global_patterns:
                    continue
                if pattern not in existing:
                    new_patterns.append((pattern, count, risk))

            if not new_patterns:
                continue

            _log(f"\n  {short_project_name(project)}: {settings_path}")
            for pattern, count, risk in new_patterns:
                _log(f"    + {pattern}  ({count} approvals, {risk})")

            if not dry_run:
                if "permissions" not in settings:
                    settings["permissions"] = {}
                if "allow" not in settings["permissions"]:
                    settings["permissions"]["allow"] = []
                for pattern, count, risk in new_patterns:
                    settings["permissions"]["allow"].append(pattern)
                _write_settings(settings_path, settings, dry_run)

            total_added += len(new_patterns)

    if scope == "global":
        action = "Would add" if dry_run else "Added"
        _log(f"\n  {action} {total_added} global patterns.")
    else:
        action = "Would add" if dry_run else "Added"
        scope_label = "globally + per-project" if scope == "both" else "per-project"
        _log(f"\n  {action} {total_added} patterns ({scope_label}).")


# --- Main ---

def _is_duration(value):
    """Return True if *value* looks like a relative duration (7d, 2w, 1m)."""
    return bool(re.match(r'^\d+[dwm]$', value))


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


def _duration_to_days(value):
    """Convert a duration string to approximate number of days."""
    m = re.match(r'^(\d+)([dwm])$', value)
    if not m:
        return None
    num = int(m.group(1))
    unit = m.group(2)
    if unit == "d":
        return num
    elif unit == "w":
        return num * 7
    elif unit == "m":
        return num * 30
    return None


def _auto_bucket(days):
    """Pick a sensible bucket size for a given window in days."""
    if days <= 31:
        return "day"
    if days <= 90:
        return "week"
    if days <= 730:
        return "month"
    if days <= 1825:
        return "quarter"
    return "year"


def _parse_ts(ts):
    """Parse a timestamp string to a timezone-aware datetime, or None on failure."""
    if not ts:
        return None
    try:
        return datetime.fromisoformat(ts.replace("Z", "+00:00"))
    except (ValueError, TypeError):
        return None


def filter_records(records, since=None, project=None):
    """Filter records by time and/or project."""
    if since:
        records = [r for r in records
                   if (dt := _parse_ts(r.get("timestamp", ""))) is not None and dt >= since]
    if project:
        full_name = HOME_SLUG + "-" + project
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

    projects = {}
    for proj in sorted(set(r["project"] for r in all_records)):
        proj_records = [r for r in all_records if r["project"] == proj]
        projects[short_project_name(proj)] = {
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

    secret_count = _count_secret_exposures(all_records)
    if secret_count:
        _print(f"  Secrets: {secret_count} secret-exposure commands approved")
        _print(f"  {SECRET_WARNING}")

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


def render_trend(all_records, bucket="day", out=None):
    """Render a time-series trend of approval rates."""
    if out is None:
        out = sys.stdout
    _print = lambda *a, **kw: print(*a, file=out, **kw)

    def parse_ts(ts):
        if not ts:
            return None
        try:
            return datetime.fromisoformat(ts.replace("Z", "+00:00"))
        except (ValueError, AttributeError):
            return None

    def bucket_key(dt):
        if bucket == "week":
            monday = dt - timedelta(days=dt.weekday())
            return monday.strftime("%Y-%m-%d")
        elif bucket == "month":
            return dt.strftime("%Y-%m")
        elif bucket == "quarter":
            q = (dt.month - 1) // 3 + 1
            return f"{dt.year}-Q{q}"
        elif bucket == "year":
            return dt.strftime("%Y")
        return dt.strftime("%Y-%m-%d")

    buckets = defaultdict(lambda: {"total": 0, "auto": 0, "prompted": 0, "rejected": 0,
                                    "destructive": 0, "mutating": 0, "read-only": 0, "secrets": 0})

    for r in all_records:
        dt = parse_ts(r.get("timestamp", ""))
        if dt is None:
            continue
        key = bucket_key(dt)
        b = buckets[key]
        b["total"] += 1
        if r["rejected"]:
            b["rejected"] += 1
        elif r["auto_allowed"]:
            b["auto"] += 1
        else:
            b["prompted"] += 1
        risk = r.get("risk", "unknown")
        if risk in ("destructive", "mutating", "read-only"):
            b[risk] += 1
        display = r.get("display", "")
        if "[secrets]" in display:
            b["secrets"] += 1

    if not buckets:
        _print("No timestamped records found.")
        return

    sorted_keys = sorted(buckets.keys())

    if len(sorted_keys) > 100:
        print(f"Warning: {len(sorted_keys)} rows of trend data. "
              f"Consider a larger bucket (--bucket week/month/quarter/year) "
              f"or narrower window (--trend 30d).", file=sys.stderr)

    label = {"day": "Day", "week": "Week of", "month": "Month",
             "quarter": "Quarter", "year": "Year"}.get(bucket, "Period")
    hdr = f"  {label:<12} {'Total':>7} {'Auto':>7} {'Prompted':>10} {'Rej':>4} {'Auto%':>6} {'Destr':>6} {'Mutat':>7} {'R/O':>7} {'Sec':>4}"
    sep = f"  {'-'*12} {'-'*7} {'-'*7} {'-'*10} {'-'*4} {'-'*6} {'-'*7} {'-'*7} {'-'*7} {'-'*4}"
    _print(f"CLAUDE CODE TREND ANALYSIS (by {bucket})")
    _print("=" * len(hdr))
    _print(hdr)
    _print(sep)

    def fmt_row(key, b, arrow=""):
        auto_pct = (b["auto"] / b["total"] * 100) if b["total"] else 0
        prompted_s = f"{b['prompted']:,}"
        if arrow:
            prompted_s += " " + arrow
        return (f"  {key:<12} {b['total']:>7,} {b['auto']:>7,} {prompted_s:>10}"
                f" {b['rejected']:>4} {auto_pct:>5.1f}% {b['destructive']:>6}"
                f" {b['mutating']:>7,} {b['read-only']:>7,} {b['secrets']:>4}")

    prev_prompted = None
    for key in sorted_keys:
        b = buckets[key]
        arrow = ""
        if prev_prompted is not None and b["prompted"] > 0:
            if b["prompted"] < prev_prompted:
                arrow = "↓"
            elif b["prompted"] > prev_prompted:
                arrow = "↑"
        prev_prompted = b["prompted"]
        _print(fmt_row(key, b, arrow))

    totals = {"total": 0, "auto": 0, "prompted": 0, "rejected": 0,
              "destructive": 0, "mutating": 0, "read-only": 0, "secrets": 0}
    for b in buckets.values():
        for k in totals:
            totals[k] += b[k]

    _print(sep)
    _print(fmt_row("TOTAL", totals))

    if len(sorted_keys) >= 2:
        first = buckets[sorted_keys[0]]
        last = buckets[sorted_keys[-1]]
        first_pct = (first["auto"] / first["total"] * 100) if first["total"] else 0
        last_pct = (last["auto"] / last["total"] * 100) if last["total"] else 0
        delta = last_pct - first_pct
        direction = "up" if delta > 0 else "down" if delta < 0 else "flat"
        _print(f"\n  Auto-allow rate: {first_pct:.1f}% ({sorted_keys[0]}) -> {last_pct:.1f}% ({sorted_keys[-1]}), {direction} {abs(delta):.1f}pp")

        first_prompted = first["prompted"]
        last_prompted = last["prompted"]
        if first_prompted > 0:
            prompt_change = ((last_prompted - first_prompted) / first_prompted) * 100
            _print(f"  Prompts: {first_prompted} ({sorted_keys[0]}) -> {last_prompted} ({sorted_keys[-1]}), {prompt_change:+.0f}%")


BASELINE_DENY_RULES = [
    "Read(**/.env*)",
    "Read(**/.dev.vars*)",
    "Read(**/*.pem)",
    "Read(**/*.key)",
    "Read(**/*.p12)",
    "Read(**/*.pfx)",
    "Read(**/secrets/**)",
    "Read(**/credentials/**)",
    "Read(**/.aws/**)",
    "Read(**/.ssh/**)",
    "Read(**/.vault-token)",
    "Read(**/.vault_token)",
    "Read(**/.npmrc)",
    "Read(**/.pypirc)",
    "Read(**/credentials.json)",
    "Read(**/.kube/config)",
    "Read(**/.docker/config.json)",
    "Read(**/.netrc)",
    "Read(**/.pgpass)",
    "Read(**/.ansible-vault-password*)",
    "Write(**/.env*)",
    "Write(**/.dev.vars*)",
    "Write(**/*.pem)",
    "Write(**/*.key)",
    "Write(**/*.p12)",
    "Write(**/*.pfx)",
    "Write(**/secrets/**)",
    "Write(**/credentials/**)",
    "Write(**/.aws/**)",
    "Write(**/.ssh/**)",
    "Write(**/.vault-token)",
    "Write(**/.vault_token)",
    "Write(**/credentials.json)",
    "Write(**/.kube/config)",
    "Write(**/.docker/config.json)",
    "Write(**/.netrc)",
    "Write(**/.pgpass)",
    "Write(**/.npmrc)",
    "Write(**/.pypirc)",
    "Write(**/.ansible-vault-password*)",
    "Edit(**/.env*)",
    "Edit(**/.dev.vars*)",
    "Edit(**/*.pem)",
    "Edit(**/*.key)",
    "Edit(**/*.p12)",
    "Edit(**/*.pfx)",
    "Edit(**/secrets/**)",
    "Edit(**/credentials/**)",
    "Edit(**/.aws/**)",
    "Edit(**/.ssh/**)",
    "Edit(**/.vault-token)",
    "Edit(**/.vault_token)",
    "Edit(**/credentials.json)",
    "Edit(**/.kube/config)",
    "Edit(**/.docker/config.json)",
    "Edit(**/.netrc)",
    "Edit(**/.pgpass)",
    "Edit(**/.npmrc)",
    "Edit(**/.pypirc)",
    "Edit(**/.ansible-vault-password*)",
]


def render_generate_settings(all_records, out=None):
    """Generate recommended deny rules and hook config based on session analysis."""
    if out is None:
        out = sys.stdout

    hooks_dir = Path(__file__).resolve().parent / "hooks"
    pre_hook = hooks_dir / "block-secrets.py"
    post_hook = hooks_dir / "warn-secrets-output.py"
    pre_cmd = f"python3 {pre_hook}" if pre_hook.exists() else "python3 <PATH_TO>/hooks/block-secrets.py"
    post_cmd = f"python3 {post_hook}" if post_hook.exists() else "python3 <PATH_TO>/hooks/warn-secrets-output.py"

    settings = {
        "permissions": {
            "deny": list(BASELINE_DENY_RULES),
        },
        "hooks": {
            "PreToolUse": [
                {
                    "matcher": "Bash|Read|Edit|Write",
                    "hooks": [{"type": "command", "command": pre_cmd}],
                },
            ],
            "PostToolUse": [
                {
                    "matcher": "Bash|Read|Edit",
                    "hooks": [{"type": "command", "command": post_cmd}],
                },
            ],
        },
    }

    print(f"\nRecommended security settings", file=sys.stderr)
    print(f"  Deny rules: {len(BASELINE_DENY_RULES)} patterns (Read/Write/Edit for sensitive files)", file=sys.stderr)

    global_settings = load_global_settings()
    existing_deny = set(global_settings.get("permissions", {}).get("deny", []))
    new_deny = [r for r in BASELINE_DENY_RULES if r not in existing_deny]
    already = len(BASELINE_DENY_RULES) - len(new_deny)

    if existing_deny:
        print(f"  Already in ~/.claude/settings.json: {already} of {len(BASELINE_DENY_RULES)}", file=sys.stderr)
        if new_deny:
            print(f"  New additions:", file=sys.stderr)
            for rule in new_deny:
                print(f"    + {rule}", file=sys.stderr)
        else:
            print(f"  All baseline deny rules already configured.", file=sys.stderr)

    if all_records:
        exposures = _find_secret_exposures(all_records)
        if exposures:
            print(f"\n  Session analysis: {len(exposures)} secret exposure(s) found", file=sys.stderr)

            category_labels = {
                "token": "Known token patterns",
                "jwt": "JWT tokens",
                "private_key": "Private key material",
                "auth_header": "Authorization headers",
                "secret_assign": "Secret variable assignments",
                "high_entropy": "High-entropy blobs",
            }
            by_category = Counter(cat for _, cat in exposures)
            for cat, count in by_category.most_common():
                label = category_labels.get(cat, cat)
                print(f"    {label}: {count} (blocked by hook)", file=sys.stderr)

            print(f"\n  The PreToolUse hook would have blocked all {len(exposures)} exposure(s).", file=sys.stderr)
            print(f"  Deny rules alone cannot prevent embedded secrets in Bash commands.", file=sys.stderr)
        else:
            print(f"\n  Session analysis: no secret exposures found in analyzed sessions.", file=sys.stderr)
    else:
        print(f"\n  No session data analyzed (use --since/--project to include).", file=sys.stderr)

    print(f"\n  PreToolUse hook: {pre_cmd}", file=sys.stderr)
    print(f"  PostToolUse hook: {post_cmd}", file=sys.stderr)
    print(f"  Merge the JSON output into ~/.claude/settings.json to enable protection.", file=sys.stderr)
    print(f"\n  Residual risks (mitigations in README):", file=sys.stderr)
    print(f"    - Pre-existing copies: files copied before hook install aren't tracked", file=sys.stderr)
    print(f"      → Use filesystem-level MAC/audit on sensitive paths", file=sys.stderr)
    print(f"    - Output capture: PostToolUse hook warns but cannot prevent (command already ran)", file=sys.stderr)
    print(f"      → Use MCP servers for secret access instead of CLI", file=sys.stderr)
    print(f"    - Encoded payloads: obfuscated secrets below entropy threshold", file=sys.stderr)
    print(f"      → Most real secrets exceed the 3.5 bits/char threshold\n", file=sys.stderr)

    json.dump(settings, out, indent=2)
    out.write("\n")


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
        pname = short_project_name(proj)
        if matching_pattern:
            status_parts.append(f"YES in {pname} ({matching_pattern})")
        else:
            status_parts.append(f"NO in {pname}")
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

    project_dirs = [d for d in sorted(PROJECTS_DIR.iterdir()) if d.is_dir()]
    if project_filter:
        full_name = HOME_SLUG + "-" + project_filter
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
        help="Write suggested patterns to settings files. "
             "Default: only read-only commands. 'mutating' includes mutating too. "
             "Never auto-applies destructive patterns.",
    )
    parser.add_argument(
        "--scope",
        default="project",
        choices=["project", "global", "both"],
        help="With --apply: 'project' writes to each project's settings.local.json (default), "
             "'global' consolidates patterns appearing in 3+ projects into ~/.claude/settings.json, "
             "'both' writes global patterns to settings.json and project-specific ones to settings.local.json.",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        default=False,
        help="With --apply, show what would be added without writing.",
    )
    parser.add_argument(
        "--auto",
        action="store_true",
        default=False,
        help="With --apply, skip interactive confirmation. Only applies read-only patterns "
             "regardless of --apply level. Use with --dry-run first to preview.",
    )
    parser.add_argument(
        "--min-approvals",
        type=int,
        default=None,
        metavar="N",
        help="With --apply, only suggest patterns approved at least N times (default: 3).",
    )
    parser.add_argument(
        "--summary", "--brief",
        action="store_true",
        default=False,
        help="Compact dashboard instead of full report.",
    )
    parser.add_argument(
        "--trend",
        nargs="?",
        const="",
        default=None,
        metavar="WINDOW",
        help="Show approval rate trends. Optional time window (7d, 2w, 1m, 90d) "
             "auto-selects bucket size. Use --bucket to override.",
    )
    parser.add_argument(
        "--bucket",
        default=None,
        choices=["day", "week", "month", "quarter", "year"],
        help="Bucket size for --trend. Auto-selected from window if omitted.",
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
    parser.add_argument(
        "--generate-settings",
        action="store_true",
        default=False,
        help="Generate recommended deny rules and hook config. "
             "Outputs JSON settings fragment to stdout. "
             "Combine with --since/--project for data-driven analysis.",
    )
    args = parser.parse_args()

    trend_window = args.trend if args.trend is not None else None
    if trend_window and _is_duration(trend_window):
        if args.since:
            print(f"Warning: --trend {trend_window} overrides --since {args.since}",
                  file=sys.stderr)
        args.since = trend_window
    elif trend_window and trend_window != "":
        print(f"Error: invalid --trend window '{trend_window}'. "
              f"Use a duration like 7d, 2w, 1m, 90d.", file=sys.stderr)
        sys.exit(1)

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

    if not all_records and not args.generate_settings:
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

    if args.generate_settings:
        if args.output is None:
            render_generate_settings(all_records)
        else:
            if args.output == "auto":
                out_path = f"claude-security-settings-{datetime.now(timezone.utc).strftime('%Y-%m-%dT%H%M%SZ')}.json"
            elif os.path.isdir(args.output):
                out_path = os.path.join(args.output, f"claude-security-settings-{datetime.now(timezone.utc).strftime('%Y-%m-%dT%H%M%SZ')}.json")
            else:
                out_path = args.output
            _atomic_write(out_path, lambda f: render_generate_settings(all_records, out=f))
            print(f"Settings written to {out_path}", file=sys.stderr)
        return

    if args.why:
        render_why(args.why, all_records)
        return

    if args.apply is not None:
        min_approvals = args.min_approvals if args.min_approvals is not None else 3
        risk_level = args.apply
        if args.auto:
            risk_level = "read-only"
        apply_kwargs = dict(risk_level=risk_level, scope=args.scope, min_approvals=min_approvals)
        if args.dry_run:
            apply_suggestions(all_records, dry_run=True, **apply_kwargs)
        elif args.auto:
            apply_suggestions(all_records, dry_run=False, **apply_kwargs)
        else:
            if not sys.stdin.isatty():
                print("Error: --apply requires an interactive terminal or --auto.", file=sys.stderr)
                print("Use --dry-run to preview, --auto to apply without confirmation.", file=sys.stderr)
                sys.exit(1)
            apply_suggestions(all_records, dry_run=True, **apply_kwargs)
            answer = input("\n  Apply these changes? [y/N] ").strip().lower()
            if answer != "y":
                print("Aborted.", file=sys.stderr)
                return
            apply_suggestions(all_records, dry_run=False, quiet=True, **apply_kwargs)
    elif args.trend is not None:
        window_days = _duration_to_days(args.trend) if args.trend else None

        if args.bucket:
            trend_bucket = args.bucket
        elif window_days:
            trend_bucket = _auto_bucket(window_days)
        else:
            trend_bucket = "day"

        if args.output is None:
            render_trend(all_records, bucket=trend_bucket)
        else:
            if args.output == "auto":
                out_path = f"claude-trend-{datetime.now(timezone.utc).strftime('%Y-%m-%dT%H%M%SZ')}.txt"
            elif os.path.isdir(args.output):
                out_path = os.path.join(args.output, f"claude-trend-{datetime.now(timezone.utc).strftime('%Y-%m-%dT%H%M%SZ')}.txt")
            else:
                out_path = args.output
            _atomic_write(out_path, lambda f: render_trend(all_records, bucket=trend_bucket, out=f))
            print(f"Trend written to {out_path}", file=sys.stderr)
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
            _atomic_write(out_path, lambda f: renderer(all_records, out=f))
            print(f"Report written to {out_path}", file=sys.stderr)


if __name__ == "__main__":
    main()
