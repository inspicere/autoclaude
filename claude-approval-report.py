#!/usr/bin/env python3
"""Analyze Claude Code session data to find which commands required the most user approval."""

import sys
if sys.version_info < (3, 11):
    sys.exit("Error: Python 3.11+ required. Found " + ".".join(map(str, sys.version_info[:3])))

import argparse
import hashlib
import json
import math
import os
import re
import stat
import subprocess
import tempfile
import time
from collections import defaultdict, Counter
from datetime import datetime, timedelta, timezone
from functools import lru_cache
from pathlib import Path
from fnmatch import fnmatch


def _read_version():
    """Read version from pyproject.toml. Returns 'unknown' if not found."""
    pyproject = Path(__file__).resolve().parent / "pyproject.toml"
    if not pyproject.exists():
        return "unknown"
    try:
        import tomllib
        with open(pyproject, "rb") as f:
            return tomllib.load(f).get("project", {}).get("version", "unknown")
    except (OSError, ImportError, KeyError):
        return "unknown"


__version__ = _read_version()

CLAUDE_DIR = Path.home() / ".claude"
PROJECTS_DIR = CLAUDE_DIR / "projects"
HOME_SLUG = "-" + str(Path.home()).lstrip("/").replace("/", "-")


def _cwd_to_project_slug():
    """Return the Claude Code project slug matching the current working dir.

    Claude Code mirrors filesystem paths to projects by replacing `/` with `-`
    and prefixing a leading `-`. /home/terrabot/autoclaude → -home-terrabot-autoclaude.
    Used by --no-cross-project to constrain the scan to the CWD's project.
    """
    return "-" + os.getcwd().lstrip("/").replace("/", "-")

# cd-prefix accepts `&&`, `;`, or a literal newline as the separator before
# the next command. Newlines occur in multi-line tool inputs where a script
# uses implicit newline-as-separator instead of `&&`.
_RE_CD_PREFIX = re.compile(
    r'^(cd\s+(?:\S+|"[^"]*"|\'[^\']*\')\s*(?:&&|;|\n)\s*)+'
)
# Env-prefix matches VAR=value pairs at the start of a command. The value
# alternatives are tried in order: $(subshell), `subshell`, ${brace}, "double",
# 'single', \S+. Subshell-first ordering prevents the strip from over-consuming
# when the value contains `$(...)` (see issue #4).
_RE_ENV_PREFIX = re.compile(
    r'^(\w+=(?:\$\(.*?\)|`[^`]*`|\$\{[^}]*\}|"[^"]*"|\'[^\']*\'|\S+)\s+)+'
)
_RE_SHELL_OPS = re.compile(r'^[&|;]+\s*')
# Backslash line continuation: `\<newline>` should be collapsed to whitespace
# before prefix-stripping so multi-line scripts classify like their joined form.
_RE_LINE_CONT = re.compile(r'\\\s*\n\s*')
# Used to find the boundary between a command-runner argument (e.g. `source X`)
# and the chained command that follows (`&& Y`, `; Y`, `|| Y`).
_RE_CMD_CHAIN = re.compile(r'\s+(?:&&|\|\||;)\s+')
# Matches a timeout duration argument like `5`, `5s`, `1.5m`, `30`.
_RE_TIMEOUT_DURATION = re.compile(r'^\d+\.?\d*[smhd]?$')
# Commands that *search for* patterns rather than *using* secrets — exempt from
# the inline secret scan in classify_risk. When one of these is wrapped in a
# command-runner (`timeout … grep …`, `source … && grep …`), the exemption must
# follow the resolved base, not the wrapper; see `_effective_base`.
_GREP_FAMILY = ("grep", "egrep", "fgrep", "rg", "ag", "ack", "find", "sed", "awk")

# --- Secret detection (patterns derived from gitleaks) ---

_RE_SECRET_ASSIGN = re.compile(
    r'\b(\w{0,50}(?:API_KEY|SECRET|TOKEN|PASSWORD|PRIVATE_KEY|CREDENTIAL|_AUTH|AUTH_)\w*)'
    r'=\s*((?:"[^"]*"|\'[^\']*\'|\S+))',
    re.IGNORECASE,
)

# A secret-named variable assigned *directly* from an environment read puts no
# literal secret in the command text — the value is pulled from the process
# environment at runtime. Anchored end-to-end so a literal welded onto the read
# (e.g. os.getenv("X")or"...") does not match and is still treated as exposed.
# Kept identical to the same-named pattern in hooks/block-secrets.py.
_RE_ENV_READ_VALUE = re.compile(
    r'''^(?:
          os\.environ\[\s*(?:"[^"]*"|'[^']*')\s*\]          # os.environ["X"]
        | os\.environ\.get\(\s*(?:"[^"]*"|'[^']*')\s*\)     # os.environ.get("X")
        | os\.getenv\(\s*(?:"[^"]*"|'[^']*')\s*\)           # os.getenv("X")
        | process\.env\.[A-Za-z_$][\w$]*                    # process.env.X (Node)
        | process\.env\[\s*(?:"[^"]*"|'[^']*')\s*\]         # process.env["X"] (Node)
      )$''',
    re.VERBOSE,
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
    r'-----BEGIN (?:(?:RSA|DSA|EC|OPENSSH|PGP|ENCRYPTED) )?PRIVATE KEY(?:\s+BLOCK)?-----'
)

_RE_CURL_AUTH = re.compile(
    r'\bcurl\b.*?\s(?:-H|--header)\s*[=\s]*["\']'
    r'(?:Authorization:\s*(?:Basic\s+|(?:Bearer|Token)\s+))',
    re.IGNORECASE,
)

_RE_BASE64_BLOB = re.compile(r'[A-Za-z0-9+/=]{32,}')
_RE_BEARER = re.compile(r'(Bearer\s+)\S+', re.IGNORECASE)
_RE_HEX = re.compile(r'^[0-9a-fA-F]+$')
_RE_PATH_SEGMENT = re.compile(r'^[A-Za-z0-9._-]+$')
# A leading ``IDENT=`` shell/property assignment prefix (issue #9). When present,
# the entropy of the *value* is what matters, not the welded identifier.
_RE_IDENT_ASSIGN_PREFIX = re.compile(r'^[A-Za-z_][A-Za-z0-9_]*=')
# An alphanumeric source identifier (camelCase/PascalCase, possibly with digits).
_RE_IDENTIFIER_TOKEN = re.compile(r'^[A-Za-z][A-Za-z0-9]*$')
# Trailing shell statement separators welded onto a ``\S+``-captured value, e.g.
# ``os.environ["X"];`` from ``TOKEN=os.environ["X"]; NAME=y`` (issue #9). ``)`` is
# intentionally excluded — it can be a legitimate trailing char of an env read.
_RE_VALUE_TRAILER = re.compile(r'[;&|]+$')


def _shannon_entropy(data):
    if not data:
        return 0.0
    counts = {}
    for c in data:
        counts[c] = counts.get(c, 0) + 1
    length = len(data)
    return -sum((n / length) * math.log2(n / length) for n in counts.values())


def _is_lowercase_dominant(s):
    """True if >50% of characters are lowercase letters.

    camelCase/PascalCase source identifiers (incl. embedded digits, e.g.
    ``linuxX64``, ``UnusedMaterial3ScaffoldPaddingParameter``) are lowercase-word
    dominant; random base64 is ~40% lowercase (26 of 64 alphabet chars), so a
    >0.5 threshold separates source symbols from secret blobs (issue #9).
    """
    return bool(s) and sum(c.islower() for c in s) / len(s) > 0.5


def _is_benign_high_entropy(s):
    """True if a >=32-char [A-Za-z0-9+/=] run is benign, not a secret.

    Mirrors the hook's ``_is_benign_high_entropy`` so the report's detector
    stops over-counting the same false positives the hook already exempts:
    - ``IDENT=value`` prefixes (``CANON=/home/...``, ``KEY=true``): judge the
      value, not the welded identifier (issue #9 A).
    - Pure-alphabetic identifiers (camelCase/PascalCase source symbols). Real
      base64 secrets carry digits and/or ``+`` ``/`` ``=``.
    - Pure-hex digests of git/sha lengths (40 = sha1/commit, 64 = sha256).
    - Lowercase-dominant alphanumeric identifiers (``linuxX64``,
      ``UnusedMaterial3...``) — camelCase symbols with digits (issue #9 B/3).
    - ``/`` or ``+`` delimited paths/lists whose every segment is itself a
      filename-shaped, low-entropy-or-lowercase-dominant token (e.g.
      ``app/src/main/kotlin/...``, ``iosArm64/linuxX64``). ``_RE_BASE64_BLOB``
      permits ``/`` and ``+``, so deep relative paths cross the entropy
      threshold; a real base64 blob keeps a high-entropy (low-lowercase) segment
      and still falls through to scoring (issue #7, #9).
    """
    m = _RE_IDENT_ASSIGN_PREFIX.match(s)
    if m and m.end() < len(s):
        return _is_benign_high_entropy(s[m.end():])
    if s.isalpha():
        return True
    if len(s) in (40, 64) and _RE_HEX.match(s):
        return True
    if _RE_IDENTIFIER_TOKEN.match(s) and _is_lowercase_dominant(s):
        return True
    if '/' in s or '+' in s:
        segs = [seg for seg in re.split(r'[/+]', s) if seg]
        if segs and all(
            _RE_PATH_SEGMENT.match(seg)
            and (seg.isalpha() or _shannon_entropy(seg) < 3.0 or _is_lowercase_dominant(seg))
            for seg in segs
        ):
            return True
    return False


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
            if _is_benign_high_entropy(clean):
                continue
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
        if _is_benign_high_entropy(val):
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
        # An env read (os.environ[...] / os.getenv(...) / process.env.X) puts no
        # literal secret in the command text. Strip a trailing shell terminator
        # first so a welded `;`/`&`/`|` from a following statement doesn't defeat
        # the anchored match (issue #9 C).
        if (not _RE_ENV_READ_VALUE.match(_RE_VALUE_TRAILER.sub('', val))
                and len(val) > 8
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
        return _classify_bash(tool_input.get("command", "").strip())

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


def _classify_source_chain(cmd, depth):
    """Classify a `source X [&& Y]` invocation by dispatching to Y if present."""
    m = _RE_CMD_CHAIN.search(cmd)
    if m:
        rest = cmd[m.end():].strip().rstrip(')').strip()
        if rest:
            return _classify_bash(rest, depth + 1)
    return "mutating"


def _timeout_cmd_index(parts):
    """Return the index of the wrapped command after `timeout`'s flags+duration.

    `parts` is the tokenized `timeout …` command. Returns the index just past
    the duration argument (which may equal len(parts) for a bare `timeout 5`),
    or None when the form is malformed (no duration found).
    """
    i = 1
    while i < len(parts):
        tok = parts[i]
        # Paired flags: consume flag and its value.
        if tok in ('-k', '--kill-after', '-s', '--signal'):
            i += 2
            continue
        # Long-form `--flag=value` paired flags.
        if tok.startswith('--kill-after=') or tok.startswith('--signal='):
            i += 1
            continue
        # Boolean flags.
        if tok in ('--foreground', '--preserve-status', '-v', '--verbose',
                   '--help', '--version'):
            i += 1
            continue
        # First non-flag token is the duration; the command follows it.
        if _RE_TIMEOUT_DURATION.match(tok):
            return i + 1
        # Malformed — no recognizable duration.
        break
    return None


def _classify_timeout(parts, depth):
    """Classify a `timeout [opts] DURATION CMD …` invocation by dispatching to CMD."""
    i = _timeout_cmd_index(parts)
    if i is None:
        return "unknown"
    rest = ' '.join(parts[i:])
    if rest:
        return _classify_bash(rest, depth + 1)
    return "read-only"


def _runner_inner_command(base, cmd, parts):
    """Return the command string a runner delegates to, or None.

    `source X && Y` / `source X; Y` delegate to `Y`; `timeout [opts] DUR CMD …`
    delegates to `CMD …`. Bare `source X` / `timeout 5` (no inner command) and
    any non-runner base return None.
    """
    if base in ("source", "."):
        m = _RE_CMD_CHAIN.search(cmd)
        if m:
            rest = cmd[m.end():].strip().rstrip(')').strip()
            return rest or None
        return None
    if base == "timeout":
        i = _timeout_cmd_index(parts)
        if i is not None and i < len(parts):
            return ' '.join(parts[i:])
        return None
    return None


def _effective_base(cmd, parts, base, depth=0):
    """Resolve `base` through command-runners (source, timeout) to the underlying
    command, so the grep-family secret-scan exemption keys on what is actually
    run. `timeout 300 grep …` and `source x && grep …` both resolve to `grep`.

    Non-runner bases (including `$VAR`) are returned unchanged — those still get
    the full inline secret scan.
    """
    if depth > 4:
        return base
    inner = _runner_inner_command(base, cmd, parts)
    if inner is not None:
        sub = inner.split()
        if sub:
            b = os.path.basename(sub[0]).rstrip('"\')}')
            return _effective_base(inner, sub, b, depth + 1)
    return base


def _classify_bash(raw_cmd, _depth=0):
    """Classify a Bash command, recursing through command-runners (source, timeout).

    The depth limit prevents pathological infinite recursion if a runner ever
    points at itself; in practice 4 is well beyond any realistic nesting.
    """
    if _depth > 4:
        return "mutating"

    # Collapse `\<newline>` line continuations so a multi-line script classifies
    # the same as its joined form.
    cmd = _RE_LINE_CONT.sub(' ', raw_cmd)
    cmd = _RE_CD_PREFIX.sub('', cmd)
    cmd = _RE_ENV_PREFIX.sub('', cmd)
    cmd = _RE_SHELL_OPS.sub('', cmd).lstrip()

    # Strip a leading paren group: `(cmd …)` or `( cmd … )`. Single paren only —
    # `((arith))` is shell-arithmetic and not interesting for risk.
    if cmd.startswith('(') and not cmd.startswith('(('):
        cmd = cmd[1:].lstrip()

    parts = cmd.split()
    if not parts or parts[0].startswith("#"):
        return "read-only"

    base = os.path.basename(parts[0])
    # Strip trailing punctuation from parsing artifacts
    base = base.rstrip('"\')}')

    # Secret scan, exempting grep-family commands — they search *for* patterns
    # rather than *using* them. Resolve through command-runners so a wrapped
    # `timeout … grep <token-shape>` is exempt like a bare grep; a wrapped
    # non-grep command (`timeout … curl -H <token>`) is still scanned.
    if _effective_base(cmd, parts, base) not in _GREP_FAMILY:
        if _cmd_has_secrets(raw_cmd):
            return "destructive"

    # Command-runners: dispatch to the trailing/underlying command.
    if base in ("source", "."):
        return _classify_source_chain(cmd, _depth)
    if base == "timeout":
        return _classify_timeout(parts, _depth)

    # `$VAR` or `$VAR/path/...` as the base — opaque indirection; almost always
    # invokes a script. Check parts[0] directly; basename strips the $-prefix
    # when the value is a path like `$HOME/bin/tool`.
    if parts[0].startswith("$"):
        return "mutating"

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


# --- Allowlist pattern matching ---

def _safe_load_settings(path):
    """Load and shape-validate a Claude Code settings JSON file.

    Returns a dict (possibly empty). On any failure or unexpected shape,
    emits a single Warning to stderr and returns {}. Validates:
      - root is a JSON object
      - permissions is absent or an object
      - permissions.allow / permissions.deny are absent or lists
    Repairs partially-bad shapes by zeroing out the offending sub-field.

    NOTE — scope-limited validation. Only the `permissions.allow` and
    `permissions.deny` shapes are checked because they're the only fields
    this module reads. Other top-level keys (`hooks`, `mcpServers`,
    `permissions.ask`, etc.) pass through untouched and could be malformed
    without producing a warning. Callers that read those fields need to do
    their own shape checks.
    """
    path = Path(path) if not isinstance(path, Path) else path
    if not path.exists():
        return {}
    try:
        with open(path) as f:
            data = json.load(f)
    except json.JSONDecodeError as e:
        print(f"Warning: invalid JSON in {path}: {e}", file=sys.stderr)
        return {}
    except OSError as e:
        print(f"Warning: cannot read {path}: {e}", file=sys.stderr)
        return {}
    if not isinstance(data, dict):
        print(f"Warning: {path} is not a JSON object (got {type(data).__name__})",
              file=sys.stderr)
        return {}
    perms = data.get("permissions")
    if perms is None:
        return data
    if not isinstance(perms, dict):
        print(f"Warning: {path} 'permissions' is not an object (got {type(perms).__name__}); ignoring",
              file=sys.stderr)
        data["permissions"] = {}
        return data
    for key in ("allow", "deny"):
        v = perms.get(key)
        if v is not None and not isinstance(v, list):
            print(f"Warning: {path} 'permissions.{key}' is not a list (got {type(v).__name__}); ignoring",
                  file=sys.stderr)
            perms[key] = []
    return data


def load_global_settings():
    return _safe_load_settings(CLAUDE_DIR / "settings.json")


def load_project_settings(project_name):
    """Load settings.local.json from project source directories and from ~/.claude/projects/."""
    patterns = []

    # Check ~/.claude/projects/<project>/settings.json
    proj_settings = PROJECTS_DIR / project_name / "settings.json"
    data = _safe_load_settings(proj_settings)
    patterns.extend(data.get("permissions", {}).get("allow", []))

    settings_path = project_settings_path(project_name)
    if settings_path:
        data = _safe_load_settings(settings_path)
        patterns.extend(data.get("permissions", {}).get("allow", []))

    return patterns


def _canonicalize_pattern(pattern):
    """Normalize semantically equivalent Claude Code permission patterns.

    Currently collapses `Bash(git add:*)` and `Bash(git add *)` to the same
    canonical form (space-delimited), so apply_suggestions doesn't append a
    new pattern when an equivalent one is already present.
    """
    if not isinstance(pattern, str):
        return pattern
    m = re.match(r'^(Bash)\((.+)\)$', pattern)
    if m:
        inner = m.group(2).replace(":", " ")
        # Collapse runs of whitespace produced by the colon swap
        inner = re.sub(r'\s+', ' ', inner).strip()
        return f"Bash({inner})"
    return pattern


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


def normalize_command(cmd, _depth=0):
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

    # Command-runners delegate to an underlying command — group the suggestion
    # by what's actually run, not the wrapper: `source … && python3 foo` groups
    # as `python3 foo`, `timeout 300 semgrep …` as `semgrep`. Bare `source X`
    # (env activation, no chained command) stays grouped as `source`.
    if _depth <= 4:
        inner = _runner_inner_command(base, cmd, parts)
        if inner is not None:
            return normalize_command(inner, _depth + 1)

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


def _resolve_max_session_size():
    """Resolve per-file JSONL cap from AUTOCLAUDE_MAX_SESSION_MB env var.

    Accepts an integer number of megabytes. Falls back to 100 MB if unset
    or invalid. Capping at 0 or negative disables the limit (sets to sys.maxsize).
    """
    raw = os.environ.get("AUTOCLAUDE_MAX_SESSION_MB", "").strip()
    if not raw:
        return 100 * 1024 * 1024
    try:
        mb = int(raw)
    except ValueError:
        print(f"Warning: AUTOCLAUDE_MAX_SESSION_MB={raw!r} is not an integer; "
              f"falling back to 100 MB", file=sys.stderr)
        return 100 * 1024 * 1024
    if mb <= 0:
        return sys.maxsize
    return mb * 1024 * 1024


_MAX_SESSION_SIZE = _resolve_max_session_size()


# --- Token-attribution helpers (Phase 1 of token-report mode) ---
#
# Strategy: per-turn `usage` lives on the assistant message, not per tool_use.
# We attribute the next-turn `cache_creation_input_tokens` delta proportionally
# across the prior turn's tool_use blocks, weighted by `result_bytes`.
# Fallback: `len(text) / 4`. The estimate method is recorded so the UI can
# surface a confidence flag.

_RE_PROSE_BOILERPLATE = re.compile(
    r'<(?:system-reminder|command-name|command-message|command-args|local-command-stdout)>'
    r'.*?</(?:system-reminder|command-name|command-message|command-args|local-command-stdout)>',
    re.DOTALL,
)


def _normalize_read_target(file_path):
    """Normalize a Read tool file_path: home -> ~, no line range hints."""
    if not file_path:
        return ""
    return shorten_path(str(file_path))


def _normalize_url(url):
    """Normalize a WebFetch URL: lowercase scheme/host, strip query+fragment."""
    if not url:
        return ""
    url = str(url).strip()
    # Strip fragment, then query
    for sep in ("#", "?"):
        i = url.find(sep)
        if i >= 0:
            url = url[:i]
    # Lowercase scheme://host portion
    m = re.match(r'^([a-zA-Z][a-zA-Z0-9+.\-]*://)([^/]+)(.*)$', url)
    if m:
        return m.group(1).lower() + m.group(2).lower() + m.group(3)
    return url


def _extract_input_target(tool_name, tool_input):
    """Return a canonical target string for grouping (Pattern A + recipes).

    Returns "" when the tool has no obvious target (e.g. WebSearch query).
    """
    if not isinstance(tool_input, dict):
        return ""
    if tool_name == "Read":
        return _normalize_read_target(tool_input.get("file_path", ""))
    if tool_name in ("Write", "Edit"):
        return _normalize_read_target(tool_input.get("file_path", ""))
    if tool_name == "WebFetch":
        return _normalize_url(tool_input.get("url", ""))
    if tool_name == "Bash":
        return normalize_command(tool_input.get("command", ""))
    return ""


def _compute_result_bytes(tool_use_result, msg_content):
    """Best-effort byte count for a tool result.

    Prefers structured `toolUseResult` (has stdout/stderr split for Bash).
    Falls back to message.content text length.
    """
    total = 0
    if isinstance(tool_use_result, dict):
        for key in ("stdout", "stderr", "content"):
            v = tool_use_result.get(key)
            if isinstance(v, str):
                total += len(v)
        if total:
            return total
        # Read-tool style: file content under .file.text or similar
        for v in tool_use_result.values():
            if isinstance(v, str):
                total += len(v)
            elif isinstance(v, dict):
                for vv in v.values():
                    if isinstance(vv, str):
                        total += len(vv)
        if total:
            return total
    elif isinstance(tool_use_result, str):
        total = len(tool_use_result)
        if total:
            return total
    if isinstance(msg_content, list):
        for c in msg_content:
            if isinstance(c, dict) and c.get("type") == "tool_result":
                content = c.get("content", "")
                if isinstance(content, str):
                    total += len(content)
                elif isinstance(content, list):
                    for x in content:
                        if isinstance(x, dict):
                            t = x.get("text", "")
                            if isinstance(t, str):
                                total += len(t)
    elif isinstance(msg_content, str):
        total += len(msg_content)
    return total


def _estimate_tokens_from_bytes(byte_count):
    """Cheap fallback: roughly 4 chars per token."""
    return max(0, byte_count // 4)


# Upper bound on tokens per byte. Real ratio is usually ~3-4 chars/token; we
# use 1/3 as a safe ceiling to cap inflated `cache_creation` attributions.
_BYTE_TOKEN_CAP_DIVISOR = 3


def attribute_tool_result_tokens(records, turn_usage_by_uuid, turn_order):
    """Attribute next-turn cache_creation tokens proportionally to a turn's tool results.

    Mutates records in-place, adding:
      - _result_tokens_est: int
      - _token_estimate_method: "usage_delta" | "usage_delta_capped" | "char_div_4"

    The proportional share is capped at `result_bytes // 3` because
    `cache_creation_input_tokens` includes everything new in the next turn
    (prose, system reminders, the assistant's output prefix, ...), not just
    the prior turn's tool output. Without the cap, single-tool turns
    over-attribute when the user adds a large prose block.

    Args:
      records: list of record dicts with `_turn_uuid` and `_result_bytes` set
      turn_usage_by_uuid: {uuid: usage_dict} from assistant messages
      turn_order: ordered list of uuids (chronological)
    """
    by_turn = defaultdict(list)
    for r in records:
        uuid = r.get("_turn_uuid")
        if uuid:
            by_turn[uuid].append(r)

    for i, uuid in enumerate(turn_order):
        turn_records = by_turn.get(uuid, [])
        if not turn_records:
            continue

        next_uuid = turn_order[i + 1] if i + 1 < len(turn_order) else None
        delta_tokens = 0
        if next_uuid:
            next_usage = turn_usage_by_uuid.get(next_uuid, {}) or {}
            delta_tokens = int(next_usage.get("cache_creation_input_tokens") or 0)

        if delta_tokens > 0:
            total_bytes = sum(r.get("_result_bytes", 0) for r in turn_records)
            if total_bytes > 0:
                for r in turn_records:
                    rb = r.get("_result_bytes", 0)
                    share = int(round(delta_tokens * (rb / total_bytes)))
                    cap = max(rb // _BYTE_TOKEN_CAP_DIVISOR, 0)
                    if share > cap and cap > 0:
                        r["_result_tokens_est"] = cap
                        r["_token_estimate_method"] = "usage_delta_capped"
                    else:
                        r["_result_tokens_est"] = share
                        r["_token_estimate_method"] = "usage_delta"
                continue
            # No bytes to weight: split evenly, no cap available
            even = delta_tokens // len(turn_records)
            for r in turn_records:
                r["_result_tokens_est"] = even
                r["_token_estimate_method"] = "usage_delta"
            continue

        # Fallback: char/4 per record
        for r in turn_records:
            r["_result_tokens_est"] = _estimate_tokens_from_bytes(r.get("_result_bytes", 0))
            r["_token_estimate_method"] = "char_div_4"


def _strip_prose_boilerplate(text):
    """Remove <system-reminder>, <command-*> tags before prose hashing."""
    if not isinstance(text, str):
        return ""
    return _RE_PROSE_BOILERPLATE.sub("", text).strip()


def extract_user_prose(jsonl_path, project_name):
    """Return prose records: user messages NOT correlated to a tool result.

    Each record: {project, session, timestamp, _kind="prose", text, _char_len}
    Tagged `_kind="prose"` so it's distinguishable from tool-call records.
    Existing renderers ignore records lacking `tool_name`.
    """
    out = []
    try:
        size = os.path.getsize(jsonl_path)
        if size > _MAX_SESSION_SIZE:
            return out
        with open(jsonl_path) as f:
            lines = list(f)
    except (OSError, UnicodeDecodeError):
        return out

    session_basename = os.path.basename(jsonl_path)
    for line in lines:
        try:
            obj = json.loads(line)
        except json.JSONDecodeError:
            continue
        if obj.get("type") != "user":
            continue
        if obj.get("sourceToolAssistantUUID") or obj.get("toolUseID"):
            continue
        msg = obj.get("message", {})
        content = msg.get("content")
        text_parts = []
        if isinstance(content, str):
            text_parts.append(content)
        elif isinstance(content, list):
            for c in content:
                if isinstance(c, dict) and c.get("type") == "text":
                    t = c.get("text", "")
                    if isinstance(t, str):
                        text_parts.append(t)
        text = _strip_prose_boilerplate("\n".join(text_parts))
        if not text:
            continue
        out.append({
            "project": project_name,
            "session": session_basename,
            "timestamp": obj.get("timestamp", ""),
            "_kind": "prose",
            "text": text,
            "_char_len": len(text),
        })
    return out


def process_session(jsonl_path, allow_patterns, project_name):
    """Process a single session JSONL file. Returns list of tool call records."""
    records = []

    try:
        size = os.path.getsize(jsonl_path)
        if size > _MAX_SESSION_SIZE:
            print(f"  Skipping {os.path.basename(jsonl_path)}: {size // (1024*1024)}MB exceeds limit",
                  file=sys.stderr)
            return records
        with open(jsonl_path) as f:
            lines = list(f)
    except (OSError, UnicodeDecodeError) as e:
        print(f"  Warning: cannot read {os.path.basename(jsonl_path)}: {e}",
              file=sys.stderr)
        return records

    objects = []
    dropped = 0
    for line in lines:
        try:
            objects.append(json.loads(line))
        except json.JSONDecodeError:
            dropped += 1
            continue
    if dropped:
        print(f"  Warning: {os.path.basename(jsonl_path)} had "
              f"{dropped} malformed line(s); dropped from analysis",
              file=sys.stderr)

    assistant_by_uuid = {}
    assistant_order = []  # chronological list of assistant uuids
    for obj in objects:
        if obj.get("type") == "assistant":
            uuid = obj.get("uuid")
            if uuid:
                assistant_by_uuid[uuid] = obj
                assistant_order.append(uuid)

    # Sort assistant turns by timestamp (parsed_ts may be None for malformed)
    def _ts_key(uuid):
        ts = assistant_by_uuid[uuid].get("timestamp", "")
        parsed = _parse_ts(ts) if ts else None
        return (parsed or datetime.min.replace(tzinfo=timezone.utc),)
    try:
        assistant_order.sort(key=_ts_key)
    except Exception:
        pass  # keep insertion order if anything is unparseable

    turn_usage_by_uuid = {
        uuid: assistant_by_uuid[uuid].get("message", {}).get("usage", {}) or {}
        for uuid in assistant_order
    }
    turn_index_by_uuid = {uuid: i for i, uuid in enumerate(assistant_order)}

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

            original_cmd = tool_input.get("command", "") if tool_name == "Bash" else ""

            secret_category = None
            exposure_risk = None
            if has_secrets and not is_rejected:
                secret_category = _categorize_secret(original_cmd)
                exposure_risk, _ = _classify_exposure_risk(original_cmd, secret_category)

            # Token-attribution fields (Phase 1)
            result_bytes = _compute_result_bytes(
                obj.get("toolUseResult"),
                obj.get("message", {}).get("content"),
            )
            input_target = _extract_input_target(tool_name, tool_input)

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
                "_secret_category": secret_category,
                "_exposure_risk": exposure_risk,
                "_input_target": input_target,
                "_result_bytes": result_bytes,
                "_turn_uuid": src_uuid,
                "_turn_index": turn_index_by_uuid.get(src_uuid),
                # _result_tokens_est and _token_estimate_method set by post-pass
                "_result_tokens_est": 0,
                "_token_estimate_method": "char_div_4",
            })

    # Post-pass: attribute next-turn cache_creation tokens proportionally
    attribute_tool_result_tokens(records, turn_usage_by_uuid, assistant_order)
    annotate_next_turn_output(records, turn_usage_by_uuid, assistant_order)

    return records


# --- Phase 2 detectors: token-consumption optimization ---
#
# All detectors are pure functions over record lists. Each returns a list of
# uniform finding dicts with this shape:
#   {
#     "kind": "repeated_read" | "recipe_ngram" | "repeated_prose" | "resummarized_output",
#     "target": str,            # canonical identifier (path / URL / step tuple / paragraph)
#     "occurrences": int,       # total count
#     "distinct_sessions": int, # how many sessions this appeared in
#     "avg_tokens": int,        # avg per-occurrence token cost
#     "sum_tokens": int,        # total token cost across all occurrences
#     "sample_session_ids": [str],  # up to 5 session basenames
#     "_raw": dict,             # detector-specific extra fields (n-gram steps, ratio, ...)
#   }
# A later phase (4) ranks/renders findings; detectors only filter by threshold.


def _safe_allow_command_names():
    """Extract bare command names from BASELINE_SAFE_ALLOW for n-gram filtering."""
    names = set()
    for pat in BASELINE_SAFE_ALLOW:
        m = re.match(r'^Bash\(([\w-]+)', pat)
        if m:
            names.add(m.group(1))
    return names


def annotate_next_turn_output(records, turn_usage_by_uuid, turn_order):
    """Add `_next_turn_output_tokens` to each record (0 when last turn).

    Used by Pattern D (re-summarized outputs) to detect heavy summarization.
    """
    next_output_by_uuid = {}
    for i, uuid in enumerate(turn_order):
        next_uuid = turn_order[i + 1] if i + 1 < len(turn_order) else None
        if next_uuid:
            next_usage = turn_usage_by_uuid.get(next_uuid, {}) or {}
            next_output_by_uuid[uuid] = int(next_usage.get("output_tokens") or 0)
        else:
            next_output_by_uuid[uuid] = 0
    for r in records:
        uuid = r.get("_turn_uuid")
        if uuid:
            r["_next_turn_output_tokens"] = next_output_by_uuid.get(uuid, 0)


# --- Pattern A: repeated reads (Read / WebFetch) ---

def find_repeated_reads(records, min_sessions=3, min_tokens=5000):
    """Find Read/WebFetch targets read across many sessions, weighted by tokens.

    Returns findings sorted by sum_tokens descending.
    """
    by_target = defaultdict(list)
    for r in records:
        if r.get("_kind") == "prose":
            continue
        if r.get("tool_name") not in ("Read", "WebFetch"):
            continue
        target = r.get("_input_target") or ""
        if not target:
            continue
        by_target[target].append(r)

    findings = []
    for target, recs in by_target.items():
        sessions = sorted({r.get("session", "") for r in recs if r.get("session")})
        if len(sessions) < min_sessions:
            continue
        sum_tokens = sum(int(r.get("_result_tokens_est") or 0) for r in recs)
        if sum_tokens < min_tokens:
            continue
        kind = "repeated_webfetch" if recs[0].get("tool_name") == "WebFetch" else "repeated_read"
        findings.append({
            "kind": kind,
            "target": target,
            "occurrences": len(recs),
            "distinct_sessions": len(sessions),
            "avg_tokens": sum_tokens // len(recs),
            "sum_tokens": sum_tokens,
            "sample_session_ids": sessions[:5],
            "_raw": {
                "tool_name": recs[0].get("tool_name"),
                "last_seen": max((r.get("timestamp", "") for r in recs), default=""),
            },
        })
    findings.sort(key=lambda f: -f["sum_tokens"])
    return findings


# --- Pattern B: recipe n-grams ---

_RECIPE_IDLE_GAP_SECONDS = 600  # 10 minutes


def _build_recipe_step(record):
    """Reduce a tool-call record to a step token used for n-gram building."""
    tool_name = record.get("tool_name", "")
    target = record.get("_input_target") or ""
    if tool_name == "Bash":
        return target or "Bash"  # _input_target is normalize_command for Bash
    if tool_name in ("Read", "Write", "Edit", "WebFetch", "WebSearch"):
        return tool_name
    if tool_name.startswith("mcp__"):
        # Group by server + verb (mcp__server__action -> mcp:server:action)
        parts = tool_name.split("__")
        if len(parts) >= 3:
            return f"mcp:{parts[1]}:{parts[2]}"
        return tool_name
    return tool_name


def _segment_session_records(session_records, gap_seconds=_RECIPE_IDLE_GAP_SECONDS):
    """Split a session's records into idle-gap-separated segments."""
    if not session_records:
        return []
    sorted_recs = sorted(
        session_records,
        key=lambda r: r.get("_turn_index") if r.get("_turn_index") is not None else 0,
    )
    segments = []
    current = [sorted_recs[0]]
    last_ts = _parse_ts(sorted_recs[0].get("timestamp", ""))
    for r in sorted_recs[1:]:
        ts = _parse_ts(r.get("timestamp", ""))
        if last_ts and ts:
            gap = (ts - last_ts).total_seconds()
            if gap > gap_seconds:
                segments.append(current)
                current = []
        current.append(r)
        if ts:
            last_ts = ts
    if current:
        segments.append(current)
    return segments


def _collapse_runs(steps):
    """Collapse consecutive identical steps: A,A,A,B,B,A -> A,B,A."""
    out = []
    for s in steps:
        if not out or out[-1] != s:
            out.append(s)
    return out


def find_recipe_ngrams(records, ns=(3, 4, 5), min_occurrences=5, min_sessions=2):
    """Find recurring n-gram sequences of tool calls.

    Returns findings sorted by occurrences * n descending.
    """
    safe_allow = _safe_allow_command_names()

    # Group by (project, session), then segment by idle gap
    by_session = defaultdict(list)
    for r in records:
        if r.get("_kind") == "prose":
            continue
        if not r.get("tool_name"):
            continue
        key = (r.get("project", ""), r.get("session", ""))
        by_session[key].append(r)

    # Aggregate n-grams: tuple -> {occurrences, sessions, sum_tokens}
    ngram_stats = defaultdict(lambda: {
        "occurrences": 0,
        "sessions": set(),
        "sum_tokens": 0,
        "n": 0,
    })

    for (project, session), recs in by_session.items():
        for segment in _segment_session_records(recs):
            steps = _collapse_runs([_build_recipe_step(r) for r in segment])
            seg_token_costs = {}  # step-index -> tokens (for windowed sum)
            # Build per-step tokens parallel to collapsed steps; collapsing
            # loses the original record alignment, so use segment-level avg
            avg_tok = (
                sum(int(r.get("_result_tokens_est") or 0) for r in segment)
                / max(len(segment), 1)
            )
            for n in ns:
                if len(steps) < n:
                    continue
                for i in range(len(steps) - n + 1):
                    window = tuple(steps[i:i + n])
                    # Reject: only one distinct step in window
                    if len(set(window)) <= 1:
                        continue
                    # Reject: every step is a baseline-safe-allow Bash command
                    if all(s in safe_allow for s in window):
                        continue
                    stats = ngram_stats[window]
                    stats["occurrences"] += 1
                    stats["sessions"].add(session)
                    stats["sum_tokens"] += int(avg_tok * n)
                    stats["n"] = n

    # Build raw findings list
    raw_findings = []
    for ngram, stats in ngram_stats.items():
        if stats["occurrences"] < min_occurrences:
            continue
        if len(stats["sessions"]) < min_sessions:
            continue
        sessions = sorted(stats["sessions"])
        raw_findings.append({
            "ngram": ngram,
            "occurrences": stats["occurrences"],
            "distinct_sessions": len(stats["sessions"]),
            "sum_tokens": stats["sum_tokens"],
            "n": stats["n"],
            "sessions": sessions,
        })

    # Dedupe: drop a shorter n-gram that's fully contained in a longer one with
    # comparable count (within 20%).
    raw_findings.sort(key=lambda f: (-f["n"], -f["occurrences"]))
    suppressed = set()
    for i, longer in enumerate(raw_findings):
        if i in suppressed:
            continue
        for j, shorter in enumerate(raw_findings):
            if j == i or j in suppressed:
                continue
            if shorter["n"] >= longer["n"]:
                continue
            # Is shorter contained in longer?
            ln = longer["ngram"]
            sn = shorter["ngram"]
            contained = any(
                ln[k:k + len(sn)] == sn for k in range(len(ln) - len(sn) + 1)
            )
            if not contained:
                continue
            # Comparable count?
            if shorter["occurrences"] <= longer["occurrences"] * 1.2:
                suppressed.add(j)

    findings = []
    for i, raw in enumerate(raw_findings):
        if i in suppressed:
            continue
        findings.append({
            "kind": "recipe_ngram",
            "target": " → ".join(raw["ngram"]),
            "occurrences": raw["occurrences"],
            "distinct_sessions": raw["distinct_sessions"],
            "avg_tokens": raw["sum_tokens"] // raw["occurrences"],
            "sum_tokens": raw["sum_tokens"],
            "sample_session_ids": raw["sessions"][:5],
            "_raw": {
                "n": raw["n"],
                "steps": list(raw["ngram"]),
            },
        })
    findings.sort(key=lambda f: -(f["occurrences"] * f["_raw"]["n"]))
    return findings


# --- Pattern C: repeated user prose ---

_RE_PROSE_NUMBER = re.compile(r'\b\d[\d,.]*\b')
_RE_PROSE_WS = re.compile(r'\s+')


def _normalize_prose_text(text):
    """Lowercase, collapse whitespace, replace numeric tokens with <N>."""
    if not isinstance(text, str):
        return ""
    t = text.lower()
    t = _RE_PROSE_NUMBER.sub("<N>", t)
    t = _RE_PROSE_WS.sub(" ", t).strip()
    return t


def _hash_prose(normalized):
    return hashlib.sha256(normalized.encode("utf-8")).hexdigest()


def find_repeated_prose(prose_records, min_occurrences=3, min_chars=400):
    """Find recurring prose paragraphs the user pastes across sessions.

    Splits each prose block into paragraphs (>= min_chars each), normalizes,
    SHA256-hashes, and clusters exact matches. Near-duplicate clustering is
    intentionally deferred (would require MinHash; tracked in plan).
    """
    by_hash = defaultdict(lambda: {
        "occurrences": 0,
        "sessions": set(),
        "char_lens": [],
        "exemplar": "",
    })

    for p in prose_records:
        if p.get("_kind") != "prose":
            continue
        text = p.get("text", "")
        if not isinstance(text, str):
            continue
        # Split on blank lines into paragraphs
        for para in re.split(r'\n\s*\n', text):
            para = para.strip()
            if len(para) < min_chars:
                continue
            normalized = _normalize_prose_text(para)
            if not normalized:
                continue
            h = _hash_prose(normalized)
            entry = by_hash[h]
            entry["occurrences"] += 1
            entry["sessions"].add(p.get("session", ""))
            entry["char_lens"].append(len(para))
            if not entry["exemplar"]:
                entry["exemplar"] = para

    findings = []
    for h, entry in by_hash.items():
        if entry["occurrences"] < min_occurrences:
            continue
        avg_chars = sum(entry["char_lens"]) // len(entry["char_lens"])
        sum_chars = sum(entry["char_lens"])
        # Token estimate: char count / 4
        avg_tokens = avg_chars // 4
        sum_tokens = sum_chars // 4
        sessions = sorted(s for s in entry["sessions"] if s)
        findings.append({
            "kind": "repeated_prose",
            "target": entry["exemplar"][:120],
            "occurrences": entry["occurrences"],
            "distinct_sessions": len(sessions),
            "avg_tokens": avg_tokens,
            "sum_tokens": sum_tokens,
            "sample_session_ids": sessions[:5],
            "_raw": {
                "hash": h,
                "avg_chars": avg_chars,
                "exemplar_full": entry["exemplar"],
            },
        })
    findings.sort(key=lambda f: -f["sum_tokens"])
    return findings


# --- Pattern D: large outputs that get re-summarized ---

def find_resummarized_outputs(records, min_bytes=8000, max_narrow_ratio=0.25,
                                min_occurrences=3):
    """Find tool outputs that are large but get heavily summarized in the next turn.

    Signal: `next_turn_output_tokens / result_tokens_est < max_narrow_ratio`.
    Aggregated by `_input_target` so a recurring "huge output → tiny summary"
    pattern surfaces a wrapper-script suggestion.
    """
    by_target = defaultdict(list)
    for r in records:
        if r.get("_kind") == "prose":
            continue
        if not r.get("tool_name"):
            continue
        rb = int(r.get("_result_bytes") or 0)
        if rb < min_bytes:
            continue
        result_tokens = int(r.get("_result_tokens_est") or 0)
        if result_tokens <= 0:
            continue
        next_out = int(r.get("_next_turn_output_tokens") or 0)
        if next_out <= 0:
            continue
        ratio = next_out / result_tokens
        if ratio >= max_narrow_ratio:
            continue
        target = r.get("_input_target") or r.get("display") or r.get("tool_name", "")
        by_target[target].append((r, ratio))

    findings = []
    for target, items in by_target.items():
        if len(items) < min_occurrences:
            continue
        sessions = sorted({r.get("session", "") for r, _ in items if r.get("session")})
        sum_tokens = sum(int(r.get("_result_tokens_est") or 0) for r, _ in items)
        avg_ratio = sum(ratio for _, ratio in items) / len(items)
        avg_input_bytes = sum(int(r.get("_result_bytes") or 0) for r, _ in items) // len(items)
        findings.append({
            "kind": "resummarized_output",
            "target": target,
            "occurrences": len(items),
            "distinct_sessions": len(sessions),
            "avg_tokens": sum_tokens // len(items),
            "sum_tokens": sum_tokens,
            "sample_session_ids": sessions[:5],
            "_raw": {
                "narrow_ratio": round(avg_ratio, 3),
                "avg_input_bytes": avg_input_bytes,
                "tool_name": items[0][0].get("tool_name"),
            },
        })
    findings.sort(key=lambda f: -f["sum_tokens"])
    return findings


# --- Phase 3: stability weighting + scoring ---
#
# A finding is more valuable if the underlying source is stable. Volatile
# files would produce stale reference docs (worse than re-deriving) so we
# multiply each finding's raw score by a `stability_factor` in [0.1, 1.0],
# where 1.0 = highly stable (no recent commits) and 0.1 = very volatile.
#
# Note: an earlier draft of the plan called this `churn_factor` and used
# division. That math actually *boosted* volatile items (low factor → small
# divisor → large score), the opposite of the stated intent. Switched to
# multiplication with a stability framing during implementation.

_STABILITY_GIT_TIMEOUT_SECONDS = 2
_STABILITY_DEFAULT_SINCE_DAYS = 180

# Total wall-clock budget for git-log stability lookups across one CLI run.
# Each call has its own 2-second subprocess timeout, but on slow filesystems
# the cumulative cost across many findings can dominate. Once the budget
# is exhausted, subsequent calls short-circuit to None and the caller falls
# back to the default stability factor (0.7).
_STABILITY_TOTAL_BUDGET_SECONDS = 30
_stability_budget_used = 0.0
_stability_budget_exhausted_warned = False


def _reset_stability_budget():
    """Reset the wall-clock budget. Used by tests and one-shot reuse."""
    global _stability_budget_used, _stability_budget_exhausted_warned
    _stability_budget_used = 0.0
    _stability_budget_exhausted_warned = False


def _set_stability_budget_used(seconds):
    """Pin the consumed counter — test hook for budget-exhaustion paths."""
    global _stability_budget_used
    _stability_budget_used = float(seconds)


def _resolve_target_path(target):
    """Map a finding target to an absolute filesystem path, or None.

    Targets from `_normalize_read_target` use `~/...` form.
    """
    if not target or not isinstance(target, str):
        return None
    if target.startswith("~/") or target == "~":
        return os.path.expanduser(target)
    if target.startswith("/"):
        return target
    return None


@lru_cache(maxsize=2048)
def _git_commit_count(abs_path, since_days=_STABILITY_DEFAULT_SINCE_DAYS):
    """Count commits touching `abs_path` in the last `since_days` days.

    Returns None when git is unavailable, the path is not in a git repo, the
    subprocess times out, or the per-run wall-clock budget is exhausted.
    Cached per-process via lru_cache so repeated findings against the same
    path don't fork git multiple times.
    """
    global _stability_budget_used, _stability_budget_exhausted_warned
    if not abs_path:
        return None
    if _stability_budget_used >= _STABILITY_TOTAL_BUDGET_SECONDS:
        if not _stability_budget_exhausted_warned:
            print(
                f"Warning: git-log stability budget "
                f"({_STABILITY_TOTAL_BUDGET_SECONDS}s) exhausted; remaining "
                f"findings will use the default stability factor.",
                file=sys.stderr,
            )
            _stability_budget_exhausted_warned = True
        return None
    parent = os.path.dirname(abs_path)
    if not parent or not os.path.isdir(parent):
        parent = "."
    t0 = time.monotonic()
    try:
        result = subprocess.run(
            ["git", "log", "--follow", f"--since={since_days} days ago",
             "--pretty=oneline", "--", abs_path],
            cwd=parent,
            capture_output=True, text=True,
            timeout=_STABILITY_GIT_TIMEOUT_SECONDS,
        )
    except (subprocess.TimeoutExpired, FileNotFoundError, OSError):
        _stability_budget_used += time.monotonic() - t0
        return None
    _stability_budget_used += time.monotonic() - t0
    if result.returncode != 0:
        return None
    return sum(1 for line in result.stdout.splitlines() if line.strip())


def _stability_from_commit_count(n):
    """Commit count -> stability. Many commits = volatile = low factor."""
    if n == 0:
        return 1.0
    if n <= 3:
        return 0.8
    if n <= 10:
        return 0.5
    if n <= 30:
        return 0.25
    return 0.1


def _stability_from_mtime(mtime):
    """Untracked-file fallback. Recently modified = volatile = low factor."""
    age_days = (time.time() - mtime) / 86400
    if age_days < 7:
        return 0.5
    if age_days < 30:
        return 0.7
    return 1.0


def compute_stability_factor(target, kind):
    """Return a stability factor in [0.1, 1.0]. Higher = safer to cache.

    Dispatches by finding kind:
      - repeated_prose: 1.0 (text the user typed; not a moving target)
      - repeated_webfetch: 0.7 (external — verify freshness)
      - recipe_ngram: 1.0 (steps don't carry literal file args)
      - repeated_read / resummarized_output: file-based (git or mtime)
    """
    if kind == "repeated_prose":
        return 1.0
    if kind == "repeated_webfetch":
        return 0.7
    if kind == "recipe_ngram":
        return 1.0

    path = _resolve_target_path(target)
    if not path:
        return 0.7
    n = _git_commit_count(path)
    if n is not None:
        return _stability_from_commit_count(n)
    if not os.path.exists(path):
        return 0.7
    try:
        return _stability_from_mtime(os.path.getmtime(path))
    except OSError:
        return 0.7


def score_finding(finding, stability_factor):
    """Ranking score: occurrences * avg_tokens * stability_factor.

    Volatile sources (low factor) get discounted because reference docs
    derived from them would go stale.
    """
    occ = int(finding.get("occurrences") or 0)
    avg = int(finding.get("avg_tokens") or 0)
    return occ * avg * max(stability_factor, 0.1)


def rank_findings(findings):
    """Annotate findings with stability + score, then sort by score descending.

    Mutates each finding in place adding `_stability_factor` and `_score`.
    Returns the same list, sorted.
    """
    for f in findings:
        stab = compute_stability_factor(f.get("target", ""), f.get("kind", ""))
        f["_stability_factor"] = stab
        f["_score"] = score_finding(f, stab)
    findings.sort(key=lambda f: -f["_score"])
    return findings


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


def _categorize_secret(cmd):
    """Categorize what type of secret a command contains."""
    if _PREFIXED_TOKEN_PATTERNS.search(cmd):
        return "token"
    elif _RE_JWT.search(cmd):
        return "jwt"
    elif _RE_PRIVATE_KEY.search(cmd):
        return "private_key"
    elif _RE_CURL_AUTH.search(cmd):
        return "auth_header"
    elif _RE_SECRET_ASSIGN.search(cmd):
        return "secret_assign"
    return "high_entropy"


def _find_secret_exposures(records):
    """Find records where secrets were exposed in commands.

    Returns list of (record, category) tuples where category is one of:
    token, jwt, private_key, auth_header, secret_assign, high_entropy.
    Uses pre-computed _secret_category from process_session.
    """
    results = []
    for r in records:
        if r["rejected"]:
            continue
        if r["tool_name"] != "Bash":
            continue
        if not r.get("_has_secrets"):
            continue

        category = r.get("_secret_category")
        if category:
            results.append((r, category))

    return results


def _count_secret_exposures(records):
    """Count records where secrets were actually exposed in command text."""
    exposed = 0
    for r, category in _find_secret_exposures(records):
        risk = r.get("_exposure_risk", "exposed")
        if risk == "exposed":
            exposed += 1
    return exposed


_RE_GIT_HASH = re.compile(r'^[0-9a-f]{7,40}$')
_RE_SSH_PUBKEY = re.compile(r'ssh-(?:ed25519|rsa|ecdsa)\s+\S+')
_RE_GIT_REF_PATH = re.compile(r'refs/(?:original|heads|remotes|tags)/')
_NON_SECRET_ASSIGNS = frozenset({
    'GIT_AUTHOR_NAME', 'GIT_AUTHOR_EMAIL',
    'GIT_COMMITTER_NAME', 'GIT_COMMITTER_EMAIL',
    'GIT_AUTHOR_DATE', 'GIT_COMMITTER_DATE',
    'HOME', 'PATH', 'SHELL', 'USER', 'LANG', 'TERM',
})


def _classify_exposure_risk(cmd, category):
    """Classify whether a secret-flagged command actually exposes the secret.

    Returns (risk_level, explanation) where risk_level is one of:
    - "exposed": literal secret value appears in command text (in transcript)
    - "variable": secret referenced via $VAR — value may appear in output
    - "pipe-safe": secret flows through pipe, never appears in transcript
    - "runtime": secret fetched at runtime via $(), may or may not leak
    - "false-positive": detected pattern is not actually a secret
    """
    if category == "token":
        if re.search(r'(?:json\.dumps|tool_result|echo\s+.*\{.*tool_name)', cmd):
            return ("false-positive", "Test payload containing synthetic token")
        return ("exposed", "Literal token in command text")
    if category == "jwt":
        return ("exposed", "Literal JWT in command text")
    if category == "private_key":
        return ("exposed", "Private key material in command text")
    if category == "high_entropy":
        if _RE_SSH_PUBKEY.search(cmd):
            return ("false-positive", "SSH public key (not a secret)")
        if re.search(r'\bgit\b.*\b(?:tag|update-ref|filter-branch|rebase|cherry-pick)\b', cmd):
            return ("false-positive", "Git commit hash or ref path")
        if _RE_GIT_REF_PATH.search(cmd):
            return ("false-positive", "Git ref path")
        return ("exposed", "High-entropy blob in command text")

    if category == "auth_header":
        m = re.search(
            r'Authorization:\s*(?:Bearer|Token|Basic)\s+(\S+)',
            cmd, re.IGNORECASE
        )
        if not m:
            m = re.search(
                r'-H\s+["\']Authorization:\s*(?:Bearer|Token|Basic)\s+(\S+)',
                cmd, re.IGNORECASE
            )
        if m:
            val = m.group(1).strip("\"'")
            if val.startswith('$(') or val.startswith('`'):
                return ("runtime", f"Auth value from subshell — secret fetched at runtime")
            if val.startswith('$') or val.startswith('${'):
                if '|' in cmd and '$(' not in cmd:
                    return ("pipe-safe", f"Auth value {val} — pipe-only, no transcript exposure")
                return ("variable", f"Auth value {val} — variable ref, may appear in output")
            if val in ('{}', '{0}') and '|' in cmd:
                return ("pipe-safe", f"Auth value from xargs/pipe — never in transcript")
            if re.search(r'^Basic\s+', val, re.IGNORECASE) or (
                    category == "auth_header" and 'Basic' in cmd):
                try:
                    import base64
                    decoded = base64.b64decode(val.split()[-1] if ' ' in val else val).decode('utf-8', errors='ignore')
                    if re.search(r'(?:test|example|dummy|fake|wrong|changeme|placeholder)', decoded, re.IGNORECASE):
                        return ("false-positive", "Basic auth with test/dummy credentials")
                except Exception:
                    pass
            return ("exposed", "Literal auth credential in command text")
        return ("exposed", "Auth header with literal value")

    if category == "secret_assign":
        m = _RE_SECRET_ASSIGN.search(cmd)
        if m:
            var_name = m.group(1)
            if var_name.upper() in _NON_SECRET_ASSIGNS:
                return ("false-positive", f"{var_name} is not a secret")
            val = m.group(2).strip("\"'")
            if val.startswith('$(') or val.startswith('`'):
                if '|' in cmd and re.search(r'\|\s*\w', cmd):
                    return ("pipe-safe", f"{var_name}=$(...) piped — secret stays in pipeline")
                return ("runtime", f"{var_name} set from subshell — may appear in output")
            if val.startswith('$') or val.startswith('${'):
                return ("variable", f"{var_name} set from variable {val}")
            # Strip a trailing shell terminator welded onto the captured value so
            # `os.environ["X"];` (from `TOKEN=...; NAME=y`) still matches (issue #9 C).
            if _RE_ENV_READ_VALUE.match(_RE_VALUE_TRAILER.sub('', val)):
                return ("false-positive", f"{var_name} read from the environment (no literal secret)")
            return ("exposed", f"Literal value assigned to {var_name}")
        return ("exposed", "Secret assignment with literal value")

    return ("exposed", "Unknown pattern")


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
    elif display.startswith("Grep"):
        return "Grep"
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
    """Write settings JSON to path unless dry_run.

    Preserves the existing file mode if the file is already present so a
    user's chosen permissions (typical Claude Code default: 0o644) survive
    an `--apply` run. New files default to 0o600 — settings.local.json
    is per-user state, owner-only is the right floor.
    """
    if dry_run:
        return
    if not path.parent.exists():
        print(f"    Skipping: {path.parent} does not exist", file=sys.stderr)
        return
    try:
        mode = stat.S_IMODE(os.stat(path).st_mode)
    except (FileNotFoundError, OSError):
        mode = 0o600
    def _do_write(f):
        json.dump(settings, f, indent=2)
        f.write("\n")
    _atomic_write(path, _do_write, mode=mode)


def _load_settings(path):
    """Load JSON settings from path, returning empty dict on missing/invalid.

    Thin wrapper around _safe_load_settings (kept for callers that pass a Path).
    """
    return _safe_load_settings(path)


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
        existing_raw = global_settings.get("permissions", {}).get("allow", [])
        existing_canon = {_canonicalize_pattern(p) for p in existing_raw}

        new_global = sorted(p for p in global_patterns
                            if _canonicalize_pattern(p) not in existing_canon)
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
            existing_raw = settings.get("permissions", {}).get("allow", [])
            existing_canon = {_canonicalize_pattern(p) for p in existing_raw}

            new_patterns = []
            for pattern, count, risk in patterns:
                if scope == "both" and pattern in global_patterns:
                    continue
                if _canonicalize_pattern(pattern) not in existing_canon:
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
        if r.get("_has_secrets") and not r["rejected"]:
            if r.get("_exposure_risk") == "exposed":
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
    hdr = f"  {label:<12} {'Total':>7} {'Auto':>7} {'Prompted':>10} {'Rej':>4} {'Auto%':>6} {'Avg7':>6} {'Destr':>6} {'Mutat':>7} {'R/O':>7} {'Sec':>4}"
    sep = f"  {'-'*12} {'-'*7} {'-'*7} {'-'*10} {'-'*4} {'-'*6} {'-'*6} {'-'*7} {'-'*7} {'-'*7} {'-'*4}"
    _print(f"CLAUDE CODE TREND ANALYSIS (by {bucket})")
    _print("=" * len(hdr))
    _print(hdr)
    _print(sep)

    auto_pcts = []
    for key in sorted_keys:
        b = buckets[key]
        auto_pcts.append((b["auto"] / b["total"] * 100) if b["total"] else 0)

    rolling_avgs = []
    for i in range(len(auto_pcts)):
        window = auto_pcts[max(0, i - 6):i + 1]
        rolling_avgs.append(sum(window) / len(window))

    def fmt_row(key, b, arrow="", rolling_avg=None):
        auto_pct = (b["auto"] / b["total"] * 100) if b["total"] else 0
        prompted_s = f"{b['prompted']:,}"
        if arrow:
            prompted_s += " " + arrow
        avg_s = f"{rolling_avg:>5.1f}%" if rolling_avg is not None else "     -"
        return (f"  {key:<12} {b['total']:>7,} {b['auto']:>7,} {prompted_s:>10}"
                f" {b['rejected']:>4} {auto_pct:>5.1f}% {avg_s} {b['destructive']:>6}"
                f" {b['mutating']:>7,} {b['read-only']:>7,} {b['secrets']:>4}")

    prev_prompted = None
    for i, key in enumerate(sorted_keys):
        b = buckets[key]
        arrow = ""
        if prev_prompted is not None and b["prompted"] > 0:
            if b["prompted"] < prev_prompted:
                arrow = "↓"
            elif b["prompted"] > prev_prompted:
                arrow = "↑"
        prev_prompted = b["prompted"]
        _print(fmt_row(key, b, arrow, rolling_avg=rolling_avgs[i]))

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

BASELINE_SAFE_ALLOW = [
    "Bash(cat *)",
    "Bash(echo *)",
    "Bash(find *)",
    "Bash(grep *)",
    "Bash(head *)",
    "Bash(ls *)",
    "Bash(pwd *)",
    "Bash(tail *)",
    "Bash(wc *)",
    "Grep",
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
            "allow": list(BASELINE_SAFE_ALLOW),
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
    print(f"  Allow rules: {len(BASELINE_SAFE_ALLOW)} read-only patterns (Bash builtins + Grep tool)", file=sys.stderr)
    print(f"  Deny rules: {len(BASELINE_DENY_RULES)} patterns (Read/Write/Edit for sensitive files)", file=sys.stderr)

    global_settings = load_global_settings()
    existing_allow = set(global_settings.get("permissions", {}).get("allow", []))
    existing_deny = set(global_settings.get("permissions", {}).get("deny", []))
    new_allow = [r for r in BASELINE_SAFE_ALLOW if r not in existing_allow]
    new_deny = [r for r in BASELINE_DENY_RULES if r not in existing_deny]
    already_allow = len(BASELINE_SAFE_ALLOW) - len(new_allow)
    already_deny = len(BASELINE_DENY_RULES) - len(new_deny)

    if existing_allow or existing_deny:
        if existing_allow:
            print(f"  Allow already configured: {already_allow} of {len(BASELINE_SAFE_ALLOW)}", file=sys.stderr)
            if new_allow:
                for rule in new_allow:
                    print(f"    + {rule}", file=sys.stderr)
        print(f"  Deny already configured: {already_deny} of {len(BASELINE_DENY_RULES)}", file=sys.stderr)
        if new_deny:
            for rule in new_deny:
                print(f"    + {rule}", file=sys.stderr)
        if not new_allow and not new_deny:
            print(f"  All baseline rules already configured.", file=sys.stderr)

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


def render_secrets(all_records, out=None):
    """Detailed report of all secret-flagged commands with exposure analysis."""
    if out is None:
        out = sys.stdout
    _print = lambda *args, **kwargs: print(*args, file=out, **kwargs)

    exposures = _find_secret_exposures(all_records)
    if not exposures:
        _print("No secret-flagged commands found.")
        return

    _print(f"\n{'='*90}")
    _print(f"  SECRET EXPOSURE ANALYSIS — {len(exposures)} flagged command(s)")
    _print(f"{'='*90}\n")

    by_risk = Counter()
    by_category = Counter()
    by_project = Counter()
    rows = []

    for r, category in exposures:
        risk_level = r.get("_exposure_risk", "exposed")
        by_risk[risk_level] += 1
        by_category[category] += 1
        by_project[short_project_name(r["project"])] += 1
        rows.append((r, category, risk_level))

    # Summary
    _print(f"  By exposure risk:")
    risk_order = ["exposed", "runtime", "variable", "pipe-safe", "false-positive"]
    risk_labels = {
        "exposed": "EXPOSED  — literal secret in command text (in transcript)",
        "runtime": "RUNTIME  — secret fetched via $(), may appear in output",
        "variable": "VARIABLE — secret referenced via $VAR, may appear in output",
        "pipe-safe": "PIPE-SAFE — secret flows through pipe, never in transcript",
        "false-positive": "FALSE-POS — not actually a secret (git hash, public key, test data)",
    }
    for risk in risk_order:
        count = by_risk.get(risk, 0)
        if count:
            _print(f"    {risk_labels[risk]:60s} {count:>5}")
    _print()

    _print(f"  By detection category:")
    cat_labels = {
        "token": "Known token pattern (ghp_, hvs., sk-, etc.)",
        "jwt": "JWT token",
        "private_key": "Private key material",
        "auth_header": "Authorization header",
        "secret_assign": "Secret variable assignment",
        "high_entropy": "High-entropy blob",
    }
    for cat, count in by_category.most_common():
        _print(f"    {cat_labels.get(cat, cat):50s} {count:>5}")
    _print()

    _print(f"  By project:")
    for proj, count in by_project.most_common():
        _print(f"    {proj:50s} {count:>5}")
    _print()

    # Detailed listing
    _print(f"  {'—'*86}")
    _print(f"  {'Timestamp':<18s} {'Risk':<10s} {'Category':<14s} {'Project':<14s} Command")
    _print(f"  {'—'*86}")

    for r, category, risk_level in rows:
        ts = r.get("timestamp", "")
        try:
            dt = datetime.fromisoformat(ts)
            time_display = dt.strftime("%Y-%m-%d %H:%M")
        except (ValueError, TypeError):
            time_display = ts[:16] if ts else "?"

        project = short_project_name(r["project"])
        cmd = r.get("full_command", r["tool_input"].get("command", ""))
        cmd_display = cmd.replace('\n', ' ')[:60]

        risk_tag = {
            "exposed": "EXPOSED",
            "runtime": "RUNTIME",
            "variable": "VAR-REF",
            "pipe-safe": "SAFE",
            "false-positive": "FALSE-POS",
        }.get(risk_level, risk_level)

        _print(f"  {time_display:<18s} {risk_tag:<10s} {category:<14s} {project:<14s} {cmd_display}")

    _print(f"  {'—'*86}")
    _print()

    exposed = by_risk.get("exposed", 0)
    safe = by_risk.get("pipe-safe", 0) + by_risk.get("variable", 0)
    fp = by_risk.get("false-positive", 0)
    runtime = by_risk.get("runtime", 0)

    if safe + fp > 0:
        _print(f"  {safe + fp} of {len(exposures)} flagged commands are not real exposures")
        _print(f"  ({fp} false positives, {safe} variable/pipe-safe).")
    if exposed > 0:
        _print(f"\n  {exposed} commands had literal secrets in the command text.")
        _print(f"  {SECRET_WARNING}")
    _print()


def render_warns(all_records, since=None, out=None):
    """Show hook warning events from the audit log, cross-referenced with session data."""
    if out is None:
        out = sys.stdout

    audit_path = CLAUDE_DIR / "hook-audit.jsonl"
    if not audit_path.exists():
        print("No hook audit log found at ~/.claude/hook-audit.jsonl", file=out)
        print("Audit logging is enabled by default in the hook (HOOK_AUDIT=1).", file=out)
        return

    warns = []
    try:
        with open(audit_path) as f:
            for line in f:
                try:
                    rec = json.loads(line)
                except json.JSONDecodeError:
                    continue
                if rec.get("decision") != "warn":
                    continue
                warns.append(rec)
    except Exception:
        print(f"Error reading {audit_path}", file=out)
        return

    if since:
        filtered = []
        for w in warns:
            try:
                ts = datetime.fromisoformat(w["ts"])
                if ts.tzinfo is None:
                    ts = ts.replace(tzinfo=timezone.utc)
                if ts >= since:
                    filtered.append(w)
            except (KeyError, ValueError):
                continue
        warns = filtered

    if not warns:
        print("No hook warnings found.", file=out)
        return

    # Build lookup of session commands by approximate timestamp + command text.
    # Two indexes:
    #   session_cmds: exact (ts_prefix, cmd[:200]) -> rec for the fast path
    #   session_cmds_by_prefix: cmd[:64] -> [rec, ...] for substring fallback
    # The prefix index avoids the historical O(W × R) linear scan when the
    # warn's command shares a leading prefix with a session record (the common
    # case — both come from the same hook invocation).
    session_cmds = {}
    session_cmds_by_prefix = defaultdict(list)
    for r in all_records:
        if r["tool_name"] != "Bash":
            continue
        cmd = r.get("full_command", "")
        ts = r.get("timestamp", "")
        if cmd and ts:
            session_cmds[(ts[:16], cmd[:200])] = r
            session_cmds_by_prefix[cmd[:64]].append(r)

    print(f"\n{'='*78}", file=out)
    print(f"  Hook Warnings — {len(warns)} event(s)", file=out)
    print(f"{'='*78}\n", file=out)

    approved = 0
    rejected = 0
    unknown = 0

    for w in warns:
        ts_str = w.get("ts", "?")
        cmd = w.get("command", w.get("summary", "?"))
        reason = w.get("reason", "?")

        # Try to find this command in session data to determine user decision
        decision = "unknown"
        try:
            ts_prefix = ts_str[:16]
        except (TypeError, IndexError):
            ts_prefix = ""

        cmd_short = cmd[:200] if cmd else ""
        # Try exact match first, then prefix-indexed substring, then full scan.
        matched_rec = session_cmds.get((ts_prefix, cmd_short))
        if not matched_rec and cmd_short:
            for rec in session_cmds_by_prefix.get(cmd_short[:64], []):
                rec_cmd = rec.get("full_command", "")[:200]
                if cmd_short in rec_cmd:
                    matched_rec = rec
                    break
            if not matched_rec:
                # Final fallback: linear scan for substring matches that don't
                # share a leading prefix (rare; preserved for behavioral parity).
                for key, rec in session_cmds.items():
                    if cmd_short in key[1]:
                        matched_rec = rec
                        break

        if matched_rec:
            if matched_rec.get("rejected"):
                decision = "rejected"
                rejected += 1
            else:
                decision = "approved"
                approved += 1
        else:
            unknown += 1

        # Format timestamp for display
        try:
            dt = datetime.fromisoformat(ts_str)
            time_display = dt.strftime("%Y-%m-%d %H:%M")
        except (ValueError, TypeError):
            time_display = ts_str[:16] if ts_str else "?"

        decision_display = {
            "approved": "APPROVED",
            "rejected": "REJECTED",
            "unknown": "—",
        }[decision]

        print(f"  {time_display}  [{decision_display:>8}]  {cmd[:70]}", file=out)
        print(f"    Reason: {reason}", file=out)
        print(file=out)

    print(f"  {'—'*70}", file=out)
    print(f"  Total: {len(warns)} warns | "
          f"{approved} approved | {rejected} rejected | {unknown} no session match", file=out)
    if unknown:
        print(f"  Note: 'no session match' means the warn was from a non-session context", file=out)
        print(f"        (e.g. test run, manual invocation) or session data was pruned.", file=out)
    print(file=out)


# --- Phase 4: token-report renderers ---


def _compute_token_findings(records, prose_records, top=None,
                             min_sessions=3, min_tokens=5000):
    """Run all four detectors, rank, and return top-N findings.

    Pure function — no I/O. `top=None` returns all findings.
    `min_sessions` and `min_tokens` override Pattern A (repeated-reads)
    thresholds; other detectors keep their built-in defaults.
    """
    findings = []
    findings += find_repeated_reads(records, min_sessions=min_sessions,
                                    min_tokens=min_tokens)
    findings += find_recipe_ngrams(records)
    findings += find_repeated_prose(prose_records or [])
    findings += find_resummarized_outputs(records)
    rank_findings(findings)
    if top is not None and top > 0:
        findings = findings[:top]
    return findings


def _suggestion_headline(finding):
    """One-line remediation hint shown in the report table."""
    kind = finding.get("kind", "")
    if kind == "repeated_read":
        return ".claude/refs/ digest"
    if kind == "repeated_webfetch":
        return ".claude/refs/ snapshot (verify freshness)"
    if kind == "recipe_ngram":
        n = finding.get("_raw", {}).get("n", 0)
        return "skill" if n >= 5 else "slash command"
    if kind == "repeated_prose":
        return "CLAUDE.md addition"
    if kind == "resummarized_output":
        return "wrapper script (scripts/)"
    return ""


def _suggestion_body(finding):
    """Multi-line remediation suggestion shown in the DETAILS section."""
    kind = finding.get("kind", "")
    target = finding.get("target", "")
    if kind == "repeated_read":
        basename = os.path.basename(target.rstrip("/")) or "ref"
        return (
            f"Create .claude/refs/{basename}.md summarizing the key sections of\n"
            f"  {target}\n"
            f"Link from CLAUDE.md so it's loaded once per session instead of repeatedly read."
        )
    if kind == "repeated_webfetch":
        return (
            f"Cache a snapshot at .claude/refs/<host>-<slug>.md from\n"
            f"  {target}\n"
            f"Mark with retrieval date — external content, verify freshness periodically."
        )
    if kind == "recipe_ngram":
        n = finding.get("_raw", {}).get("n", 0)
        steps = finding.get("_raw", {}).get("steps", [])
        artifact = "skill" if n >= 5 else "slash command"
        path_hint = (
            "~/.claude/skills/<name>/SKILL.md" if n >= 5
            else ".claude/commands/<name>.md"
        )
        return (
            f"Create a {artifact} at {path_hint} that performs:\n"
            f"  {' → '.join(steps)}\n"
            f"Invoke as /<name> instead of running these manually."
        )
    if kind == "repeated_prose":
        exemplar = finding.get("_raw", {}).get("exemplar_full", target)
        preview = exemplar[:200].replace("\n", " ")
        return (
            f"Add this recurring text to CLAUDE.md (or a project-specific note):\n"
            f"  {preview}{'...' if len(exemplar) > 200 else ''}\n"
            f"Loaded once per session instead of pasted into every prompt."
        )
    if kind == "resummarized_output":
        ratio = finding.get("_raw", {}).get("narrow_ratio", 0)
        avg_bytes = finding.get("_raw", {}).get("avg_input_bytes", 0)
        return (
            f"Add scripts/<name>.sh that pre-narrows the output of\n"
            f"  {target}\n"
            f"Avg input bytes: {avg_bytes}; only ~{int(ratio * 100)}% surfaces in output today."
        )
    return ""


def _suggestion_type(finding):
    """Machine-readable suggestion type for JSON output."""
    kind = finding.get("kind", "")
    if kind == "repeated_read":
        return "reference_md"
    if kind == "repeated_webfetch":
        return "reference_md_external"
    if kind == "recipe_ngram":
        n = finding.get("_raw", {}).get("n", 0)
        return "skill" if n >= 5 else "slash_command"
    if kind == "repeated_prose":
        return "claude_md_addition"
    if kind == "resummarized_output":
        return "wrapper_script"
    return ""


def render_token_report(records, prose_records, top=20, detail_top=5, out=None):
    """Text report: ranked findings table + DETAILS section per top-N."""
    if out is None:
        out = sys.stdout

    findings = _compute_token_findings(records, prose_records, top=top)

    print("CLAUDE CODE TOKEN-CONSUMPTION REPORT", file=out)
    print("=" * 70, file=out)
    print(f"  Records scanned:    {len(records):>6}", file=out)
    print(f"  Prose blocks:       {len(prose_records or []):>6}", file=out)
    print(f"  Findings (top {top}):  {len(findings):>6}", file=out)
    print(file=out)

    if not findings:
        print("  No findings above threshold.", file=out)
        return

    # Header
    header = f"{'#':>3}  {'KIND':<22}{'OCC':>4} {'SESS':>4} {'AVG_TOK':>8} {'SCORE':>9} {'STAB':>5}  {'TARGET':<46} SUGGESTION"
    print(header, file=out)
    print("-" * len(header), file=out)
    for i, f in enumerate(findings, 1):
        target = f["target"]
        if len(target) > 44:
            target = target[:43] + "…"
        line = (
            f"{i:>3}  {f['kind']:<22}"
            f"{f['occurrences']:>4} {f['distinct_sessions']:>4} "
            f"{f['avg_tokens']:>8} {int(f['_score']):>9} "
            f"{f['_stability_factor']:>5.2f}  "
            f"{target:<46} {_suggestion_headline(f)}"
        )
        print(line, file=out)
    print(file=out)

    # Details section
    detail_n = min(detail_top, len(findings))
    if detail_n <= 0:
        return
    print("DETAILS (top {})".format(detail_n), file=out)
    print("=" * 70, file=out)
    for i, f in enumerate(findings[:detail_n], 1):
        print(file=out)
        print(f"[{i}] {f['kind']} — {f['target']}", file=out)
        print(
            f"    occurrences: {f['occurrences']} across {f['distinct_sessions']} sessions",
            file=out,
        )
        print(
            f"    avg_tokens: {f['avg_tokens']}, sum_tokens: {f['sum_tokens']}, "
            f"score: {int(f['_score'])}, stability: {f['_stability_factor']:.2f}",
            file=out,
        )
        sample = f.get("sample_session_ids", [])
        if sample:
            short = ", ".join(s[:8] for s in sample)
            print(f"    sample sessions: {short}", file=out)
        print(f"    suggestion ({_suggestion_type(f)}):", file=out)
        for line in _suggestion_body(f).splitlines():
            print(f"      {line}", file=out)


def render_token_report_json(records, prose_records, top=20, filters=None, out=None):
    """JSON report: structured findings for downstream tooling."""
    if out is None:
        out = sys.stdout

    findings = _compute_token_findings(records, prose_records, top=top)

    serialized = []
    for i, f in enumerate(findings, 1):
        serialized.append({
            "rank": i,
            "kind": f["kind"],
            "target": f["target"],
            "occurrences": f["occurrences"],
            "distinct_sessions": f["distinct_sessions"],
            "avg_tokens": f["avg_tokens"],
            "sum_tokens": f["sum_tokens"],
            "stability_factor": round(f["_stability_factor"], 3),
            "score": round(f["_score"], 1),
            "sample_session_ids": f.get("sample_session_ids", []),
            "suggestion": {
                "type": _suggestion_type(f),
                "headline": _suggestion_headline(f),
                "body": _suggestion_body(f),
            },
            "raw": f.get("_raw", {}),
        })

    payload = {
        "generated_at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "filters": filters or {},
        "summary": {
            "records_scanned": len(records),
            "prose_blocks": len(prose_records or []),
            "total_findings": len(findings),
            "top": top,
        },
        "findings": serialized,
    }
    json.dump(payload, out, indent=2)
    print(file=out)


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
    # Was 'Auto-allowed:' — collided with the prior line's same label that
    # reports historical counts. Use an unambiguous label for current state.
    print(f"  Currently in allowlist: {', '.join(status_parts)}")

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
        all_jsonl.extend(d.glob("**/*.jsonl"))

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
    parser = argparse.ArgumentParser(
        description="Analyze Claude Code approval data",
        epilog=(
            "examples:\n"
            "  %(prog)s --summary              compact dashboard\n"
            "  %(prog)s --trend 7d              daily trend, last week\n"
            "  %(prog)s --why 'git push'        diagnose a specific command\n"
            "  %(prog)s --secrets --since 7d    secret exposure report\n"
            "  %(prog)s --token-report          token-consumption optimization report\n"
            "  %(prog)s --apply --dry-run       preview allowlist changes\n"
            "  %(prog)s --generate-settings     deny rules + hook config\n"
            "\n"
            "env vars:\n"
            "  AUTOCLAUDE_MAX_SESSION_MB  per-file JSONL ingest cap (default: 100; set 0 to disable)\n"
            "  HOOK_AUDIT                 PreToolUse hook audit log (1/true/yes/on; default: 1)\n"
            "  HOOK_DEBUG                 PreToolUse hook stderr trace (1/true/yes/on; default: 0)\n"
            "  HOOK_CORRELATE             PostToolUse pre-to-post warn correlation (default: 1)\n"
            "\n"
            "full reference: docs/cli-reference.md"
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument(
        "--version",
        action="version",
        version=f"autoclaude {__version__}",
    )
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
        "--no-cross-project",
        action="store_true",
        default=False,
        help="Restrict the scan to the project matching the current working "
             "directory. By default the analyzer reads transcripts from every "
             "project under ~/.claude/projects/. Mutually exclusive with --project.",
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
    parser.add_argument(
        "--warns",
        action="store_true",
        default=False,
        help="Show hook warning events from ~/.claude/hook-audit.jsonl. "
             "Cross-references with session data to show user approval decisions.",
    )
    parser.add_argument(
        "--secrets",
        action="store_true",
        default=False,
        help="Detailed secret exposure report. Shows each flagged command with "
             "exposure analysis: whether the secret was a literal (exposed), "
             "variable reference, runtime expansion, or pipe-safe.",
    )
    parser.add_argument(
        "--token-report",
        action="store_true",
        default=False,
        help="Token-consumption optimization report. Detects repeated reads, "
             "recurring tool-call recipes, repeated user prose, and large "
             "re-summarized outputs. Suggests reference docs / slash commands / "
             "skills / wrappers per finding. Read-only.",
    )
    parser.add_argument(
        "--token-report-json",
        action="store_true",
        default=False,
        help="Same as --token-report but emits structured JSON for downstream tooling.",
    )
    parser.add_argument(
        "--token-top",
        type=int,
        default=20,
        metavar="N",
        help="With --token-report(-json): show only the top N findings (default 20).",
    )
    parser.add_argument(
        "--token-min-sessions",
        type=int,
        default=3,
        metavar="N",
        help="With --token-report(-json): a repeated-read finding requires "
             "at least N distinct sessions (default 3).",
    )
    parser.add_argument(
        "--token-min-tokens",
        type=int,
        default=5000,
        metavar="N",
        help="With --token-report(-json): a repeated-read finding requires "
             "at least N total tokens across all reads (default 5000).",
    )
    parser.add_argument(
        "--max-records",
        type=int,
        default=None,
        metavar="N",
        help="Cap the in-memory record list at N most-recent records. "
             "Memory usage grows linearly with tool-call history; use this "
             "for very large session corpora. Token-report aggregation "
             "(cross-session recipes/prose) will see a reduced sample.",
    )
    parser.add_argument(
        "-q", "--quiet",
        action="store_true",
        default=False,
        help="Suppress progress messages on stderr ('Scanning...', 'Filters:...'). "
             "Warning/Error messages still surface.",
    )
    args = parser.parse_args()

    # --no-cross-project narrows the default scan; mutually exclusive with
    # an explicit --project filter so the user's intent stays unambiguous.
    if args.no_cross_project and args.project:
        print("Error: --no-cross-project and --project are mutually exclusive.",
              file=sys.stderr)
        sys.exit(2)

    # Surface the --apply mutating --auto silent downgrade so the user knows
    # their stated intent wasn't fully honored. Print before any data load
    # so an empty-session early-exit still shows the warning.
    if args.apply is not None and args.auto and args.apply != "read-only":
        print(
            f"Warning: --auto forces risk level to read-only; "
            f"ignoring --apply {args.apply}. Use without --auto and "
            f"confirm interactively to apply non-read-only patterns.",
            file=sys.stderr,
        )

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

    if not args.quiet:
        print("Scanning Claude Code session data...", file=sys.stderr)

    global_settings = load_global_settings()
    global_allow = global_settings.get("permissions", {}).get("allow", [])

    collect_prose = args.token_report or args.token_report_json

    all_records = []
    all_prose = []

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
            if collect_prose:
                all_prose.extend(extract_user_prose(str(sf), project_name))
    else:
        project_dirs = sorted(PROJECTS_DIR.iterdir()) if PROJECTS_DIR.exists() else []
        if args.no_cross_project:
            target_slug = _cwd_to_project_slug()
            project_dirs = [d for d in project_dirs if d.name == target_slug]
            if not project_dirs and not args.quiet:
                print(
                    f"--no-cross-project: no transcripts found for slug "
                    f"{target_slug!r} (cwd={os.getcwd()!r})",
                    file=sys.stderr,
                )
        for project_dir in project_dirs:
            if not project_dir.is_dir():
                continue
            project_name = project_dir.name
            project_allow = load_project_settings(project_name)
            combined_allow = global_allow + project_allow
            jsonl_files = sorted(project_dir.glob("**/*.jsonl"))
            for jsonl_file in jsonl_files:
                records = process_session(str(jsonl_file), combined_allow, project_name)
                all_records.extend(records)
                if collect_prose:
                    all_prose.extend(extract_user_prose(str(jsonl_file), project_name))

    all_records = filter_records(all_records, since=since, project=args.project)
    if collect_prose and args.project:
        all_prose = [p for p in all_prose if p.get("project") == args.project
                     or short_project_name(p.get("project", "")) == args.project]

    if args.max_records is not None and args.max_records > 0:
        if len(all_records) > args.max_records:
            # Keep the most-recent N records (last in chronological order).
            all_records.sort(key=lambda r: _parse_ts(r.get("timestamp", ""))
                             or datetime.min.replace(tzinfo=timezone.utc))
            dropped = len(all_records) - args.max_records
            all_records = all_records[-args.max_records:]
            print(f"--max-records: kept {args.max_records} most-recent, "
                  f"dropped {dropped} older records.", file=sys.stderr)

    if (not all_records
        and not args.generate_settings
        and not args.warns
        and not args.secrets
        and not args.token_report
        and not args.token_report_json):
        print("No tool call data found.", file=sys.stderr)
        sys.exit(1)

    active_filters = []
    if args.since:
        active_filters.append(f"since {args.since}")
    if args.project:
        active_filters.append(f"project={args.project}")
    if args.session:
        active_filters.append(f"session={args.session}")
    if active_filters and not args.quiet:
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

    if args.warns:
        render_warns(all_records, since=since)
        return

    if args.secrets:
        render_secrets(all_records)
        return

    if args.token_report or args.token_report_json:
        as_json = args.token_report_json
        active_filter_dict = {}
        if args.since:
            active_filter_dict["since"] = args.since
        if args.project:
            active_filter_dict["project"] = args.project
        if args.session:
            active_filter_dict["session"] = args.session

        def _render(out=None):
            if as_json:
                render_token_report_json(
                    all_records, all_prose,
                    top=args.token_top,
                    filters=active_filter_dict,
                    out=out,
                )
            else:
                render_token_report(
                    all_records, all_prose,
                    top=args.token_top,
                    out=out,
                )

        if args.output is None:
            _render()
        else:
            ext = ".json" if as_json else ".txt"
            if args.output == "auto":
                out_path = f"claude-token-report-{datetime.now(timezone.utc).strftime('%Y-%m-%dT%H%M%SZ')}{ext}"
            elif os.path.isdir(args.output):
                out_path = os.path.join(
                    args.output,
                    f"claude-token-report-{datetime.now(timezone.utc).strftime('%Y-%m-%dT%H%M%SZ')}{ext}",
                )
            else:
                out_path = args.output
            _atomic_write(out_path, lambda f: _render(out=f))
            print(f"Token report written to {out_path}", file=sys.stderr)
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
