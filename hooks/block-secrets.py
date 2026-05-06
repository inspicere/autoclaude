#!/usr/bin/env python3
"""PreToolUse hook — blocks Bash commands containing secrets and reads of sensitive files.

Catches two classes of leaks that deny rules alone cannot prevent:
  1. Embedded secrets in Bash commands (tokens, JWTs, auth headers, high-entropy blobs)
  2. Sensitive file reads via Bash (cat .env, head ~/.ssh/id_rsa) that bypass Read deny rules

Install by adding to hooks in ~/.claude/settings.json:
  "hooks": {
    "PreToolUse": [{
      "matcher": "Bash|Read|Edit",
      "hooks": [{"type": "command", "command": "python3 /path/to/hooks/block-secrets.py"}]
    }]
  }

Blocks by exiting with code 2 (stderr shown to user). Exits 0 to allow.
"""

import json
import math
import os
import re
import sys


# --- Token patterns (same as claude-approval-report.py) ---

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

_RE_SECRET_ASSIGN = re.compile(
    r'([\w]*(?:API_KEY|SECRET|TOKEN|PASSWORD|PRIVATE_KEY|CREDENTIAL|_AUTH|AUTH_)[\w]*)'
    r'=\s*(\S+)',
    re.IGNORECASE,
)

# Commands that are searching FOR patterns, not using secrets
_GREP_FAMILY = frozenset({
    'grep', 'egrep', 'fgrep', 'rg', 'ag', 'ack', 'find', 'sed', 'awk',
})

# --- Sensitive file path detection ---

_SENSITIVE_PATH_RE = re.compile(
    r'(?:'
    r'(?:^|/)\.env(?:\.\w+)?$'
    r'|(?:^|/)\.dev\.vars(?:\.\w+)?$'
    r'|\.(?:pem|key|p12|pfx)$'
    r'|(?:^|/)\.aws/(?:credentials|config)$'
    r'|(?:^|/)\.ssh/id_'
    r'|(?:^|/)\.vault[-_]token$'
    r'|(?:^|/)\.npmrc$'
    r'|(?:^|/)\.pypirc$'
    r'|(?:^|/)credentials\.json$'
    r'|(?:^|/)service[-_]account.*\.json$'
    r'|/etc/g?shadow$'
    r'|(?:^|/)\.kube/config$'
    r'|(?:^|/)\.docker/config\.json$'
    r'|(?:^|/)\.netrc$'
    r'|(?:^|/)\.pgpass$'
    r'|(?:^|/)\.ansible[-_]vault[-_]password'
    r')',
)

_FILE_READERS = frozenset({
    'cat', 'head', 'tail', 'less', 'more', 'bat', 'nl', 'tac', 'rev',
    'strings', 'xxd', 'od', 'hexdump', 'base64', 'source', '.',
})


def _shannon_entropy(data):
    if not data:
        return 0.0
    counts = {}
    for c in data:
        counts[c] = counts.get(c, 0) + 1
    length = len(data)
    return -sum((n / length) * math.log2(n / length) for n in counts.values())


def _is_sensitive_path(path):
    path = os.path.expanduser(path)
    if not path.startswith('/'):
        path = '/' + path
    basename = os.path.basename(path)
    if basename.endswith(('.example', '.sample', '.template')):
        return False
    if path.endswith('.pub'):
        return False
    return bool(_SENSITIVE_PATH_RE.search(path))


def _check_command_secrets(command):
    """Check for embedded secrets in a Bash command. Returns reason string or None."""
    if _PREFIXED_TOKEN_PATTERNS.search(command):
        return "Command contains a known API token/key pattern"

    if _RE_JWT.search(command):
        return "Command contains a JWT token"

    if _RE_PRIVATE_KEY.search(command):
        return "Command contains private key material"

    if _RE_CURL_AUTH.search(command):
        auth_val = re.search(r'\b(?:Bearer|Token)\s+(\S+)', command, re.IGNORECASE)
        if auth_val:
            val = auth_val.group(1).strip("\"'")
            if not val.startswith('$'):
                return "Command contains an Authorization header with credentials"
        else:
            return "Command contains an Authorization header with credentials"

    m = _RE_SECRET_ASSIGN.search(command)
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
            return f"Command assigns a value to secret variable {m.group(1)}"

    parts = command.split()
    if len(parts) > 1:
        for token in parts[1:]:
            clean = token.strip("\"'")
            if clean.startswith(('/', '.', '~', '-', '$', '{', '(')):
                continue
            if len(clean) >= 32 and re.match(r'^[A-Za-z0-9+/=]+$', clean):
                if _shannon_entropy(clean) >= 3.5:
                    return "Command contains a high-entropy string (possible secret)"

    return None


_RE_STDIN_REDIRECT = re.compile(
    r'<\s*([^\s<>&|;]+)'
)

_RE_SHELL_EXEC = re.compile(
    r'\b(?:bash|sh|zsh)\s+-c\s+["\'](.+?)["\']'
    r'|'
    r'\b(?:bash|sh|zsh)\s+-c\s+(\S+)',
    re.DOTALL,
)

_RE_EVAL = re.compile(
    r'\beval\s+["\'](.+?)["\']'
    r'|'
    r'\beval\s+(.+)',
    re.DOTALL,
)

_RE_INTERP_FILE_READ = re.compile(
    r'''(?:open|Path)\s*\(\s*['"]([^'"]+)['"]'''
    r'''|File\.(?:read|open)\s*\(\s*['"]([^'"]+)['"]'''
    r'''|open\s*\(\s*\w+\s*,\s*['"](?:<\s*)?['"]?\s*,\s*['"]([^'"]+)['"]'''
    r'''|open\s+\w+\s*,\s*['"]?([^'";\s]+)['"]?'''
)

_INTERPRETERS = frozenset({'python3', 'python', 'perl', 'ruby', 'node'})


def _check_sensitive_paths_in_text(text):
    """Scan arbitrary text for sensitive file paths. Returns first match or None."""
    for token in re.findall(r'[/~.][\w./_-]+', text):
        if _is_sensitive_path(token):
            return token
    return None


def _check_bash_file_access(command):
    """Check if a Bash command reads sensitive files. Returns reason string or None."""
    cmd = re.sub(r'^(cd\s+(?:\S+|"[^"]*"|\'[^\']*\')\s*&&\s*)+', '', command.strip())
    cmd = re.sub(r'^(\w+=(?:\S+|"[^"]*"|\'[^\']*\')\s+)+', '', cmd)
    parts = cmd.split()
    if not parts:
        return None

    base = os.path.basename(parts[0])

    # Direct file readers: cat, head, tail, etc.
    if base in _FILE_READERS:
        for arg in parts[1:]:
            if arg.startswith('-'):
                continue
            if _is_sensitive_path(arg):
                return f"Command reads sensitive file: {arg}"

    # dd if=<path>
    if base == 'dd':
        for arg in parts[1:]:
            if arg.startswith('if='):
                path = arg[3:]
                if _is_sensitive_path(path):
                    return f"Command reads sensitive file via dd: {path}"

    # eval '<inner command>' — unwrap and re-check
    if base == 'eval':
        m = _RE_EVAL.search(cmd)
        if m:
            inner = m.group(1) or m.group(2)
            if inner:
                result = _check_bash_file_access(inner)
                if result:
                    return f"eval wraps blocked command: {result}"

    # bash -c / sh -c / zsh -c — unwrap and re-check
    for m in _RE_SHELL_EXEC.finditer(cmd):
        inner = m.group(1) or m.group(2)
        if inner:
            result = _check_bash_file_access(inner)
            if result:
                return f"Subshell wraps blocked command: {result}"

    # Interpreter file reads: python3 -c, perl -e, ruby -e
    if base in _INTERPRETERS:
        for i, arg in enumerate(parts[1:], 1):
            if arg in ('-c', '-e') and i + 1 <= len(parts) - 1:
                script = ' '.join(parts[i + 1:])
                for fm in _RE_INTERP_FILE_READ.finditer(script):
                    path = fm.group(1) or fm.group(2) or fm.group(3) or fm.group(4)
                    if path and _is_sensitive_path(path):
                        return f"Interpreter reads sensitive file: {path}"
                sensitive = _check_sensitive_paths_in_text(script)
                if sensitive:
                    return f"Interpreter script references sensitive file: {sensitive}"
                break

    # Shell stdin redirection: < /path/to/sensitive
    for m in _RE_STDIN_REDIRECT.finditer(command):
        path = m.group(1).strip("\"'")
        if _is_sensitive_path(path):
            return f"Stdin redirection from sensitive file: {path}"

    return None


def _check_file_path(path):
    """Check if a Read/Edit file_path targets a sensitive file."""
    if _is_sensitive_path(path):
        return f"Sensitive file access blocked: {path}"
    return None


def block(reason):
    print(reason, file=sys.stderr)
    sys.exit(2)


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
        if not command:
            sys.exit(0)

        stripped = re.sub(r'^(cd\s+(?:\S+|"[^"]*"|\'[^\']*\')\s*&&\s*)+', '', command.strip())
        stripped = re.sub(r'^(\w+=(?:\S+|"[^"]*"|\'[^\']*\')\s+)+', '', stripped)
        base_parts = stripped.split()
        if base_parts:
            base = os.path.basename(base_parts[0])
            if base not in _GREP_FAMILY:
                reason = _check_command_secrets(command)
                if reason:
                    block(f"BLOCKED: {reason}")

        reason = _check_bash_file_access(command)
        if reason:
            block(f"BLOCKED: {reason}")

    elif tool_name in ("Read", "Edit"):
        file_path = tool_input.get("file_path", "")
        if file_path:
            reason = _check_file_path(file_path)
            if reason:
                block(f"BLOCKED: {reason}")

    sys.exit(0)


if __name__ == "__main__":
    main()
