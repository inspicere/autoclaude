#!/usr/bin/env python3
"""PreToolUse hook — blocks Bash commands containing secrets and reads of sensitive files.

Catches two classes of leaks that deny rules alone cannot prevent:
  1. Embedded secrets in Bash commands (tokens, JWTs, auth headers, high-entropy blobs)
  2. Sensitive file reads via Bash (cat .env, head ~/.ssh/id_rsa) that bypass Read deny rules

Install by adding to hooks in ~/.claude/settings.json:
  "hooks": {
    "PreToolUse": [{
      "matcher": "Bash|Read|Edit|Write",
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
    r'\b(\w{0,50}(?:API_KEY|SECRET|TOKEN|PASSWORD|PRIVATE_KEY|CREDENTIAL|_AUTH|AUTH_)\w*)'
    r'=\s*(\S+)',
    re.IGNORECASE,
)

_RE_HIGH_ENTROPY = re.compile(r'^[A-Za-z0-9+/=]+$')

_SAFE_PLACEHOLDERS = frozenset({
    'changeme', 'password', 'placeholder', 'example',
    'your-token-here', 'your_token_here', 'replace-me',
    'xxxxxxxx', 'test1234', 'password123', 'true', 'false',
    'none', 'null',
})

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
    r'|(?:^|/)\.git-credentials$'
    r'|(?:^|/)\.gnupg/(?:secring|private-keys)'
    r'|(?:^|/)\.bash_history$'
    r'|(?:^|/)\.zsh_history$'
    r'|(?:^|/)\.my\.cnf$'
    r'|(?:^|/)\.?terraform\.tfstate(?:\.backup)?$'
    r')',
)

_FILE_READERS = frozenset({
    'cat', 'head', 'tail', 'less', 'more', 'bat', 'nl', 'tac', 'rev',
    'strings', 'xxd', 'od', 'hexdump', 'base64', 'source', '.',
    'sort', 'paste', 'cut', 'fmt', 'fold', 'expand', 'pr', 'column',
    'diff', 'cmp', 'comm', 'csplit', 'split', 'join', 'uniq', 'iconv',
    'jq', 'yq', 'xq', 'script',
    # Additional content-reading tools (round 2 audit)
    'shuf', 'unexpand', 'colrm', 'look', 'tsort', 'ptx', 'nkf',
    'uuencode', 'base32', 'zcat', 'bzcat', 'xzcat', 'lz4', 'vidir',
})

# Tools that accept a sensitive file via -flag VALUE (separate token, not -flag=VALUE)
# Maps command name -> set of flags whose next argument is a file path
_FILE_FLAG_ARGS = {
    'openssl': {'-in', '-inkey', '-certfile', '-CAfile'},
    'ansible-vault': {'--vault-password-file', '--vault-pass-file'},
    'ansible-playbook': {'--vault-password-file', '--vault-pass-file'},
    'ansible': {'--vault-password-file', '--vault-pass-file'},
}

# Long-option prefixes whose value (after '=') is a file path, for _FILE_READERS members
_LONG_FILE_FLAGS = frozenset({
    '--from-file=', '--old-file=', '--new-file=',       # diff
    '--files0-from=',                                    # sort
    '--input-file=', '--file=',                          # various
})

_FILE_COPIERS = frozenset({
    'cp', 'mv', 'ln', 'install', 'rsync', 'scp',
})

_COMMAND_WRAPPERS = frozenset({
    'sudo', 'env', 'time', 'nice', 'timeout', 'nohup', 'command', 'busybox',
    'stdbuf', 'ionice', 'numactl', 'taskset', 'chrt',
})

_INTERPRETERS = frozenset({
    'python3', 'python', 'perl', 'ruby', 'node', 'php', 'lua',
})

_RE_COMMAND_SUBST = re.compile(r'\$\((.+?)\)', re.DOTALL)
_RE_PROC_SUBST = re.compile(r'<\((.+?)\)', re.DOTALL)
_RE_BACKTICK_SUBST = re.compile(r'`(.+?)`', re.DOTALL)

_SENSITIVE_DIRS_RE = re.compile(
    r'(?:^|/)\.(?:ssh|gnupg|aws|kube|docker)/?$'
)

_RE_STDIN_REDIRECT = re.compile(r'(?<!<)<(?!<)\s*([^\s<>&|;]+)')

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

_RE_HEREDOC = re.compile(
    r'<<\s*-?\s*[\'"]?(\w+)[\'"]?',
)

_RE_INTERP_FILE_READ = re.compile(
    r'''(?:open|Path)\s*\(\s*['"]([^'"]+)['"]'''
    r'''|File\.(?:read|open)\s*\(\s*['"]([^'"]+)['"]'''
    r'''|open\s*\(\s*\w+\s*,\s*['"](?:<\s*)?['"]?\s*,\s*['"]([^'"]+)['"]'''
    r'''|open\s+\w+\s*,\s*['"]?([^'";\s]+)['"]?'''
    r'''|file_get_contents\s*\(\s*['"]([^'"]+)['"]'''
)


def _shannon_entropy(data):
    if not data:
        return 0.0
    counts = {}
    for c in data:
        counts[c] = counts.get(c, 0) + 1
    length = len(data)
    return -sum((n / length) * math.log2(n / length) for n in counts.values())


def _strip_quotes(s):
    if len(s) >= 2 and s[0] == s[-1] and s[0] in ('"', "'"):
        return s[1:-1]
    if s.startswith(("'", '"')):
        return s[1:]
    if s.endswith(("'", '"')):
        return s[:-1]
    return s


_GLOB_CHARS = frozenset('*?[{')


def _could_glob_match_sensitive(token):
    """Check if a glob pattern could expand to match a sensitive path."""
    if not any(c in token for c in _GLOB_CHARS):
        return False
    import fnmatch
    pattern_basename = os.path.basename(token)
    if pattern_basename in ('*', '?', '**'):
        return False
    for sensitive_name in ('.env', '.env.local', '.env.production', '.env.development',
                           '.pem', '.key', '.npmrc', '.pypirc', '.netrc', '.pgpass',
                           '.my.cnf', '.git-credentials', '.bash_history', '.zsh_history',
                           '.dev.vars', '.vault-token', '.vault_token'):
        if fnmatch.fnmatch(sensitive_name, pattern_basename):
            return True
    return False


def _is_sensitive_path(path):
    path = _strip_quotes(path)
    path = os.path.expanduser(path)
    if not path.startswith('/'):
        path = '/' + path
    basename = os.path.basename(path)
    if basename.endswith(('.example', '.sample', '.template')):
        return False
    if path.endswith('.pub'):
        return False
    if _could_glob_match_sensitive(path):
        return True
    return bool(_SENSITIVE_PATH_RE.search(path))


def _check_command_secrets(command):
    """Check for embedded secrets in a command string. Returns reason or None."""
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
            if not val.startswith('$') and val.lower() not in _SAFE_PLACEHOLDERS:
                return "Command contains an Authorization header with credentials"
        else:
            return "Command contains an Authorization header with credentials"

    m = _RE_SECRET_ASSIGN.search(command)
    if m:
        val = m.group(2).strip("\"'")
        if (len(val) > 8
                and not val.startswith(('$', '{', 'http://', 'https://', '/'))
                and val.lower() not in _SAFE_PLACEHOLDERS):
            return f"Command assigns a value to secret variable {m.group(1)}"

    parts = command.split()
    if len(parts) > 1:
        for token in parts[1:]:
            clean = token.strip("\"'")
            if clean.startswith(('/', '.', '~', '-', '$', '{', '(')):
                continue
            if len(clean) >= 32 and _RE_HIGH_ENTROPY.match(clean):
                if _shannon_entropy(clean) >= 3.5:
                    return "Command contains a high-entropy string (possible secret)"

    return None


def _unwrap_grouping(command):
    """Unwrap outer ( ... ) subshell or { ...; } brace grouping, returning inner text or None."""
    s = command.strip()
    s = s.rstrip('& \t')
    if s.startswith('(') and s.endswith(')'):
        return s[1:-1].strip()
    if s.startswith('{') and s.endswith('}'):
        inner = s[1:-1].strip()
        if inner.endswith(';'):
            inner = inner[:-1].strip()
        return inner
    return None


def _split_shell_commands(command):
    """Split a shell command on ;, &&, ||, | respecting quotes.

    Also unwraps outer ( ) subshells and { } brace groups so that
    (cat file) and { cat file; } are not treated as atomic opaque tokens.
    """
    # Unwrap outer grouping so (cat .env) and { cat .env; } are traversed
    unwrapped = _unwrap_grouping(command)
    if unwrapped is not None:
        return _split_shell_commands(unwrapped)

    commands = []
    current = []
    i = 0
    in_sq = False
    in_dq = False
    paren_depth = 0

    while i < len(command):
        c = command[i]

        if c == '\\' and in_dq and i + 1 < len(command):
            current.append(c)
            current.append(command[i + 1])
            i += 2
            continue

        if c == "'" and not in_dq:
            in_sq = not in_sq
            current.append(c)
        elif c == '"' and not in_sq:
            in_dq = not in_dq
            current.append(c)
        elif not in_sq and not in_dq:
            if c == '(':
                paren_depth += 1
                current.append(c)
            elif c == ')':
                paren_depth -= 1
                current.append(c)
            elif paren_depth > 0:
                # Inside nested parens — collect verbatim, don't split
                current.append(c)
            elif c == ';':
                cmd = ''.join(current).strip()
                if cmd:
                    commands.append(cmd)
                current = []
            elif c == '&' and i + 1 < len(command) and command[i + 1] == '&':
                cmd = ''.join(current).strip()
                if cmd:
                    commands.append(cmd)
                current = []
                i += 1
            elif c == '|' and i + 1 < len(command) and command[i + 1] == '|':
                cmd = ''.join(current).strip()
                if cmd:
                    commands.append(cmd)
                current = []
                i += 1
            elif c == '|':
                cmd = ''.join(current).strip()
                if cmd:
                    commands.append(cmd)
                current = []
            else:
                current.append(c)
        else:
            current.append(c)
        i += 1

    cmd = ''.join(current).strip()
    if cmd:
        commands.append(cmd)

    # Post-process: for any segment that is a bare shell interpreter (sh, bash, zsh)
    # preceded by a pipe, the previous segment's string content is the injected command.
    # We detect this by scanning the segments list for shell-interpreter-only segments.
    _RE_QUOTED_ARG = re.compile(r"""'([^']*)'|"((?:[^"\\]|\\.)*)"|(\S+)""")

    result = []
    for idx, seg in enumerate(commands):
        result.append(seg)
        stripped = _strip_prefixes(seg).strip()
        parts = stripped.split()
        if parts and os.path.basename(parts[0]) in ('sh', 'bash', 'zsh', 'dash'):
            # This segment is a bare shell interpreter — the previous segment may
            # feed commands to it. Re-check the previous segment's content
            # as a potential command string passed to the interpreter.
            if idx > 0:
                prev = commands[idx - 1]
                prev_stripped = _strip_prefixes(prev).strip()
                # Parse the previous segment's tokens respecting quotes
                prev_tokens = []
                for m in _RE_QUOTED_ARG.finditer(prev_stripped):
                    prev_tokens.append(m.group(1) or m.group(2) or m.group(3) or '')
                if prev_tokens and os.path.basename(prev_tokens[0]) in ('echo', 'printf'):
                    # Collect all non-flag arguments and join them (they form the command)
                    inner_parts = [t for t in prev_tokens[1:] if not t.startswith('-')]
                    if inner_parts:
                        inner = ' '.join(inner_parts)
                        result.extend(_split_shell_commands(inner))

    # Post-process: detect while read VAR; do ... done loops where
    # a sensitive path flows via pipe into the loop variable.
    # Pattern: prev segment echoes/cats a sensitive path, next segment is 'while read VAR'
    final = []
    for idx, seg in enumerate(result):
        final.append(seg)
        seg_stripped = seg.strip()
        m_while = re.match(r'\bwhile\s+read\s+(\w+)', seg_stripped)
        if m_while and idx > 0:
            loop_var = m_while.group(1)
            prev_seg = result[idx - 1]
            prev_parts = prev_seg.split()
            if prev_parts:
                prev_base = os.path.basename(_strip_prefixes(prev_seg).split()[0]) if prev_seg.strip() else ''
                # If the preceding command passes a sensitive path as an arg to echo/printf/cat/etc
                for arg in prev_parts[1:]:
                    if not arg.startswith('-') and _is_sensitive_path(arg.strip("\"'")):
                        # The loop variable receives this path — look for cat/file-readers in loop body
                        # Collect segments until 'done'
                        for j in range(idx + 1, len(result)):
                            body_seg = result[j].strip()
                            if body_seg in ('done', 'fi', 'esac'):
                                break
                            # Strip leading shell keywords: do, then, else, elif
                            body_seg_stripped = re.sub(r'^(?:do|then|else|elif)\s+', '', body_seg)
                            body_parts = body_seg_stripped.split()
                            if body_parts:
                                body_base = os.path.basename(body_parts[0])
                                if body_base in _FILE_READERS | _FILE_COPIERS:
                                    for barg in body_parts[1:]:
                                        clean = barg.strip("\"'")
                                        varname = None
                                        if clean.startswith('${') and clean.endswith('}'):
                                            varname = clean[2:-1]
                                        elif clean.startswith('$'):
                                            varname = clean[1:].split('/')[0]
                                        if varname == loop_var:
                                            final.append(f"SENSITIVE_VAR_LOOP:{arg}")

    return final


def _strip_prefixes(cmd):
    """Strip cd and env-var prefixes from a command."""
    cmd = re.sub(r'^(cd\s+(?:\S+|"[^"]*"|\'[^\']*\')\s*&&\s*)+', '', cmd.strip())
    cmd = re.sub(r'^(\w+=(?:\S+|"[^"]*"|\'[^\']*\')\s+)+', '', cmd)
    return cmd


def _strip_wrappers(parts):
    """Strip command wrappers (sudo, env, time, etc.) and return remaining parts."""
    idx = 0
    while idx < len(parts):
        base = os.path.basename(parts[idx])
        if base == 'sudo':
            idx += 1
            while idx < len(parts):
                if parts[idx].startswith('-'):
                    flag = parts[idx]
                    idx += 1
                    if flag in ('-u', '-g', '-C', '-D', '-h', '-p', '-r', '-t', '-U'):
                        if idx < len(parts):
                            idx += 1
                elif '=' in parts[idx]:
                    idx += 1
                else:
                    break
        elif base in ('time', 'nice', 'nohup', 'command'):
            idx += 1
        elif base == 'busybox':
            idx += 1
        elif base == 'stdbuf':
            idx += 1
            while idx < len(parts) and parts[idx].startswith('-'):
                idx += 1
        elif base in ('ionice', 'numactl', 'taskset', 'chrt'):
            idx += 1
            while idx < len(parts) and (parts[idx].startswith('-') or parts[idx].isdigit()):
                idx += 1
        elif base == 'timeout':
            idx += 1
            while idx < len(parts) and parts[idx].startswith('-'):
                idx += 1
            if idx < len(parts):
                idx += 1
        elif base == 'env':
            idx += 1
            while idx < len(parts) and (parts[idx].startswith('-') or '=' in parts[idx]):
                idx += 1
        else:
            break
    return parts[idx:]


def _check_sensitive_paths_in_text(text):
    """Scan arbitrary text for sensitive file paths. Returns first match or None."""
    for token in re.findall(r'[/~.][\w./_-]+', text):
        if _is_sensitive_path(token):
            return token
    return None


def _check_single_command_access(command):
    """Check if a single shell command (no pipes/chains) accesses sensitive files."""
    cmd = _strip_prefixes(command)
    parts = cmd.split()
    if not parts:
        return None

    parts = _strip_wrappers(parts)
    if not parts:
        return None

    base = os.path.basename(parts[0])

    if base in _FILE_READERS:
        for arg in parts[1:]:
            if arg.startswith('-'):
                # Check --flag=value long options that embed a file path
                for prefix in _LONG_FILE_FLAGS:
                    if arg.startswith(prefix):
                        val = arg[len(prefix):]
                        if _is_sensitive_path(val):
                            return f"Command reads sensitive file via {arg[:arg.index('=')]}: {val}"
                continue
            if _is_sensitive_path(arg):
                return f"Command reads sensitive file: {arg}"

    if base in _FILE_FLAG_ARGS:
        flag_set = _FILE_FLAG_ARGS[base]
        skip_next = False
        for i, arg in enumerate(parts[1:], 1):
            if skip_next:
                if _is_sensitive_path(arg):
                    return f"Command reads sensitive file via {base}: {arg}"
                skip_next = False
                continue
            if arg in flag_set:
                skip_next = True
                continue
            # Also handle --flag=value form for these tools
            for flag in flag_set:
                if arg.startswith(flag + '='):
                    val = arg[len(flag) + 1:]
                    if _is_sensitive_path(val):
                        return f"Command reads sensitive file via {base} {flag}: {val}"

    if base in _FILE_COPIERS:
        if base == 'scp':
            args = [a for a in parts[1:] if not a.startswith('-')]
            for arg in args[:-1]:
                if ':' not in arg and _is_sensitive_path(arg):
                    return f"Command copies sensitive file via scp: {arg}"
        else:
            args = [a for a in parts[1:] if not a.startswith('-')]
            sources = args[:-1] if len(args) >= 2 else args
            for src in sources:
                if _is_sensitive_path(src):
                    return f"Command copies/moves sensitive file: {src}"

    if base in _GREP_FAMILY:
        _FIND_VALUE_FLAGS = frozenset({
            '-name', '-iname', '-path', '-ipath', '-regex', '-iregex',
            '-wholename', '-iwholename', '-lname', '-ilname',
        })
        skip_next = False
        for arg in parts[1:]:
            if skip_next:
                skip_next = False
                continue
            if arg in _FIND_VALUE_FLAGS:
                skip_next = True
                continue
            if arg.startswith('-'):
                continue
            if _is_sensitive_path(arg):
                return f"Command accesses sensitive file: {arg}"

    if base == 'dd':
        for arg in parts[1:]:
            if arg.startswith('if='):
                path = arg[3:]
                if _is_sensitive_path(path):
                    return f"Command reads sensitive file via dd: {path}"

    if base in ('curl', 'wget'):
        for i, arg in enumerate(parts[1:], 1):
            if arg.lower().startswith('file://'):
                path = arg[7:]
                if _is_sensitive_path(path):
                    return f"Command reads sensitive file via {base}: {arg}"
            if base == 'curl':
                if arg.startswith('@') and _is_sensitive_path(arg[1:]):
                    return f"Command uploads sensitive file via curl: {arg}"
                if '=@' in arg:
                    at_path = arg.split('=@', 1)[1]
                    if _is_sensitive_path(at_path):
                        return f"Command uploads sensitive file via curl: {arg}"
                if arg in ('-T', '--upload-file') and i + 1 < len(parts):
                    if _is_sensitive_path(parts[i + 1]):
                        return f"Command uploads sensitive file via curl -T: {parts[i + 1]}"
            if base == 'wget':
                for prefix in ('--post-file=', '--input-file=', '--body-file='):
                    if arg.startswith(prefix):
                        path = arg[len(prefix):]
                        if _is_sensitive_path(path):
                            return f"Command reads sensitive file via wget: {arg}"

    if base in ('tar', 'zip'):
        for arg in parts[1:]:
            if arg.startswith('-'):
                continue
            if _is_sensitive_path(arg):
                return f"Command archives sensitive file: {arg}"

    if base == 'docker' and len(parts) > 1 and parts[1] == 'run':
        for i, arg in enumerate(parts):
            if arg in ('-v', '--volume') and i + 1 < len(parts):
                mount = parts[i + 1]
                host_path = mount.split(':')[0]
                expanded = os.path.expanduser(host_path)
                if _is_sensitive_path(host_path) or _SENSITIVE_DIRS_RE.search(expanded):
                    return f"Command mounts sensitive path into container: {host_path}"

    if base == 'script':
        for i, arg in enumerate(parts[1:], 1):
            if arg in ('-c', '--command') and i + 1 <= len(parts) - 1:
                inner = _strip_quotes(' '.join(parts[i + 1:]))
                result = _check_single_command_access(inner)
                if result:
                    return f"script -c wraps blocked command: {result}"
                break

    if base == 'xargs':
        for i, arg in enumerate(parts[1:], 1):
            if arg in ('-a', '--arg-file') and i + 1 < len(parts):
                if _is_sensitive_path(parts[i + 1]):
                    return f"xargs reads sensitive file via {arg}: {parts[i + 1]}"
            if arg.startswith('--arg-file='):
                val = arg.split('=', 1)[1]
                if _is_sensitive_path(val):
                    return f"xargs reads sensitive file via --arg-file: {val}"
        remaining = [a for a in parts[1:] if not a.startswith('-')]
        if remaining:
            xargs_cmd = remaining[0]
            if os.path.basename(xargs_cmd) in _FILE_READERS | _FILE_COPIERS:
                return f"xargs invokes file-reading command: {xargs_cmd}"

    if base == 'make':
        for arg in parts[1:]:
            if arg.startswith('-') and 'f' in arg:
                continue
            if _is_sensitive_path(arg):
                return f"Command accesses sensitive file via make: {arg}"

    if base == 'eval':
        m = _RE_EVAL.search(cmd)
        if m:
            inner = m.group(1) or m.group(2)
            if inner:
                result = _check_single_command_access(inner)
                if result:
                    return f"eval wraps blocked command: {result}"

    if base in ('bash', 'sh', 'zsh', 'dash', 'ksh'):
        in_c_mode = False
        c_end_idx = 0
        for i, arg in enumerate(parts[1:], 1):
            if arg == '-c':
                in_c_mode = True
                c_end_idx = i + 1
                if c_end_idx < len(parts):
                    c_end_idx += 1
                break
        if in_c_mode:
            for arg in parts[c_end_idx:]:
                if arg == '--' or arg == '_':
                    continue
                if _is_sensitive_path(arg):
                    return f"Shell positional argument is sensitive file: {arg}"

    if base == 'ssh':
        non_flag_args = []
        skip_next = False
        for arg in parts[1:]:
            if skip_next:
                skip_next = False
                continue
            if arg.startswith('-'):
                if arg in ('-p', '-l', '-i', '-o', '-F', '-J', '-L', '-R', '-D', '-W', '-b', '-c', '-m', '-S', '-E'):
                    skip_next = True
                continue
            non_flag_args.append(arg)
        if len(non_flag_args) >= 2:
            remote_cmd_args = non_flag_args[1:]
            for arg in remote_cmd_args:
                if _is_sensitive_path(arg):
                    return f"SSH remote command accesses sensitive file: {arg}"

    for m in _RE_SHELL_EXEC.finditer(cmd):
        inner = m.group(1) or m.group(2)
        if inner:
            inner_cmds = _split_shell_commands(inner)
            # Track variable assignments within the subshell content
            _RE_INNER_VAR = re.compile(r'^(?:export\s+)?(\w+)=(\S+)')
            inner_sensitive_vars = set()
            for ic in inner_cmds:
                mv = _RE_INNER_VAR.match(ic.strip())
                if mv:
                    val = mv.group(2).strip("\"'")
                    if _is_sensitive_path(val):
                        inner_sensitive_vars.add(mv.group(1))
            for inner_cmd in inner_cmds:
                result = _check_single_command_access(inner_cmd)
                if result:
                    return f"Subshell wraps blocked command: {result}"
                # Check variable indirection within subshell
                if inner_sensitive_vars:
                    ic_stripped = _strip_prefixes(inner_cmd)
                    ic_parts = _strip_wrappers(ic_stripped.split()) if ic_stripped.split() else []
                    if ic_parts:
                        ic_base = os.path.basename(ic_parts[0])
                        if ic_base in _FILE_READERS | _FILE_COPIERS | {'eval', 'exec'}:
                            for arg in ic_parts[1:]:
                                clean = arg.strip("\"'")
                                varname = None
                                if clean.startswith('${') and clean.endswith('}'):
                                    varname = clean[2:-1]
                                elif clean.startswith('$'):
                                    varname = clean[1:].split('/')[0]
                                if varname and varname in inner_sensitive_vars:
                                    return f"Subshell accesses sensitive file via variable ${varname}"

    if base in _INTERPRETERS:
        has_inline_flag = False
        _INLINE_FLAGS = {'-c', '-e', '-r', '--eval', '--exec', '--print', '--require', '--command'}
        for i, arg in enumerate(parts[1:], 1):
            if arg in _INLINE_FLAGS and i + 1 <= len(parts) - 1:
                has_inline_flag = True
                script = ' '.join(parts[i + 1:])
                for fm in _RE_INTERP_FILE_READ.finditer(script):
                    path = (fm.group(1) or fm.group(2) or fm.group(3)
                            or fm.group(4) or fm.group(5))
                    if path and _is_sensitive_path(path):
                        return f"Interpreter reads sensitive file: {path}"
                sensitive = _check_sensitive_paths_in_text(script)
                if sensitive:
                    return f"Interpreter script references sensitive file: {sensitive}"
                break
        if not has_inline_flag:
            for arg in parts[1:]:
                if arg.startswith('-'):
                    continue
                if _is_sensitive_path(arg):
                    return f"Interpreter accesses sensitive file: {arg}"

    for m in _RE_STDIN_REDIRECT.finditer(command):
        path = m.group(1).strip("\"'")
        if path.startswith('('):
            continue
        if _is_sensitive_path(path):
            return f"Stdin redirection from sensitive file: {path}"

    return None


def _check_file_path(path):
    """Check if a Read/Edit/Write file_path targets a sensitive file."""
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

        sub_cmds = _split_shell_commands(command)
        for m in _RE_COMMAND_SUBST.finditer(command):
            sub_cmds.extend(_split_shell_commands(m.group(1)))
        for m in _RE_PROC_SUBST.finditer(command):
            sub_cmds.extend(_split_shell_commands(m.group(1)))
        for m in _RE_BACKTICK_SUBST.finditer(command):
            sub_cmds.extend(_split_shell_commands(m.group(1)))

        _HEREDOC_SHELLS = _INTERPRETERS | {'bash', 'sh', 'zsh', 'dash', 'ksh'}
        if _RE_HEREDOC.search(command):
            stripped_full = _strip_prefixes(command.split('<<')[0].strip())
            full_parts = _strip_wrappers(stripped_full.split())
            if full_parts:
                heredoc_base = os.path.basename(full_parts[0])
                if heredoc_base in _HEREDOC_SHELLS:
                    heredoc_body = command[command.index('<<'):]
                    sensitive = _check_sensitive_paths_in_text(heredoc_body)
                    if sensitive:
                        block(f"BLOCKED: Heredoc to interpreter references sensitive file: {sensitive}")

        # Variable-indirection tracking: find VAR=sensitive_path assignments,
        # then flag any command that uses $VAR or ${VAR} as an argument.
        _RE_VAR_ASSIGN = re.compile(r'^(?:export\s+)?(\w+)=(\S+)')
        sensitive_vars = set()
        for sub_cmd in sub_cmds:
            m_assign = _RE_VAR_ASSIGN.match(sub_cmd.strip())
            if m_assign:
                val = m_assign.group(2).strip("\"'")
                if _is_sensitive_path(val):
                    sensitive_vars.add(m_assign.group(1))

        for sub_cmd in sub_cmds:
            stripped = _strip_prefixes(sub_cmd)
            base_parts = _strip_wrappers(stripped.split())

            if base_parts:
                base = os.path.basename(base_parts[0])
                if base not in _GREP_FAMILY:
                    reason = _check_command_secrets(sub_cmd)
                    if reason:
                        block(f"BLOCKED: {reason}")

            reason = _check_single_command_access(sub_cmd)
            if reason:
                block(f"BLOCKED: {reason}")

            # Check for while-read-loop sentinel inserted by _split_shell_commands
            if sub_cmd.startswith('SENSITIVE_VAR_LOOP:'):
                path = sub_cmd[len('SENSITIVE_VAR_LOOP:'):]
                block(f"BLOCKED: while-read loop reads sensitive file via pipe: {path}")

            # Check for variable-indirection: cat $TFILE where TFILE holds a sensitive path
            if sensitive_vars:
                sub_parts = stripped.split()
                sub_parts = _strip_wrappers(sub_parts) if sub_parts else sub_parts
                if sub_parts:
                    sub_base = os.path.basename(sub_parts[0])
                    check_set = _FILE_READERS | _FILE_COPIERS | {'eval', 'exec'}
                    if sub_base in check_set:
                        for arg in sub_parts[1:]:
                            # Match $VAR, ${VAR}, "$VAR", "${VAR}"
                            clean = arg.strip("\"'")
                            varname = None
                            if clean.startswith('${') and clean.endswith('}'):
                                varname = clean[2:-1]
                            elif clean.startswith('$'):
                                varname = clean[1:].split('/')[0]
                            if varname and varname in sensitive_vars:
                                block(f"BLOCKED: Command accesses sensitive file via variable ${varname}")

    elif tool_name in ("Read", "Edit", "Write"):
        file_path = tool_input.get("file_path", "")
        if file_path:
            reason = _check_file_path(file_path)
            if reason:
                block(f"BLOCKED: {reason}")

        content = tool_input.get("content", "") or tool_input.get("new_string", "")
        _SCANNABLE_EXTENSIONS = frozenset({
            '.sh', '.bash', '.zsh', '.ksh', '.csh', '.fish',
            '.py', '.rb', '.pl', '.php', '.lua',
            '.js', '.ts', '.mjs', '.cjs',
            '.ps1', '.psm1', '.bat', '.cmd',
            '.env', '.envrc', '.profile', '.bashrc', '.zshrc',
        })
        should_scan_content = False
        if file_path:
            _, ext = os.path.splitext(os.path.basename(file_path))
            should_scan_content = ext.lower() in _SCANNABLE_EXTENSIONS or not ext
        if content and should_scan_content:
            _SCRIPT_COMMANDS = _FILE_READERS | _FILE_COPIERS | _INTERPRETERS | {'bash', 'sh', 'zsh', 'exec', 'eval'}
            for line in content.splitlines():
                line_stripped = line.strip()
                if not line_stripped or line_stripped.startswith('#'):
                    continue
                first_word = line_stripped.split()[0] if line_stripped.split() else ''
                first_word = os.path.basename(first_word)
                if first_word in _SCRIPT_COMMANDS:
                    reason = _check_single_command_access(line_stripped)
                    if reason:
                        block(f"BLOCKED: Written content contains: {reason}")

    sys.exit(0)


if __name__ == "__main__":
    main()
