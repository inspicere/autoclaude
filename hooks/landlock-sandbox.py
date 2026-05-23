#!/usr/bin/env python3
"""Landlock filesystem sandbox for Claude Code Bash commands.

Proof-of-concept wrapper that restricts file access at the kernel level
using Linux Landlock LSM (ABI v6+). This prevents all runtime indirection
attacks (shell function indirection, array expansion, runtime path
construction, write-then-execute, symlink TOCTOU) because the kernel
denies open() regardless of how the path was derived.

Usage as a shell wrapper:
  SHELL=/path/to/landlock-sandbox.py claude
  # Claude Code calls: $SHELL -c "command"
  # This script applies Landlock restrictions, then exec's bash -c "command"

Usage standalone (testing):
  python3 landlock-sandbox.py -c "ls /tmp"           # allowed
  python3 landlock-sandbox.py -c "cat /tmp/safe.txt"  # allowed

Requirements:
  - Linux kernel 5.13+ with Landlock enabled
  - No privileges needed (unprivileged Landlock)
"""

import ctypes
import ctypes.util
import os
import re
import sys

# --- Landlock constants (from linux/landlock.h) ---

LANDLOCK_CREATE_RULESET_VERSION = 1 << 0

LANDLOCK_ACCESS_FS_READ_FILE  = 1 << 2
LANDLOCK_ACCESS_FS_READ_DIR   = 1 << 3

LANDLOCK_RULE_PATH_BENEATH = 1

# Syscall numbers (x86_64)
NR_landlock_create_ruleset = 444
NR_landlock_add_rule = 445
NR_landlock_restrict_self = 446


# Sensitive path patterns — shared with block-secrets.py
_SENSITIVE_PATH_RE = re.compile(
    r'(?:'
    r'(?:^|/)\.env(?:\.\w+)?$'
    r'|(?:^|/)\.envrc$'
    r'|(?:^|/)\.dev\.vars(?:\.\w+)?$'
    r'|(?:^|/)\.?\w[\w.\-]*\.(?:pem|key|p12|pfx)$'
    r'|(?:^|/)\.aws/'
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

_SENSITIVE_DIRS = ['.ssh', '.aws', '.gnupg', '.kube']


def _is_sensitive(path):
    """Check if a resolved path matches sensitive patterns."""
    return bool(_SENSITIVE_PATH_RE.search(path))


class LandlockError(Exception):
    pass


class LandlockRulesetAttr(ctypes.Structure):
    _fields_ = [
        ("handled_access_fs", ctypes.c_uint64),
        ("handled_access_net", ctypes.c_uint64),
    ]


class LandlockPathBeneathAttr(ctypes.Structure):
    _fields_ = [
        ("allowed_access", ctypes.c_uint64),
        ("parent_fd", ctypes.c_int32),
    ]


def _libc():
    path = ctypes.util.find_library("c")
    if not path:
        raise LandlockError("cannot find libc")
    return ctypes.CDLL(path, use_errno=True)


def _check_abi(libc):
    ret = libc.syscall(NR_landlock_create_ruleset, 0, 0, LANDLOCK_CREATE_RULESET_VERSION)
    if ret < 0:
        errno = ctypes.get_errno()
        if errno == 38:
            raise LandlockError("Landlock not supported by kernel")
        raise LandlockError(f"Landlock version query failed: errno {errno}")
    return ret


def _collect_deny_paths(home):
    """Build list of paths to deny based on sensitive pattern matching."""
    deny_files = set()
    deny_dirs = set()

    # Well-known sensitive directories
    for d in _SENSITIVE_DIRS:
        full = os.path.join(home, d)
        if os.path.isdir(full):
            deny_dirs.add(os.path.realpath(full))

    # Walk home looking for sensitive files (shallow, max 1 level)
    try:
        for entry in os.listdir(home):
            full = os.path.join(home, entry)
            if os.path.isfile(full) and _is_sensitive(full):
                deny_files.add(os.path.realpath(full))
    except OSError:
        pass

    # Engagement target directory
    target = os.path.join(home, "autoclaude_engagement_target")
    if os.path.isdir(target):
        deny_dirs.add(os.path.realpath(target))

    return deny_files, deny_dirs


def apply_sandbox(deny_files, deny_dirs):
    """Apply Landlock restrictions denying read access to specified paths.

    Uses allowlist approach: handle READ_FILE in ruleset (all reads denied
    by default), then grant READ_FILE to every path NOT in the deny sets.
    """
    libc = _libc()
    abi = _check_abi(libc)

    # All ancestor directories of denied items need recursive handling
    denied_parents = set()
    for p in list(deny_files) + list(deny_dirs):
        parent = os.path.dirname(p)
        while parent and parent != '/':
            denied_parents.add(parent)
            parent = os.path.dirname(parent)

    attr = LandlockRulesetAttr()
    attr.handled_access_fs = LANDLOCK_ACCESS_FS_READ_FILE
    attr.handled_access_net = 0

    ruleset_fd = libc.syscall(
        NR_landlock_create_ruleset,
        ctypes.byref(attr),
        ctypes.sizeof(attr),
        0,
    )
    if ruleset_fd < 0:
        raise LandlockError(f"create_ruleset failed: errno {ctypes.get_errno()}")

    def grant_read(path):
        try:
            flags = os.O_PATH
            if os.path.isdir(path):
                flags |= os.O_DIRECTORY
            fd = os.open(path, flags)
        except OSError:
            return
        try:
            rule = LandlockPathBeneathAttr()
            rule.allowed_access = LANDLOCK_ACCESS_FS_READ_FILE
            rule.parent_fd = fd
            libc.syscall(
                NR_landlock_add_rule,
                ruleset_fd,
                LANDLOCK_RULE_PATH_BENEATH,
                ctypes.byref(rule),
                0,
            )
        finally:
            os.close(fd)

    def grant_subtree(dirpath):
        try:
            entries = os.listdir(dirpath)
        except OSError:
            return
        for entry in entries:
            full = os.path.join(dirpath, entry)
            real = os.path.realpath(full)
            if real in deny_files:
                continue
            if real in deny_dirs:
                continue
            if os.path.isdir(full) and real in denied_parents:
                grant_subtree(full)
            else:
                grant_read(full)

    # Grant read access to all top-level dirs except those containing secrets
    try:
        for entry in os.listdir("/"):
            full = "/" + entry
            real = os.path.realpath(full)
            if real in deny_dirs or real in deny_files:
                continue
            if real in denied_parents:
                grant_subtree(full)
            else:
                grant_read(full)
    except OSError:
        pass

    # Set no_new_privs (required by Landlock)
    PR_SET_NO_NEW_PRIVS = 38
    libc.prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0)

    ret = libc.syscall(NR_landlock_restrict_self, ruleset_fd, 0)
    os.close(ruleset_fd)
    if ret < 0:
        raise LandlockError(f"restrict_self failed: errno {ctypes.get_errno()}")


def main():
    # Parse -c flag (bash-compatible interface)
    if "-c" not in sys.argv:
        print("Usage: landlock-sandbox.py -c 'command'", file=sys.stderr)
        sys.exit(1)

    c_idx = sys.argv.index("-c")
    if c_idx + 1 >= len(sys.argv):
        print("Missing command after -c", file=sys.stderr)
        sys.exit(1)

    command = sys.argv[c_idx + 1]
    home = os.path.expanduser("~")

    deny_files, deny_dirs = _collect_deny_paths(home)

    if deny_files or deny_dirs:
        try:
            apply_sandbox(deny_files, deny_dirs)
        except LandlockError as e:
            print(f"[landlock] WARNING: {e} — running unsandboxed", file=sys.stderr)

    os.execvp("bash", ["bash", "-c", command])


if __name__ == "__main__":
    main()
