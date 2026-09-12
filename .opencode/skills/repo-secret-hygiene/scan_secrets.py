#!/usr/bin/env python3
"""Scan a repository tree, staging area, or history for leaked secrets.

Hard findings are credentials and keys and always fail the scan. Soft
findings are identifying data (private IPs, MACs, user paths, emails) and
fail only under ``--strict``. Placeholders and documented allowlist values
are ignored so examples do not trip the guard.
"""

import argparse
import os
import re
import subprocess
import sys

PLACEHOLDERS = (
    "<secret>", "<token>", "changeme", "change-me", "change_me", "example",
    "redacted", "placeholder", "your_", "your-", "dummy", "fake", "sample",
    "todo", "xxxx", "aaaa", "deadbeef", "0000000000", "abc123",
)

ALLOWED_IPS = {
    "192.168.1.1", "192.168.1.50", "10.0.0.1", "10.0.0.3", "10.0.0.5",
    "127.0.0.1", "0.0.0.0", "255.255.255.255",
}

ALLOWED_MACS = {
    "00:11:22:33:44:55", "aa:bb:cc:dd:ee:ff", "ff:ff:ff:ff:ff:ff",
    "00:00:00:00:00:00",
}

ALLOWED_EMAIL_DOMAINS = ("example.com", "example.org", "example.net", "test.com")

SKIP_DIRS = {
    ".git", ".venv", "venv", "__pycache__", "node_modules", ".pytest_cache",
    "build", "dist", "reports",
}

SKIP_EXT = {
    ".png", ".jpg", ".jpeg", ".gif", ".pdf", ".zip", ".gz", ".xz", ".bz2",
    ".bin", ".img", ".pcap", ".so", ".dylib", ".o", ".a", ".pyc", ".woff",
}

HARD = (
    ("private-key", r"-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP )?PRIVATE KEY-----"),
    ("aws-access-key", r"\bAKIA[0-9A-Z]{16}\b"),
    ("github-token", r"\b(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{36}\b"),
    ("slack-token", r"\bxox[baprs]-[A-Za-z0-9-]{10,}\b"),
    ("google-api-key", r"\bAIza[0-9A-Za-z_\-]{35}\b"),
    ("jwt", r"\beyJ[A-Za-z0-9_\-]{8,}\.[A-Za-z0-9_\-]{8,}\.[A-Za-z0-9_\-]{8,}\b"),
    ("bearer-token", r"(?i)authorization\s*:\s*bearer\s+\S{16,}"),
    (
        "generic-secret",
        r"(?i)\b(?:api[_-]?key|secret|token|passwd|password|passphrase)\b"
        r"\s*[:=]\s*['\"]([^'\"]{12,})['\"]",
    ),
)

SOFT = (
    (
        "private-ipv4",
        r"\b(?:10|192\.168|172\.(?:1[6-9]|2\d|3[01]))\.\d{1,3}\.\d{1,3}\b",
    ),
    ("mac-address", r"\b(?:[0-9a-fA-F]{2}:){5}[0-9a-fA-F]{2}\b"),
    ("user-path", r"/Users/[A-Za-z0-9._-]+/"),
    ("email", r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b"),
)

_HARD_RE = [(name, re.compile(pat)) for name, pat in HARD]
_SOFT_RE = [(name, re.compile(pat)) for name, pat in SOFT]


def _placeholder(text: str) -> bool:
    """
    Report whether a line is an obvious placeholder example.

    Parameters
    ----------
    text : str
        Line of text.

    Returns
    -------
    bool
        True when the line should be ignored.
    """
    low = text.lower()
    return any(token in low for token in PLACEHOLDERS)


def _allowed_hit(name: str, value: str) -> bool:
    """
    Report whether a matched value is a documented allowlist entry.

    Parameters
    ----------
    name : str
        Pattern name.
    value : str
        Matched text.

    Returns
    -------
    bool
        True when the value is permitted.
    """
    if name == "private-ipv4":
        return value in ALLOWED_IPS
    if name == "mac-address":
        return value.lower() in ALLOWED_MACS
    if name == "email":
        return value.split("@")[-1].lower() in ALLOWED_EMAIL_DOMAINS
    return False


def _redact(value: str) -> str:
    """
    Redact a matched secret to a short prefix.

    Parameters
    ----------
    value : str
        Matched text.

    Returns
    -------
    str
        Redacted text.
    """
    return value[:8] + "..." if len(value) > 8 else value


def _emit(severity: str, label: str, name: str, value: str) -> None:
    """
    Print one finding in a stable, redacted format.

    Parameters
    ----------
    severity : str
        HARD or SOFT.
    label : str
        Source location label.
    name : str
        Pattern name.
    value : str
        Matched text.

    Returns
    -------
    None
    """
    print("[{}] {}: {}: {}".format(severity, label, name, _redact(value)))


def scan_text(text: str, label: str, strict: bool = False) -> tuple:
    """
    Scan a text blob for hard and soft findings.

    Parameters
    ----------
    text : str
        Text to scan.
    label : str
        Source location label.
    strict : bool
        When True, report soft findings too.

    Returns
    -------
    tuple
        (hard_count, soft_count).
    """
    hard = soft = 0
    for number, line in enumerate(text.splitlines(), 1):
        if _placeholder(line):
            continue
        where = "{}:{}".format(label, number)
        hard += _scan_line(_HARD_RE, line, where, "HARD")
        soft += _scan_soft(_SOFT_RE, line, where, strict)
    return hard, soft


def _scan_line(patterns, line: str, where: str, severity: str) -> int:
    """
    Apply hard patterns to one line, honoring the allowlist.

    Parameters
    ----------
    patterns : list
        Compiled (name, regex) pairs.
    line : str
        Line of text.
    where : str
        Source label.
    severity : str
        Severity tag.

    Returns
    -------
    int
        Number of findings.
    """
    count = 0
    for name, regex in patterns:
        match = regex.search(line)
        if match and not _allowed_hit(name, match.group(0)):
            _emit(severity, where, name, match.group(0))
            count += 1
    return count


def _scan_soft(patterns, line: str, where: str, strict: bool) -> int:
    """
    Apply soft patterns to one line.

    Parameters
    ----------
    patterns : list
        Compiled (name, regex) pairs.
    line : str
        Line of text.
    where : str
        Source label.
    strict : bool
        When False, soft findings are suppressed.

    Returns
    -------
    int
        Number of findings.
    """
    if not strict:
        return 0
    count = 0
    for name, regex in patterns:
        match = regex.search(line)
        if match and not _allowed_hit(name, match.group(0)):
            _emit("SOFT", where, name, match.group(0))
            count += 1
    return count


def _ignored(root: str) -> set:
    """
    Return absolute paths that Git ignores, so the scan skips them.

    Parameters
    ----------
    root : str
        Repository root.

    Returns
    -------
    set
        Absolute ignored paths.
    """
    listing = _git(["ls-files", "-o", "-i", "--exclude-standard"], root)
    return {
        os.path.abspath(os.path.join(root, line))
        for line in listing.splitlines() if line
    }


def _iter_tree(root: str, ignored: set):
    """
    Yield text files under a root, skipping binary and ignored directories.

    Parameters
    ----------
    root : str
        Directory root.
    ignored : set
        Absolute paths Git ignores.

    Yields
    ------
    str
        File paths.
    """
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [
            d for d in dirnames
            if d not in SKIP_DIRS
            and os.path.abspath(os.path.join(dirpath, d)) not in ignored
        ]
        for name in filenames:
            path = os.path.join(dirpath, name)
            if os.path.abspath(path) in ignored:
                continue
            if os.path.splitext(name)[1].lower() in SKIP_EXT:
                continue
            yield path


def _read(path: str):
    """
    Read a file as text, returning None on binary or read errors.

    Parameters
    ----------
    path : str
        File path.

    Returns
    -------
    str or None
        Decoded text, or None.
    """
    try:
        with open(path, "r", encoding="utf-8", errors="strict") as handle:
            return handle.read()
    except (OSError, UnicodeDecodeError):
        return None


def _git(args: list, root: str) -> str:
    """
    Run a git command and return stdout (empty on failure).

    Parameters
    ----------
    args : list
        Git arguments.
    root : str
        Repository root.

    Returns
    -------
    str
        Standard output.
    """
    try:
        result = subprocess.run(
            ["git"] + args,
            cwd=root,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=60,
        )
        return result.stdout
    except (OSError, subprocess.SubprocessError):
        return ""


def scan_tree(root: str, strict: bool) -> tuple:
    """
    Scan every text file in a working tree.

    Parameters
    ----------
    root : str
        Directory root.
    strict : bool
        Report soft findings.

    Returns
    -------
    tuple
        (hard_count, soft_count).
    """
    hard = soft = 0
    ignored = _ignored(root)
    for path in _iter_tree(root, ignored):
        rel = os.path.relpath(path, root)
        text = _read(path)
        if text is None:
            continue
        h, s = scan_text(text, rel, strict)
        hard += h
        soft += s
    return hard, soft


def scan_staged(root: str, strict: bool) -> tuple:
    """
    Scan the staged snapshot of each changed file.

    Parameters
    ----------
    root : str
        Repository root.
    strict : bool
        Report soft findings.

    Returns
    -------
    tuple
        (hard_count, soft_count).
    """
    names = _git(["diff", "--cached", "--name-only", "--diff-filter=ACM"], root)
    hard = soft = 0
    for name in names.splitlines():
        text = _git(["show", ":" + name], root)
        h, s = scan_text(text, name, strict)
        hard += h
        soft += s
    return hard, soft


def scan_history(root: str, strict: bool) -> tuple:
    """
    Scan added lines across all reachable commits for secrets.

    Parameters
    ----------
    root : str
        Repository root.
    strict : bool
        Report soft findings.

    Returns
    -------
    tuple
        (hard_count, soft_count).
    """
    diff = _git(["log", "-p", "-U0", "--all", "--no-color"], root)
    added = "\n".join(
        line[1:] for line in diff.splitlines()
        if line.startswith("+") and not line.startswith("+++")
    )
    return scan_text(added, "<history>", strict)


def _build_parser() -> argparse.ArgumentParser:
    """
    Build the command-line parser.

    Parameters
    ----------
    None

    Returns
    -------
    argparse.ArgumentParser
        Configured parser.
    """
    parser = argparse.ArgumentParser(description="Scan a repo for secrets")
    parser.add_argument("--root", default=".", help="Repository root")
    parser.add_argument("--tree", action="store_true", help="Scan working tree")
    parser.add_argument("--staged", action="store_true", help="Scan staged files")
    parser.add_argument("--history", action="store_true", help="Scan commit history")
    parser.add_argument("--strict", action="store_true", help="Fail on soft findings")
    return parser


def main() -> int:
    """
    Run the requested scan modes and return an exit code.

    Parameters
    ----------
    None

    Returns
    -------
    int
        Zero when clean, 1 for hard findings, 2 for strict soft findings.
    """
    args = _build_parser().parse_args()
    if not (args.tree or args.staged or args.history):
        args.tree = True
    hard = soft = 0
    for enabled, scanner in (
        (args.tree, scan_tree),
        (args.staged, scan_staged),
        (args.history, scan_history),
    ):
        if enabled:
            h, s = scanner(args.root, args.strict)
            hard, soft = hard + h, soft + s
    if hard:
        print("FAIL: {} hard finding(s)".format(hard))
        return 1
    if args.strict and soft:
        print("FAIL: {} soft finding(s) under --strict".format(soft))
        return 2
    print("OK: no hard findings ({} soft)".format(soft))
    return 0


if __name__ == "__main__":
    sys.exit(main())
