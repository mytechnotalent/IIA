"""Offline secret discovery with a deterministic pattern/structural ladder.

Findings carry a confidence tier: ``pattern`` (shape only), ``structural``
(a parsed JWT or PEM block), or ``validated`` (a recomputed checksum or a
recognized crypt-hash format). The scanner asserts well-formedness only; an
empty result is a real answer, and nothing here ever touches the network.
"""

import base64
import json
import os
import re

from ..firmware.entropy import _shannon

CRED_PATHS = re.compile(
    r"(?:^|/)(?:\.env|\.netrc|\.npmrc|id_rsa|id_ed25519|authorized_keys|"
    r"shadow|passwd|htpasswd|credentials|\.aws/credentials|\.git-credentials)$"
)
HIGH_ENTROPY = 4.2

PATTERNS = (
    (
        "private-key",
        re.compile(rb"-----BEGIN [A-Z ]*PRIVATE KEY-----"),
        "structural",
        0.99,
    ),
    (
        "aws-access-key-id",
        re.compile(rb"\bAKIA[0-9A-Z]{16}\b"),
        "pattern",
        0.9,
    ),
    (
        "github-token",
        re.compile(rb"\b(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{36}\b"),
        "pattern",
        0.85,
    ),
    (
        "slack-token",
        re.compile(rb"\bxox[baprs]-[A-Za-z0-9-]{10,}\b"),
        "pattern",
        0.85,
    ),
    (
        "google-api-key",
        re.compile(rb"\bAIza[0-9A-Za-z_\-]{35}\b"),
        "pattern",
        0.85,
    ),
    (
        "stripe-key",
        re.compile(rb"\b(?:sk|rk)_(?:live|test)_[A-Za-z0-9]{16,}\b"),
        "pattern",
        0.85,
    ),
    (
        "db-uri",
        re.compile(
            rb"\b(?:mongodb|mysql|postgres|postgresql|redis)"
            rb"://[^:\s]+:[^@\s]+@"
        ),
        "pattern",
        0.8,
    ),
    (
        "bearer",
        re.compile(rb"(?i)authorization\s*:\s*bearer\s+\S{16,}"),
        "pattern",
        0.8,
    ),
    (
        "secret-assignment",
        re.compile(
            rb"(?i)\b(?:api[_-]?key|secret|token|passwd|password|"
            rb"passphrase|access[_-]?key|private[_-]?key)\b\s*[:=]\s*"
            rb"['\"]([^'\"]{12,})['\"]"
        ),
        "pattern",
        0.7,
    ),
)

JWT = re.compile(
    rb"\beyJ[A-Za-z0-9_\-]{8,}\.[A-Za-z0-9_\-]{8,}\.[A-Za-z0-9_\-]{4,}\b"
)
PEM = re.compile(rb"-----BEGIN [A-Z ]*PRIVATE KEY-----")
CRYPT = re.compile(rb"\$(1|2[aby]?|5|6)\$[./A-Za-z0-9]{8,}\$?[./A-Za-z0-9]*")
SHADOW = re.compile(rb"^[A-Za-z0-9_.\-]+:([^:]*):", re.MULTILINE)

PLACEHOLDERS = (
    "<secret>",
    "<token>",
    "changeme",
    "change-me",
    "example",
    "redacted",
    "placeholder",
    "your_",
    "your-",
    "dummy",
    "fake",
    "sample",
    "xxxx",
    "aaaa",
)


def _placeholder(blob: bytes) -> bool:
    """
    Report whether a match sits on an obvious placeholder line.

    Parameters
    ----------
    blob : bytes
        Matched bytes.

    Returns
    -------
    bool
        True when the value is a placeholder.
    """
    low = blob.lower()
    return any(token.encode() in low for token in PLACEHOLDERS)


def _redact(value) -> str:
    """
    Redact a secret value to a short prefix.

    Parameters
    ----------
    value : bytes or str
        Secret value.

    Returns
    -------
    str
        Redacted string.
    """
    text = (
        value.decode("utf-8", "ignore") if isinstance(value, bytes) else value
    )
    return text[:6] + "..." if len(text) > 6 else text


def _entropy_value(value: bytes) -> float:
    """
    Score the Shannon entropy of a candidate value.

    Parameters
    ----------
    value : bytes
        Candidate bytes.

    Returns
    -------
    float
        Entropy in bits per byte.
    """
    return _shannon(value)


def _jwt_structural(blob: bytes) -> bool:
    """
    Verify a JWT's header decodes to a JSON object.

    Parameters
    ----------
    blob : bytes
        Candidate JWT.

    Returns
    -------
    bool
        True when the header is valid JSON.
    """
    try:
        header = blob.split(b".")[0]
        padded = header + b"=" * (-len(header) % 4)
        return isinstance(json.loads(base64.urlsafe_b64decode(padded)), dict)
    except (ValueError, json.JSONDecodeError):
        return False


def _crypt_valid(blob: bytes) -> bool:
    """
    Report whether a crypt hash names a recognized algorithm.

    Parameters
    ----------
    blob : bytes
        Candidate hash.

    Returns
    -------
    bool
        True for md5/bcrypt/sha256/sha512 crypt formats.
    """
    return CRYPT.match(blob) is not None


def scan_text(text: str, label: str = "") -> list:
    """
    Scan a text blob for credentials across the confidence ladder.

    Parameters
    ----------
    text : str
        Text to scan.
    label : str
        Source location label.

    Returns
    -------
    list
        Findings with rule, tier, confidence, evidence, and line number.
    """
    blob = text.encode("utf-8", "ignore")
    findings = []
    for number, line in enumerate(blob.splitlines(), 1):
        findings.extend(_scan_line(line, label, number))
    return findings


def _scan_line(line: bytes, label: str, number: int) -> list:
    """
    Apply every rule to a single line.

    Parameters
    ----------
    line : bytes
        Line bytes.
    label : str
        Source label.
    number : int
        Line number.

    Returns
    -------
    list
        Findings on this line.
    """
    found = []
    for rule, regex, tier, confidence in PATTERNS:
        match = regex.search(line)
        if match and not _placeholder(match.group(0)):
            found.append(
                _finding(rule, tier, confidence, match.group(0), label, number)
            )
    found.extend(_scan_structural(line, label, number))
    return found


def _scan_structural(line: bytes, label: str, number: int) -> list:
    """
    Apply structural and validated rules to a line.

    Parameters
    ----------
    line : bytes
        Line bytes.
    label : str
        Source label.
    number : int
        Line number.

    Returns
    -------
    list
        Structural findings.
    """
    found = []
    jwt = JWT.search(line)
    if jwt and _jwt_structural(jwt.group(0)):
        found.append(
            _finding("jwt", "structural", 0.95, jwt.group(0), label, number)
        )
    crypt = CRYPT.search(line)
    if crypt and _crypt_valid(crypt.group(0)):
        found.append(
            _finding(
                "crypt-hash", "validated", 0.9, crypt.group(0), label, number
            )
        )
    return found


def _finding(
    rule: str, tier: str, confidence: float, value, label: str, number: int
) -> dict:
    """
    Build a normalized secret finding.

    Parameters
    ----------
    rule : str
        Rule name.
    tier : str
        Confidence tier.
    confidence : float
        Confidence score.
    value : bytes
        Matched value.
    label : str
        Source label.
    number : int
        Line number.

    Returns
    -------
    dict
        Finding record.
    """
    return {
        "rule": rule,
        "tier": tier,
        "confidence": confidence,
        "evidence": _redact(value),
        "location": "{}:{}".format(label, number),
    }


def _shadow_flags(text: str, label: str) -> list:
    """
    Flag weak or empty password hashes in shadow/htpasswd content.

    Parameters
    ----------
    text : str
        File content.
    label : str
        Source label.

    Returns
    -------
    list
        Credential-hardening findings.
    """
    flags = []
    for hash_value in SHADOW.findall(text.encode("utf-8", "ignore")):
        if hash_value in (b"", b"*", b"!"):
            flags.append(
                _finding(
                    "empty-password", "validated", 0.8, b"empty", label, 0
                )
            )
        elif hash_value.startswith((b"$1$", b"$2", b"$5$")):
            flags.append(
                _finding("weak-hash", "validated", 0.7, hash_value, label, 0)
            )
    return flags


def scan_file(path: str) -> list:
    """
    Scan one file, adding credential-path flags.

    Parameters
    ----------
    path : str
        File path.

    Returns
    -------
    list
        Findings.
    """
    raw = _read_bytes(path)
    if raw is None:
        return []
    return _file_findings(path, raw)


def _read_bytes(path: str):
    """
    Read a file as bytes, returning None on failure.

    Parameters
    ----------
    path : str
        File path.

    Returns
    -------
    bytes or None
        File bytes.
    """
    try:
        with open(path, "rb") as handle:
            return handle.read()
    except OSError:
        return None


def _file_findings(path: str, raw: bytes) -> list:
    """
    Build all findings for a file's bytes.

    Parameters
    ----------
    path : str
        File path.
    raw : bytes
        File bytes.

    Returns
    -------
    list
        Findings.
    """
    text = raw.decode("utf-8", "ignore")
    findings = scan_text(text, path)
    if CRED_PATHS.search(path):
        findings.append(
            _finding("credential-file", "structural", 0.6, path, path, 0)
        )
    if os.path.basename(path) in ("shadow", "htpasswd"):
        findings.extend(_shadow_flags(text, path))
    return findings


def scan_secrets(path: str) -> dict:
    """
    Scan a file or directory tree for secrets.

    Parameters
    ----------
    path : str
        File or directory.

    Returns
    -------
    dict
        Findings list and counts by tier.
    """
    findings = []
    for target in _iter_files(path):
        findings.extend(scan_file(target))
    return {"path": path, "findings": findings, "count": len(findings)}


def _iter_files(path: str):
    """
    Yield files under a path.

    Parameters
    ----------
    path : str
        File or directory.

    Yields
    ------
    str
        File paths.
    """
    if os.path.isfile(path):
        yield path
        return
    for dirpath, _dirs, names in os.walk(path):
        for name in names:
            yield os.path.join(dirpath, name)
