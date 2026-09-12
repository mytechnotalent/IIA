"""Offline component-to-CVE join against a local advisory mirror.

The mirror is a plain JSON file (no network at scan time). Every match
records how it was made (exact version, affected range, or CPE) and carries
optional CISA KEV and EPSS annotations so a finding's certainty is explicit.
"""

import json
import re

_SEG = re.compile(r"(\d+)")


def _vkey(version: str):
    """
    Convert a version string into a comparable tuple.

    Parameters
    ----------
    version : str
        Version string.

    Returns
    -------
    tuple
        Comparable key honoring numeric and alphabetic segments.
    """
    key = []
    for part in re.split(r"([0-9]+)", version):
        if not part:
            continue
        key.append((0, int(part)) if part.isdigit() else (1, part.lower()))
    return tuple(key)


def _compare(left: str, right: str) -> int:
    """
    Compare two version strings.

    Parameters
    ----------
    left : str
        Left version.
    right : str
        Right version.

    Returns
    -------
    int
        -1, 0, or 1.
    """
    a, b = _vkey(left), _vkey(right)
    return (a > b) - (a < b)


def _in_range(version: str, spec: str) -> bool:
    """
    Test a version against a comma-separated range expression.

    Parameters
    ----------
    version : str
        Component version.
    spec : str
        Expression such as ``>=1.0.0,<1.1.1k``.

    Returns
    -------
    bool
        True when the version satisfies every clause.
    """
    for clause in spec.split(","):
        clause = clause.strip()
        if not clause:
            continue
        if not _clause(version, clause):
            return False
    return True


def _clause(version: str, clause: str) -> bool:
    """
    Evaluate a single comparison clause.

    Parameters
    ----------
    version : str
        Component version.
    clause : str
        Clause such as ``>=1.1.1``.

    Returns
    -------
    bool
        True when satisfied.
    """
    for op in (">=", "<=", "==", ">", "<"):
        if clause.startswith(op):
            target = clause[len(op):].strip()
            result = _compare(version, target)
            return {
                ">=": result >= 0,
                "<=": result <= 0,
                "==": result == 0,
                ">": result > 0,
                "<": result < 0,
            }[op]
    return _compare(version, clause) == 0


def load_mirror(path: str) -> dict:
    """
    Load an advisory mirror from disk.

    Parameters
    ----------
    path : str
        JSON file with an ``advisories`` list.

    Returns
    -------
    dict
        Parsed mirror (empty on failure).
    """
    try:
        with open(path, "r", encoding="utf-8") as handle:
            data = json.load(handle)
    except (OSError, ValueError):
        return {"advisories": []}
    return {"advisories": data.get("advisories", [])}


def _match(component: dict, advisory: dict):
    """
    Decide whether an advisory matches a component and how.

    Parameters
    ----------
    component : dict
        Component with name and version.
    advisory : dict
        Advisory with component, affected, and fixed.

    Returns
    -------
    str or None
        Match method label, or None.
    """
    if advisory.get("component", "").lower() != component["name"].lower():
        return None
    version = component.get("version", "")
    if not version:
        return "cpe"
    return _match_version(version, advisory)


def _match_version(version: str, advisory: dict):
    """
    Determine how a version matches an advisory's range or fixed version.

    Parameters
    ----------
    version : str
        Component version.
    advisory : dict
        Advisory with affected/fixed/version fields.

    Returns
    -------
    str or None
        Match method label, or None.
    """
    if advisory.get("affected") and _in_range(version, advisory["affected"]):
        return "affected-range"
    fixed = advisory.get("fixed")
    if fixed and _compare(version, fixed) < 0:
        return "fixed-version"
    if advisory.get("version") and _compare(version, advisory["version"]) == 0:
        return "exact-version"
    return None


def join_cves(components: list, mirror: dict) -> dict:
    """
    Join components against every advisory in the mirror.

    Parameters
    ----------
    components : list
        SBOM components (name, version).
    mirror : dict
        Loaded advisory mirror.

    Returns
    -------
    dict
        Findings plus a severity/KEV summary.
    """
    findings = []
    for component in components:
        for advisory in mirror.get("advisories", []):
            method = _match(component, advisory)
            if method:
                findings.append(_finding(component, advisory, method))
    findings.sort(key=lambda f: (f["cvss"] or 0), reverse=True)
    return {"findings": findings, "summary": _summary(findings)}


def _finding(component: dict, advisory: dict, method: str) -> dict:
    """
    Build a normalized CVE finding.

    Parameters
    ----------
    component : dict
        Matched component.
    advisory : dict
        Matched advisory.
    method : str
        Match method.

    Returns
    -------
    dict
        Finding record.
    """
    return {
        "component": component["name"],
        "version": component.get("version", ""),
        "cve": advisory.get("cve", ""),
        "cvss": advisory.get("cvss"),
        "severity": advisory.get("severity", ""),
        "kev": bool(advisory.get("kev")),
        "epss": advisory.get("epss"),
        "matched_by": method,
        "summary": advisory.get("summary", ""),
    }


def _summary(findings: list) -> dict:
    """
    Summarize findings by severity and KEV status.

    Parameters
    ----------
    findings : list
        CVE findings.

    Returns
    -------
    dict
        Counts and the highest CVSS score.
    """
    by_severity = {}
    for item in findings:
        label = (item["severity"] or "unknown").lower()
        by_severity[label] = by_severity.get(label, 0) + 1
    return {
        "total": len(findings),
        "kev": sum(1 for f in findings if f["kev"]),
        "by_severity": by_severity,
        "top_cvss": max(
            (f["cvss"] for f in findings if f["cvss"]), default=None
        ),
    }
