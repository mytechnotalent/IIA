"""SPDX license identification from tags, file text, and license filenames."""

import os
import re

SPDX_TAG = re.compile(r"SPDX-License-Identifier:\s*([A-Za-z0-9.\-+ ]+)")

LICENSE_FILES = re.compile(
    r"(?:^|/)(LICENSE|LICENCE|COPYING|COPYRIGHT|NOTICE|UNLICENSE)"
    r"(?:[.\-_].*)?$"
)

HEURISTICS = (
    ("Apache-2.0", ("apache license", "version 2.0, january 2004")),
    ("MIT", ("permission is hereby granted, free of charge",)),
    (
        "BSD-3-Clause",
        (
            "redistribution and use in source and binary forms",
            "neither the name",
        ),
    ),
    ("BSD-2-Clause", ("redistribution and use in source and binary forms",)),
    ("GPL-3.0-only", ("gnu general public license", "version 3")),
    ("GPL-2.0-only", ("gnu general public license", "version 2")),
    ("LGPL-3.0-only", ("gnu lesser general public license", "version 3")),
    ("LGPL-2.1-only", ("gnu lesser general public license", "version 2.1")),
    ("MPL-2.0", ("mozilla public license version 2.0",)),
    ("ISC", ("permission to use, copy, modify, and/or distribute",)),
    ("Unlicense", ("this is free and unencumbered software",)),
    ("CC0-1.0", ("creative commons", "cc0 1.0")),
)


def _ids_from_text(low: str) -> set:
    """
    Infer SPDX ids from license text using ordered heuristics.

    Parameters
    ----------
    low : str
        Lowercased file content.

    Returns
    -------
    set
        Matched SPDX ids.
    """
    ids = set()
    for spdx, phrases in HEURISTICS:
        if all(phrase in low for phrase in phrases):
            ids.add(spdx)
    if "BSD-3-Clause" in ids and "BSD-2-Clause" in ids:
        ids.discard("BSD-2-Clause")
    return ids


def _scan_file(path: str) -> list:
    """
    Extract license findings from one file.

    Parameters
    ----------
    path : str
        File path.

    Returns
    -------
    list
        Findings with id and source.
    """
    text = _read_text(path)
    if text is None:
        return []
    found = _tag_findings(text, path)
    if LICENSE_FILES.search(path):
        found += _text_findings(text, path)
    return found


def _read_text(path: str):
    """
    Read a text file, returning None on failure.

    Parameters
    ----------
    path : str
        File path.

    Returns
    -------
    str or None
        File text.
    """
    try:
        with open(path, "r", encoding="utf-8", errors="ignore") as handle:
            return handle.read()
    except OSError:
        return None


def _tag_findings(text: str, path: str) -> list:
    """
    Build findings from SPDX-License-Identifier tags.

    Parameters
    ----------
    text : str
        File text.
    path : str
        File path.

    Returns
    -------
    list
        Tag findings.
    """
    return [
        {"id": match.strip(), "source": "spdx-tag", "path": path}
        for match in SPDX_TAG.findall(text)
    ]


def _text_findings(text: str, path: str) -> list:
    """
    Build findings from license text heuristics.

    Parameters
    ----------
    text : str
        File text.
    path : str
        File path.

    Returns
    -------
    list
        Text findings.
    """
    return [
        {"id": spdx, "source": "text", "path": path}
        for spdx in _ids_from_text(text.lower())
    ]


def scan_licenses(path: str) -> dict:
    """
    Scan a file or tree for licenses and aggregate by SPDX id.

    Parameters
    ----------
    path : str
        File or directory.

    Returns
    -------
    dict
        Findings plus an id -> {count, paths} summary.
    """
    findings = []
    for target in _iter_files(path):
        findings.extend(_scan_file(target))
    return {
        "path": path,
        "findings": findings,
        "summary": _summarize(findings),
    }


def _summarize(findings: list) -> dict:
    """
    Aggregate license findings by SPDX id.

    Parameters
    ----------
    findings : list
        License findings.

    Returns
    -------
    dict
        Id to count and paths.
    """
    summary = {}
    for item in findings:
        entry = summary.setdefault(item["id"], {"count": 0, "paths": []})
        entry["count"] += 1
        entry["paths"].append(item["path"])
    return summary


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
