"""Raw carving of identified regions without parsing their contents."""

import os
import re

_SAFE = re.compile(r"[^A-Za-z0-9._-]+")


def _safe(name: str) -> str:
    """
    Sanitize a type label for use as a filename component.

    Parameters
    ----------
    name : str
        Raw label.

    Returns
    -------
    str
        Filesystem-safe label.
    """
    return _SAFE.sub("_", name).strip("_") or "region"


def _regions(findings: list, total: int):
    """
    Turn findings into contiguous carve ranges.

    Parameters
    ----------
    findings : list
        Sorted finding dictionaries with an ``offset``.
    total : int
        Total blob length.

    Yields
    ------
    tuple
        (offset, end, type) carve ranges.
    """
    for index, item in enumerate(findings):
        start = item["offset"]
        if index + 1 < len(findings):
            end = findings[index + 1]["offset"]
        else:
            end = total
        if end > start:
            yield start, end, item.get("type", "region")


def carve_findings(
    data: bytes, findings: list, outdir: str, max_bytes: int = 268435456
) -> list:
    """
    Write each identified region to its own file under ``outdir``.

    Parameters
    ----------
    data : bytes
        Whole blob.
    findings : list
        Signature findings carrying byte offsets.
    outdir : str
        Destination directory (created if absent).
    max_bytes : int
        Cap on total bytes written.

    Returns
    -------
    list
        Manifest entries describing each carved region.
    """
    ordered = sorted(findings, key=lambda item: item["offset"])
    os.makedirs(outdir, exist_ok=True)
    written = []
    for start, end, label in _regions(ordered, len(data)):
        written.append(_carve_one(data, start, end, label, outdir, max_bytes))
    return written


def _carve_one(
    data: bytes, start: int, end: int, label: str, outdir: str, max_bytes: int
) -> dict:
    """
    Write one carved region to disk.

    Parameters
    ----------
    data : bytes
        Whole blob.
    start : int
        Region start offset.
    end : int
        Region end offset.
    label : str
        Region type label.
    outdir : str
        Destination directory.
    max_bytes : int
        Region size cap.

    Returns
    -------
    dict
        Manifest entry.
    """
    chunk = data[start:end][:max_bytes]
    name = "0x{:x}-{}.bin".format(start, _safe(label))
    path = os.path.join(outdir, name)
    with open(path, "wb") as handle:
        handle.write(chunk)
    return {"offset": start, "size": len(chunk), "type": label, "path": path}
