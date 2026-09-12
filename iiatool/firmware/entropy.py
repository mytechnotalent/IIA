"""Shannon entropy analysis over fixed-size windows of a blob."""

import math
from collections import Counter

DEFAULT_BLOCK = 4096
DEFAULT_THRESHOLD = 7.5


def _shannon(data: bytes) -> float:
    """
    Compute the Shannon entropy of a byte string in bits per byte.

    Parameters
    ----------
    data : bytes
        Input bytes.

    Returns
    -------
    float
        Entropy between 0.0 (uniform) and 8.0 (maximal).
    """
    if not data:
        return 0.0
    freq = Counter(data)
    total = len(data)
    return -sum(
        (count / total) * math.log2(count / total) for count in freq.values()
    )


def _windows(data: bytes, size: int, step: int):
    """
    Yield (offset, block) windows across the blob.

    Parameters
    ----------
    data : bytes
        Input bytes.
    size : int
        Window size in bytes.
    step : int
        Stride between windows.

    Yields
    ------
    tuple
        (offset, block) pairs.
    """
    for offset in range(0, len(data), step):
        block = data[offset: offset + size]
        if len(block) < size and offset:
            break
        yield offset, block


def _samples(data: bytes, size: int, step: int):
    """
    Build (offset, entropy, size) samples for every window.

    Parameters
    ----------
    data : bytes
        Input bytes.
    size : int
        Window size in bytes.
    step : int
        Stride between windows.

    Returns
    -------
    list
        Sample dictionaries.
    """
    out = []
    for offset, block in _windows(data, size, step):
        out.append(
            {
                "offset": offset,
                "size": len(block),
                "entropy": round(_shannon(block), 3),
            }
        )
    return out


def _merge(rows: list, threshold: float):
    """
    Merge contiguous high-entropy windows into regions.

    Parameters
    ----------
    rows : list
        Entropy samples sorted by offset.
    threshold : float
        Entropy floor for a window to be flagged.

    Returns
    -------
    list
        Merged region dictionaries with start/end offsets.
    """
    regions = []
    current = None
    for row in rows:
        if row["entropy"] >= threshold:
            current = _extend(current, row)
            continue
        regions, current = _flush(regions, current)
    return _flush(regions, current)[0]


def _flush(regions: list, current):
    """
    Close an open high-entropy region, if any.

    Parameters
    ----------
    regions : list
        Merged regions so far.
    current : dict or None
        Open region.

    Returns
    -------
    tuple
        Updated regions and a cleared current pointer.
    """
    if current:
        regions.append(current)
    return regions, None


def _extend(current, row):
    """
    Extend an open high-entropy region with the next sample.

    Parameters
    ----------
    current : dict or None
        Open region, if any.
    row : dict
        Next high-entropy sample.

    Returns
    -------
    dict
        The extended region.
    """
    if current is None:
        return {
            "start": row["offset"],
            "end": row["offset"] + row["size"],
            "peak": row["entropy"],
        }
    current["end"] = row["offset"] + row["size"]
    current["peak"] = max(current["peak"], row["entropy"])
    return current


def entropy_pass(
    data: bytes,
    size: int = DEFAULT_BLOCK,
    step: int = 0,
    threshold: float = DEFAULT_THRESHOLD,
) -> dict:
    """
    Score a blob for unidentified or possibly-encrypted regions.

    Parameters
    ----------
    data : bytes
        Input bytes.
    size : int
        Window size in bytes.
    step : int
        Stride between windows (defaults to the window size).
    threshold : float
        Entropy floor for a window to be flagged.

    Returns
    -------
    dict
        Overall entropy, samples, and merged high-entropy regions.
    """
    stride = step or size
    rows = _samples(data, size, stride)
    return {
        "overall_entropy": round(_shannon(data), 3),
        "block_size": size,
        "threshold": threshold,
        "samples": rows,
        "regions": _merge(rows, threshold),
    }
