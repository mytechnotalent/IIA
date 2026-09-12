"""Detection of UPX-style packed executables from their trailing marker.

Packed binaries append a marker near end-of-file and often zero or alter the
original executable header. This module locates the marker, reports its byte
offset, infers the host executable format, and flags stubs whose header was
zeroed. It is deliberately conservative: unsigned fields are surfaced as raw
integers rather than guessed names, and scans never trust the marker alone.
"""

import re
import struct

MARKER = b"UPX!"
_TRAILER = 4096

_HOST_MAGICS = (
    ("ELF", b"\x7fELF"),
    ("PE", b"MZ"),
    ("Mach-O 64", b"\xfe\xed\xfa\xcf"),
    ("Mach-O 32", b"\xfe\xed\xfa\xce"),
    ("Mach-O 64 swapped", b"\xcf\xfa\xed\xfe"),
    ("Mach-O 32 swapped", b"\xce\xfa\xed\xfe"),
    ("Mach-O fat", b"\xca\xfe\xba\xbe"),
)


def _host_format(data: bytes) -> str:
    """
    Identify the executable container format of a packed image.

    Parameters
    ----------
    data : bytes
        Candidate executable bytes.

    Returns
    -------
    str
        Container label, or ``unknown``.
    """
    for label, magic in _HOST_MAGICS:
        if data[: len(magic)] == magic:
            return label
    return "unknown"


def _pack_fields(data: bytes, marker_at: int):
    """
    Parse plausible PackHeader fields adjacent to a marker.

    Parameters
    ----------
    data : bytes
        Whole file.
    marker_at : int
        Offset of the located marker.

    Returns
    -------
    dict
        Best-effort numeric fields and their origin.
    """
    candidates = _candidate_windows(data, marker_at)
    for window in candidates:
        fields = _decode_header(window)
        if fields:
            return fields
    return {}


def _candidate_windows(data: bytes, marker_at: int):
    """
    Yield windows that may contain a 32-byte PackHeader.

    Parameters
    ----------
    data : bytes
        Whole file.
    marker_at : int
        Offset of the located marker.

    Yields
    ------
    bytes
        Candidate PackHeader windows.
    """
    head = max(0, marker_at - 32)
    if marker_at + 32 <= len(data):
        yield data[marker_at + 4: marker_at + 36]
    if marker_at >= 32:
        yield data[head:marker_at]
    yield data[-32:] if len(data) >= 32 else b""


def _decode_header(window: bytes):
    """
    Decode a 32-byte PackHeader candidate when the values look sane.

    Parameters
    ----------
    window : bytes
        Candidate window.

    Returns
    -------
    dict or None
        Parsed fields, or None when implausible.
    """
    if len(window) < 20:
        return None
    adler = struct.unpack_from("<I", window, 0)[0]
    lengths = struct.unpack_from("<IIII", window, 8)
    level = window[23]
    if level > 11 or any(v > 0x7FFFFFFF for v in lengths):
        return None
    return {
        "adler32_hint": adler,
        "uncompressed_len": lengths[0],
        "compressed_len": lengths[1],
        "level": level,
    }


def _zeroed_header(data: bytes) -> bool:
    """
    Report whether the leading executable header appears zeroed out.

    Parameters
    ----------
    data : bytes
        Whole file.

    Returns
    -------
    bool
        True when the first sixteen bytes are all zero.
    """
    return len(data) >= 16 and not any(data[:16])


def detect_upx(data: bytes) -> dict:
    """
    Locate a UPX-style pack marker and describe the enclosing executable.

    Parameters
    ----------
    data : bytes
        Candidate firmware or executable bytes.

    Returns
    -------
    dict
        ``packed`` flag plus marker offset, host format, fields, and stub
        flag when a marker is present.
    """
    tail = data[-_TRAILER:] if len(data) > _TRAILER else data
    marker_at = tail.rfind(MARKER)
    if marker_at < 0:
        return {"packed": False}
    absolute = len(data) - len(tail) + marker_at
    span = data[max(0, absolute - 64): absolute + 64]
    return {
        "packed": True,
        "marker_offset": absolute,
        "host_format": _host_format(data),
        "zeroed_header": _zeroed_header(data),
        "exec_magic_near_marker": bool(re.search(rb"\x7fELF|MZ", span)),
        "fields": _pack_fields(data, absolute),
    }
