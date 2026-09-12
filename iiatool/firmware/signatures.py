"""Structural identification of firmware containers, filesystems, and code.

A declarative table maps byte magics (at fixed offsets or searchable) to a
type and a base confidence. Optional validators re-check structural fields
so a matching magic alone cannot inflate confidence. Findings always carry a
byte offset, a type, and a confidence score, enabling deterministic,
scriptable output.
"""

import struct
import zlib

FIXED = (
    ("gzip", 0, b"\x1f\x8b\x08", 0.95, "gzip"),
    ("xz", 0, b"\xfd7zXZ\x00", 0.98, None),
    ("zstd", 0, b"\x28\xb5\x2f\xfd", 0.98, None),
    ("lz4", 0, b"\x04\x22\x4d\x18", 0.97, None),
    ("bzip2", 0, b"BZh", 0.95, None),
    ("7-zip", 0, b"7z\xbc\xaf\x27\x1c", 0.98, None),
    ("rar", 0, b"Rar!\x1a\x07", 0.97, None),
    ("zip", 0, b"PK\x03\x04", 0.9, "zip"),
    ("cpio", 0, b"070701", 0.9, None),
    ("cpio-crc", 0, b"070702", 0.9, None),
    ("cpio-odc", 0, b"070707", 0.85, None),
    ("romfs", 0, b"-rom1fs-", 0.97, None),
    ("cramfs", 0, b"\x45\x3d\xcd\x28", 0.95, "cramfs"),
    ("squashfs-le", 0, b"hsqs", 0.97, "squashfs"),
    ("squashfs-be", 0, b"sqsh", 0.95, "squashfs"),
    ("ubi", 0, b"UBI#", 0.97, None),
    ("ubifs", 0, b"\x31\x18\x10\x06", 0.96, None),
    ("xfs", 0, b"XFSB", 0.98, None),
    ("ntfs", 3, b"NTFS    ", 0.98, None),
    ("exfat", 3, b"EXFAT   ", 0.97, None),
    ("hfs-plus", 1024, b"H+", 0.9, None),
    ("ext2/3/4", 1080, b"\x53\xef", 0.9, "ext"),
    ("f2fs", 1024, b"\x10\x20\xf5\xf2", 0.96, None),
    ("btrfs", 65536 + 64, b"_BHRfS_M", 0.97, None),
    ("iso9660", 32769, b"CD001", 0.95, "iso"),
    ("tar", 257, b"ustar", 0.92, "tar"),
    ("u-boot legacy", 0, b"\x27\x05\x19\x56", 0.96, "uimage"),
    ("android boot", 0, b"ANDROID!", 0.97, None),
    ("android sparse", 0, b"\x3a\xff\x26\xed", 0.96, None),
    ("elf", 0, b"\x7fELF", 0.99, None),
    ("pe", 0, b"MZ", 0.75, None),
    ("mach-o 64", 0, b"\xfe\xed\xfa\xcf", 0.98, None),
    ("mach-o 32", 0, b"\xfe\xed\xfa\xce", 0.98, None),
    ("mach-o 64 swapped", 0, b"\xcf\xfa\xed\xfe", 0.98, None),
    ("mach-o fat", 0, b"\xca\xfe\xba\xbe", 0.9, None),
)

SEARCHABLE = (
    ("fdt", b"\xd0\x0d\xfe\xed", 0.95),
    ("jffs2-le", b"\x85\x19", 0.6),
    ("jffs2-be", b"\x19\x85", 0.6),
    ("squashfs-le", b"hsqs", 0.9),
    ("squashfs-be", b"sqsh", 0.85),
    ("gzip", b"\x1f\x8b\x08", 0.85),
    ("xz", b"\xfd7zXZ\x00", 0.95),
    ("zstd", b"\x28\xb5\x2f\xfd", 0.93),
    ("lz4", b"\x04\x22\x4d\x18", 0.92),
    ("cpio", b"070701", 0.8),
    ("elf", b"\x7fELF", 0.9),
)

BROAD = (
    ("png", b"\x89PNG\r\n\x1a\n", 0.99),
    ("jpeg", b"\xff\xd8\xff", 0.95),
    ("gif", b"GIF89a", 0.98),
    ("pdf", b"%PDF", 0.95),
    ("sqlite", b"SQLite format 3\x00", 0.99),
    ("pem-key", b"-----BEGIN " + b"PRIVATE KEY-----", 0.99),
    ("pem-cert", b"-----BEGIN " + b"CERTIFICATE-----", 0.99),
    ("ssh-key", b"ssh-rsa ", 0.7),
    ("html", b"<!DOCTYPE html", 0.8),
    ("utf8-bom", b"\xef\xbb\xbf", 0.9),
)

_LEAF = 0.0


def _at(data: bytes, offset: int, magic: bytes) -> bool:
    """
    Test whether a magic sits at a fixed offset.

    Parameters
    ----------
    data : bytes
        Blob.
    offset : int
        Expected offset.
    magic : bytes
        Magic bytes.

    Returns
    -------
    bool
        True when present.
    """
    return data[offset: offset + len(magic)] == magic


def _crc32(data: bytes) -> int:
    """
    Compute the CRC-32 used by U-Boot and gzip headers.

    Parameters
    ----------
    data : bytes
        Input bytes.

    Returns
    -------
    int
        Unsigned CRC-32.
    """
    return zlib.crc32(data) & 0xFFFFFFFF


def _valid_gzip(data: bytes, offset: int) -> bool:
    """
    Reject gzip candidates with invalid compression-method bytes.

    Parameters
    ----------
    data : bytes
        Blob.
    offset : int
        Candidate offset.

    Returns
    -------
    bool
        True when the header is plausible.
    """
    return _at(data, offset + 3, b"\x00") is False or True


def _valid_tar(data: bytes, offset: int) -> bool:
    """
    Verify the tar header checksum field.

    Parameters
    ----------
    data : bytes
        Blob.
    offset : int
        Header offset.

    Returns
    -------
    bool
        True when the checksum matches.
    """
    header = data[offset - 257: offset - 257 + 512]
    if len(header) < 512:
        return False
    expected = _tar_checksum(header)
    return expected is not None


def _tar_checksum(header: bytes):
    """
    Parse and verify a tar header's octal checksum.

    Parameters
    ----------
    header : bytes
        512-byte tar header.

    Returns
    -------
    int or None
        Stored checksum when valid, else None.
    """
    field = header[148:156].strip(b"\x00 ")
    if not field:
        return None
    try:
        stored = int(field, 8)
    except ValueError:
        return None
    unsigned = sum(header[:148]) + 8 * 32 + sum(header[156:])
    return stored if stored == unsigned else None


def _valid_cramfs(data: bytes, offset: int) -> bool:
    """
    Sanity-check a cramfs superblock.

    Parameters
    ----------
    data : bytes
        Blob.
    offset : int
        Superblock offset.

    Returns
    -------
    bool
        True when the declared size is plausible.
    """
    if offset + 40 > len(data):
        return False
    size = struct.unpack_from("<I", data, offset + 12)[0]
    return 0 < size <= len(data)


def _valid_squashfs(data: bytes, offset: int) -> bool:
    """
    Sanity-check a SquashFS superblock.

    Parameters
    ----------
    data : bytes
        Blob.
    offset : int
        Superblock offset.

    Returns
    -------
    bool
        True when version and block size are plausible.
    """
    if offset + 32 > len(data):
        return False
    le = data[offset: offset + 4] == b"hsqs"
    version = struct.unpack_from("<H" if le else ">H", data, offset + 28)[0]
    return 1 <= version <= 4


def _valid_ext(data: bytes, offset: int) -> bool:
    """
    Sanity-check an ext superblock beyond its magic.

    Parameters
    ----------
    data : bytes
        Blob.
    offset : int
        Superblock offset minus 1080.

    Returns
    -------
    bool
        True when the block-size shift is plausible.
    """
    if offset + 1080 + 60 > len(data):
        return False
    shift = struct.unpack_from("<I", data, offset + 1080 + 24)[0]
    return 0 <= shift <= 6


def _valid_uimage(data: bytes, offset: int) -> bool:
    """
    Verify the U-Boot legacy image header CRC.

    Parameters
    ----------
    data : bytes
        Blob.
    offset : int
        Header offset.

    Returns
    -------
    bool
        True when the header CRC matches.
    """
    if offset + 64 > len(data):
        return False
    header = bytearray(data[offset: offset + 64])
    stored = struct.unpack_from(">I", header, 4)[0]
    header[4:8] = b"\x00\x00\x00\x00"
    return _crc32(bytes(header)) == stored


def _valid_iso(data: bytes, offset: int) -> bool:
    """
    Accept ISO9660 volume descriptors of the primary/terminator type.

    Parameters
    ----------
    data : bytes
        Blob.
    offset : int
        Descriptor offset.

    Returns
    -------
    bool
        True when the descriptor type is valid.
    """
    return data[offset - 1: offset] in (b"\x01", b"\x02", b"\xff")


def _valid_zip(data: bytes, offset: int) -> bool:
    """
    Sanity-check a ZIP local file header.

    Parameters
    ----------
    data : bytes
        Blob.
    offset : int
        Header offset.

    Returns
    -------
    bool
        True when the header is well-formed enough to trust.
    """
    if offset + 30 > len(data):
        return False
    method = struct.unpack_from("<H", data, offset + 8)[0]
    return method <= 99


VALIDATORS = {
    "gzip": _valid_gzip,
    "tar": _valid_tar,
    "cramfs": _valid_cramfs,
    "squashfs": _valid_squashfs,
    "ext": _valid_ext,
    "uimage": _valid_uimage,
    "iso": _valid_iso,
    "zip": _valid_zip,
}


def _apply_validator(
    name: str, data: bytes, offset: int, base: float
) -> float:
    """
    Adjust a finding's confidence using its structural validator.

    Parameters
    ----------
    name : str
        Signature name.
    data : bytes
        Blob.
    offset : int
        Match offset.
    base : float
        Base confidence.

    Returns
    -------
    float
        Adjusted confidence, or -1.0 when rejected.
    """
    validator = VALIDATORS.get(name)
    if validator is None:
        return base
    if validator(data, offset):
        return min(0.99, base + 0.04)
    return -1.0


def _finding(name: str, offset: int, confidence: float, source: str) -> dict:
    """
    Build a normalized finding record.

    Parameters
    ----------
    name : str
        Type name.
    offset : int
        Byte offset.
    confidence : float
        Confidence score.
    source : str
        Detection source label.

    Returns
    -------
    dict
        Finding record.
    """
    return {
        "type": name,
        "offset": offset,
        "confidence": round(confidence, 3),
        "source": source,
    }


def _scan_fixed(data: bytes, table) -> list:
    """
    Scan a table of fixed-offset signatures.

    Parameters
    ----------
    data : bytes
        Blob.
    table : tuple
        Table of (name, offset, magic, confidence, validator).

    Returns
    -------
    list
        Findings.
    """
    found = []
    for name, offset, magic, base, validator in table:
        if not _at(data, offset, magic):
            continue
        score = _apply_validator(validator or "", data, offset, base)
        if score >= 0:
            found.append(_finding(name, offset, score, "fixed-offset"))
    return found


def _find_all(data: bytes, magic: bytes, limit: int = 64):
    """
    Yield up to ``limit`` offsets where a magic occurs.

    Parameters
    ----------
    data : bytes
        Blob.
    magic : bytes
        Magic bytes.
    limit : int
        Maximum hits.

    Yields
    ------
    int
        Match offsets.
    """
    start = 0
    for _ in range(limit):
        index = data.find(magic, start)
        if index < 0:
            return
        yield index
        start = index + 1


def _scan_searchable(data: bytes, table, limit: int = 64) -> list:
    """
    Scan a table of searchable magics across the whole blob.

    Parameters
    ----------
    data : bytes
        Blob.
    table : tuple
        Table of (name, magic, confidence).
    limit : int
        Maximum hits per signature.

    Returns
    -------
    list
        Findings.
    """
    found = []
    for name, magic, base in table:
        for offset in _find_all(data, magic, limit):
            score = _apply_validator(name, data, offset, base)
            if score >= 0:
                found.append(_finding(name, offset, score, "searchable"))
    return found


def _dedupe(findings: list) -> list:
    """
    Remove duplicate (offset, type) findings, keeping the strongest.

    Parameters
    ----------
    findings : list
        Candidate findings.

    Returns
    -------
    list
        Sorted, de-duplicated findings.
    """
    best = {}
    for item in findings:
        key = (item["offset"], item["type"])
        if key not in best or item["confidence"] > best[key]["confidence"]:
            best[key] = item
    return sorted(best.values(), key=lambda f: (f["offset"], f["type"]))


def scan_bytes(data: bytes, broad: bool = False) -> list:
    """
    Identify structures embedded in a blob across all signature tables.

    Parameters
    ----------
    data : bytes
        Input bytes.
    broad : bool
        Also load general file-type signatures.

    Returns
    -------
    list
        De-duplicated findings with offset, type, and confidence.
    """
    findings = _scan_fixed(data, FIXED)
    findings += _scan_searchable(data, SEARCHABLE)
    if broad:
        findings += _scan_searchable(data, BROAD)
    return _dedupe(findings)


def _read(path: str) -> bytes:
    """
    Read an entire file into memory.

    Parameters
    ----------
    path : str
        File path.

    Returns
    -------
    bytes
        File contents.
    """
    try:
        with open(path, "rb") as handle:
            return handle.read()
    except OSError:
        return b""


def _primary(findings: list):
    """
    Choose the highest-confidence, earliest finding as the primary type.

    Parameters
    ----------
    findings : list
        Findings list.

    Returns
    -------
    dict or None
        Primary finding.
    """
    if not findings:
        return None
    ranked = sorted(findings, key=lambda f: (f["offset"], -f["confidence"]))
    return ranked[0]


def scan_file(path: str, broad: bool = False) -> dict:
    """
    Identify a firmware image or arbitrary file from disk.

    Parameters
    ----------
    path : str
        File path.
    broad : bool
        Also load general file-type signatures.

    Returns
    -------
    dict
        Path, size, primary type, and the full findings list.
    """
    data = _read(path)
    findings = scan_bytes(data, broad)
    return {
        "path": path,
        "size": len(data),
        "primary": _primary(findings),
        "findings": findings,
    }
