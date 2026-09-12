"""Archive and image containers: tar, zip, cpio, and ISO 9660.

Extraction is path-traversal safe: every member name is resolved beneath the
destination directory and rejected when it escapes. tar and zip use the
standard library; cpio and ISO 9660 are parsed directly from their on-disk
structures.
"""

import io
import os
import struct
import tarfile
import zipfile

_OCTAL = (b"070701", b"070702", b"070707")


def safe_join(root: str, member: str) -> str:
    """
    Resolve a member name beneath a root directory, or reject it.

    Parameters
    ----------
    root : str
        Destination root.
    member : str
        Archive member path.

    Returns
    -------
    str
        Absolute destination path.

    Raises
    ------
    ValueError
        When the member would escape the root.
    """
    target = os.path.realpath(os.path.join(root, member.lstrip("/")))
    base = os.path.realpath(root)
    if target != base and not target.startswith(base + os.sep):
        raise ValueError("unsafe member path: " + member)
    return target


def _write_file(root: str, name: str, payload: bytes, max_bytes: int):
    """
    Write one extracted member, enforcing the byte cap.

    Parameters
    ----------
    root : str
        Destination root.
    name : str
        Member name.
    payload : bytes
        Member content.
    max_bytes : int
        Per-file cap.

    Returns
    -------
    dict
        Manifest entry.
    """
    path = safe_join(root, name)
    os.makedirs(os.path.dirname(path), exist_ok=True)
    chunk = payload[:max_bytes]
    with open(path, "wb") as handle:
        handle.write(chunk)
    return {"path": path, "size": len(chunk), "member": name}


def list_tar(data: bytes) -> list:
    """
    List members of a tar archive held in memory.

    Parameters
    ----------
    data : bytes
        Tar bytes.

    Returns
    -------
    list
        Member names.
    """
    with tarfile.open(fileobj=io.BytesIO(data)) as archive:
        return [member.name for member in archive.getmembers()]


def extract_tar(data: bytes, outdir: str, max_bytes: int = 67108864) -> list:
    """
    Extract a tar archive with path-traversal protection.

    Parameters
    ----------
    data : bytes
        Tar bytes.
    outdir : str
        Destination directory.
    max_bytes : int
        Per-file cap.

    Returns
    -------
    list
        Manifest entries.
    """
    written = []
    with tarfile.open(fileobj=io.BytesIO(data)) as archive:
        for member in archive.getmembers():
            if not member.isfile():
                continue
            payload = archive.extractfile(member).read(max_bytes)
            written.append(
                _write_file(outdir, member.name, payload, max_bytes)
            )
    return written


def list_zip(data: bytes) -> list:
    """
    List members of a zip archive held in memory.

    Parameters
    ----------
    data : bytes
        Zip bytes.

    Returns
    -------
    list
        Member names.
    """
    with zipfile.ZipFile(io.BytesIO(data)) as archive:
        return archive.namelist()


def extract_zip(data: bytes, outdir: str, max_bytes: int = 67108864) -> list:
    """
    Extract a zip archive with path-traversal protection.

    Parameters
    ----------
    data : bytes
        Zip bytes.
    outdir : str
        Destination directory.
    max_bytes : int
        Per-file cap.

    Returns
    -------
    list
        Manifest entries.
    """
    written = []
    with zipfile.ZipFile(io.BytesIO(data)) as archive:
        for name in archive.namelist():
            if name.endswith("/"):
                continue
            payload = archive.read(name)[:max_bytes]
            written.append(_write_file(outdir, name, payload, max_bytes))
    return written


def _cpio_name(header: bytes, newc: bool):
    """
    Extract the file name from a cpio header.

    Parameters
    ----------
    header : bytes
        Header bytes.
    newc : bool
        True for the newc/crc format.

    Returns
    -------
    tuple
        (name, file_size, header_size).
    """
    if newc:
        return _cpio_newc_name(header)
    return _cpio_odc_name(header)


def _cpio_newc_name(header: bytes):
    """
    Parse a newc/crc cpio header name and sizes.

    Parameters
    ----------
    header : bytes
        Header bytes.

    Returns
    -------
    tuple
        (name, file_size, header_size).
    """
    namesize = int(header[94:102], 16)
    filesize = int(header[54:62], 16)
    name = header[110: 110 + namesize - 1].decode("utf-8", "ignore")
    return name, filesize, _pad(110 + namesize)


def _cpio_odc_name(header: bytes):
    """
    Parse an odc cpio header name and sizes.

    Parameters
    ----------
    header : bytes
        Header bytes.

    Returns
    -------
    tuple
        (name, file_size, header_size).
    """
    namesize = int(header[59:65], 8)
    filesize = int(header[65:76], 8)
    name = header[76: 76 + namesize - 1].decode("utf-8", "ignore")
    return name, filesize, _pad(76 + namesize)


def _pad(value: int, block: int = 4) -> int:
    """
    Round a value up to a block boundary.

    Parameters
    ----------
    value : int
        Raw value.
    block : int
        Block size.

    Returns
    -------
    int
        Padded value.
    """
    return (value + block - 1) // block * block


def iter_cpio(data: bytes):
    """
    Yield (name, payload) pairs from a cpio archive.

    Parameters
    ----------
    data : bytes
        Cpio bytes.

    Yields
    ------
    tuple
        (name, payload) pairs.
    """
    offset = 0
    while offset + 6 <= len(data):
        entry = _cpio_entry(data, offset)
        if entry is None:
            return
        name, size, body = entry
        yield name, data[body: body + size]
        offset = body + _pad(size)


def _cpio_entry(data: bytes, offset: int):
    """
    Parse the entry at an offset, or return None at the archive end.

    Parameters
    ----------
    data : bytes
        Cpio bytes.
    offset : int
        Current offset.

    Returns
    -------
    tuple or None
        (name, size, body offset) or None.
    """
    magic = data[offset: offset + 6]
    if magic not in _OCTAL:
        return None
    return _cpio_parse(data, offset, magic in _OCTAL[:2])


def _cpio_parse(data: bytes, offset: int, newc: bool):
    """
    Parse a cpio entry once its magic is known to be valid.

    Parameters
    ----------
    data : bytes
        Cpio bytes.
    offset : int
        Entry offset.
    newc : bool
        True for the newc/crc format.

    Returns
    -------
    tuple or None
        (name, size, body offset) or None for the trailer.
    """
    header_len = 110 if newc else 76
    name, size, header_size = _cpio_name(
        data[offset: offset + header_len + 256], newc
    )
    if name == "TRAILER!!!":
        return None
    return name, size, offset + header_size


def list_cpio(data: bytes) -> list:
    """
    List member names of a cpio archive.

    Parameters
    ----------
    data : bytes
        Cpio bytes.

    Returns
    -------
    list
        Member names.
    """
    return [name for name, _ in iter_cpio(data)]


def extract_cpio(data: bytes, outdir: str, max_bytes: int = 67108864) -> list:
    """
    Extract a cpio archive with path-traversal protection.

    Parameters
    ----------
    data : bytes
        Cpio bytes.
    outdir : str
        Destination directory.
    max_bytes : int
        Per-file cap.

    Returns
    -------
    list
        Manifest entries.
    """
    written = []
    for name, payload in iter_cpio(data):
        written.append(_write_file(outdir, name, payload, max_bytes))
    return written


def _iso_record(data: bytes, offset: int):
    """
    Parse an ISO 9660 directory record.

    Parameters
    ----------
    data : bytes
        Image bytes.
    offset : int
        Record offset.

    Returns
    -------
    dict or None
        Parsed record fields.
    """
    if offset + 33 > len(data) or data[offset] == 0:
        return None
    extent = struct.unpack_from("<I", data, offset + 2)[0]
    size = struct.unpack_from("<I", data, offset + 10)[0]
    return {
        "extent": extent,
        "size": size,
        "flags": data[offset + 25],
        "name": _iso_name(data, offset),
    }


def _iso_name(data: bytes, offset: int) -> str:
    """
    Decode an ISO 9660 record name, mapping the special entries.

    Parameters
    ----------
    data : bytes
        Image bytes.
    offset : int
        Record offset.

    Returns
    -------
    str
        Entry name.
    """
    name_len = data[offset + 32]
    name = data[offset + 33: offset + 33 + name_len].decode("utf-8", "ignore")
    if name == "\x00":
        return "."
    if name == "\x01":
        return ".."
    return name


def list_iso(data: bytes) -> list:
    """
    Walk an ISO 9660 primary volume descriptor and list file paths.

    Parameters
    ----------
    data : bytes
        ISO image bytes.

    Returns
    -------
    list
        File paths within the image.
    """
    root = _iso_root(data)
    if not root:
        return []
    return [path for path, _ in _iso_walk(data, root, "")]


def _iso_root(data: bytes):
    """
    Locate the ISO 9660 primary volume descriptor root record.

    Parameters
    ----------
    data : bytes
        Image bytes.

    Returns
    -------
    dict or None
        Root directory record.
    """
    for sector in range(16, 32):
        offset = sector * 2048
        block = data[offset: offset + 2048]
        if len(block) < 190 or not block.startswith(b"\x01CD001"):
            continue
        return _iso_record(block, 156)
    return None


def _iso_walk(data: bytes, record: dict, prefix: str):
    """
    Recursively walk ISO directory records.

    Parameters
    ----------
    data : bytes
        Image bytes.
    record : dict
        Directory record.
    prefix : str
        Accumulated path prefix.

    Yields
    ------
    tuple
        (path, record) pairs for files.
    """
    for child in _iso_children(data, record):
        name = child["name"]
        if name in (".", "..", ""):
            continue
        path = prefix + "/" + name
        if child["flags"] & 0x02:
            yield from _iso_walk(data, child, path)
        else:
            yield path, child


def _iso_children(data: bytes, record: dict):
    """
    Enumerate directory records inside an ISO directory extent.

    Parameters
    ----------
    data : bytes
        Image bytes.
    record : dict
        Directory record.

    Returns
    -------
    list
        Child records.
    """
    pos = record["extent"] * 2048
    end = pos + record["size"]
    return list(_iso_scan(data, pos, end))


def _iso_scan(data: bytes, pos: int, end: int):
    """
    Yield directory records across an ISO directory extent.

    Parameters
    ----------
    data : bytes
        Image bytes.
    pos : int
        Start offset.
    end : int
        End offset.

    Yields
    ------
    dict
        Directory records.
    """
    while pos < end and pos < len(data):
        entry = _iso_record(data, pos)
        if entry is None:
            return
        yield entry
        pos = _iso_next(data, pos, end)


def _iso_next(data: bytes, pos: int, end: int) -> int:
    """
    Advance to the next ISO directory record.

    Parameters
    ----------
    data : bytes
        Image bytes.
    pos : int
        Current record offset.
    end : int
        Directory end offset.

    Returns
    -------
    int
        Next record offset.
    """
    length = data[pos]
    return pos + (length if length else (end - pos))


def extract_iso(data: bytes, outdir: str, max_bytes: int = 67108864) -> list:
    """
    Extract files from an ISO 9660 image.

    Parameters
    ----------
    data : bytes
        Image bytes.
    outdir : str
        Destination directory.
    max_bytes : int
        Per-file cap.

    Returns
    -------
    list
        Manifest entries.
    """
    root = _iso_root(data)
    if not root:
        return []
    written = []
    for path, record in _iso_walk(data, root, ""):
        written.append(_iso_extract_one(data, path, record, outdir, max_bytes))
    return written


def _iso_extract_one(
    data: bytes, path: str, record: dict, outdir: str, max_bytes: int
) -> dict:
    """
    Extract one ISO file to disk.

    Parameters
    ----------
    data : bytes
        Image bytes.
    path : str
        Member path.
    record : dict
        Directory record.
    outdir : str
        Destination directory.
    max_bytes : int
        Per-file cap.

    Returns
    -------
    dict
        Manifest entry.
    """
    start = record["extent"] * 2048
    payload = data[start: start + record["size"]][:max_bytes]
    return _write_file(outdir, path, payload, max_bytes)
