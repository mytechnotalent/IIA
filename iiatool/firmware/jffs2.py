"""JFFS2 node scanning and file reconstruction.

JFFS2 stores a log of nodes rather than a directory tree. This module walks
node headers, learns names from directory-entry nodes, decompresses data
nodes (uncompressed or zlib), and reassembles regular files by inode and
offset. Unknown compression methods are skipped rather than guessed.
"""

import struct
import zlib

from .archives import _write_file

MAGIC = 0x1985
DIRENT = 0xE001
INODE = 0xE002
DATA = 0xE003
PADDING = 0x2004
SUMMARY = 0x2006

DT_DIR = 4
DT_REG = 8

COMPR_NONE = 0
COMPR_ZLIB = 1


def _endian(data: bytes, offset: int):
    """
    Detect per-node endianness from the magic bytes.

    Parameters
    ----------
    data : bytes
        Image bytes.
    offset : int
        Node offset.

    Returns
    -------
    str or None
        Struct endianness prefix, or None.
    """
    magic = data[offset: offset + 2]
    if magic == b"\x19\x85":
        return ">"
    if magic == b"\x85\x19":
        return "<"
    return None


def iter_nodes(data: bytes):
    """
    Yield parsed JFFS2 nodes from an image.

    Parameters
    ----------
    data : bytes
        Image bytes.

    Yields
    ------
    dict
        Parsed node records.
    """
    offset = 0
    seen = 0
    while offset + 12 <= len(data) and seen < 4_000_000:
        offset, result = _node_step(data, offset)
        seen += 1
        if result is not None:
            yield result


def _node_step(data: bytes, offset: int):
    """
    Advance one JFFS2 node and return any parsed record.

    Parameters
    ----------
    data : bytes
        Image bytes.
    offset : int
        Node offset.

    Returns
    -------
    tuple
        (next offset, parsed node or None).
    """
    end = _endian(data, offset)
    if not end:
        return offset + 4, None
    nodetype, totlen = struct.unpack_from(end + "HI", data, offset + 2)
    if totlen < 12 or offset + totlen > len(data):
        return offset + 4, None
    return _align(offset + totlen), _node_result(
        data, offset, totlen, nodetype, end
    )


def _node_result(
    data: bytes, offset: int, totlen: int, nodetype: int, end: str
):
    """
    Parse a valid JFFS2 node, or None for padding/summary nodes.

    Parameters
    ----------
    data : bytes
        Image bytes.
    offset : int
        Node offset.
    totlen : int
        Node length.
    nodetype : int
        Node type code.
    end : str
        Struct endianness prefix.

    Returns
    -------
    dict or None
        Parsed node or None.
    """
    if nodetype not in (DIRENT, INODE, DATA, PADDING, SUMMARY):
        return None
    if nodetype in (DIRENT, INODE, DATA):
        return _parse_node(data, offset, totlen, nodetype, end)
    return None


def _align(value: int) -> int:
    """
    Align an offset to a four-byte boundary.

    Parameters
    ----------
    value : int
        Raw offset.

    Returns
    -------
    int
        Aligned offset.
    """
    return (value + 3) & ~3


def _parse_node(
    data: bytes, offset: int, totlen: int, nodetype: int, end: str
):
    """
    Parse one dirent, inode, or data node.

    Parameters
    ----------
    data : bytes
        Image bytes.
    offset : int
        Node offset.
    totlen : int
        Total node length.
    nodetype : int
        Node type code.
    end : str
        Struct endianness prefix.

    Returns
    -------
    dict
        Parsed node.
    """
    if nodetype == DIRENT:
        return _parse_dirent(data, offset, totlen, end)
    if nodetype == DATA:
        return _parse_data(data, offset, end)
    return _parse_inode(data, offset, end)


def _parse_dirent(data: bytes, offset: int, totlen: int, end: str) -> dict:
    """
    Parse a JFFS2 dirent node.

    Parameters
    ----------
    data : bytes
        Image bytes.
    offset : int
        Node offset.
    totlen : int
        Node length.
    end : str
        Struct endianness prefix.

    Returns
    -------
    dict
        Dirent fields.
    """
    pino, _ver, ino, _mctime, nsize, dtype = struct.unpack_from(
        end + "IIIIBB", data, offset + 12
    )
    name = data[offset + 32: offset + 32 + nsize].decode("utf-8", "ignore")
    return {
        "kind": "dirent",
        "pino": pino,
        "ino": ino,
        "name": name,
        "dtype": dtype,
    }


def _parse_data(data: bytes, offset: int, end: str) -> dict:
    """
    Parse a JFFS2 data node.

    Parameters
    ----------
    data : bytes
        Image bytes.
    offset : int
        Node offset.
    end : str
        Struct endianness prefix.

    Returns
    -------
    dict
        Data node fields with decompressed payload.
    """
    ino, _ver, file_off, csize, dsize = struct.unpack_from(
        end + "IIIII", data, offset + 12
    )
    compr = data[offset + 32]
    blob = data[offset + 34: offset + 34 + csize]
    return {
        "kind": "data",
        "ino": ino,
        "file_offset": file_off,
        "dsize": dsize,
        "payload": _decompress(compr, blob, dsize),
    }


def _parse_inode(data: bytes, offset: int, end: str) -> dict:
    """
    Parse a JFFS2 inode node.

    Parameters
    ----------
    data : bytes
        Image bytes.
    offset : int
        Node offset.
    end : str
        Struct endianness prefix.

    Returns
    -------
    dict
        Inode or data fields.
    """
    mode, isize, compr, csize, ino = _inode_fields(data, offset, end)
    if csize == 0:
        return {"kind": "inode", "ino": ino, "mode": mode, "isize": isize}
    return _inode_data(data, offset, end, ino, compr, csize)


def _inode_fields(data: bytes, offset: int, end: str):
    """
    Read the common fields of a JFFS2 inode node.

    Parameters
    ----------
    data : bytes
        Image bytes.
    offset : int
        Node offset.
    end : str
        Struct endianness prefix.

    Returns
    -------
    tuple
        (mode, isize, compr, csize, ino).
    """
    mode = struct.unpack_from(end + "I", data, offset + 20)[0]
    isize = struct.unpack_from(end + "I", data, offset + 28)[0]
    compr = data[offset + 56]
    csize = struct.unpack_from(end + "I", data, offset + 48)[0]
    ino = struct.unpack_from(end + "I", data, offset + 12)[0]
    return mode, isize, compr, csize, ino


def _inode_data(data: bytes, offset: int, end: str, ino: int, compr: int,
                csize: int) -> dict:
    """
    Build the data record for an inode node that carries a payload.

    Parameters
    ----------
    data : bytes
        Image bytes.
    offset : int
        Node offset.
    end : str
        Struct endianness prefix.
    ino : int
        Inode number.
    compr : int
        Compression method code.
    csize : int
        Compressed size.

    Returns
    -------
    dict
        Data node fields.
    """
    file_off = struct.unpack_from(end + "I", data, offset + 44)[0]
    dsize = struct.unpack_from(end + "I", data, offset + 52)[0]
    blob = data[offset + 60: offset + 60 + csize]
    return {
        "kind": "data",
        "ino": ino,
        "file_offset": file_off,
        "dsize": dsize,
        "payload": _decompress(compr, blob, dsize),
    }


def _decompress(compr: int, blob: bytes, dsize: int) -> bytes:
    """
    Decompress a JFFS2 payload for the supported methods.

    Parameters
    ----------
    compr : int
        Compression method code.
    blob : bytes
        Compressed bytes.
    dsize : int
        Declared decompressed size.

    Returns
    -------
    bytes
        Payload bytes (empty when unsupported).
    """
    if compr == COMPR_NONE:
        return blob[:dsize]
    if compr == COMPR_ZLIB:
        try:
            return zlib.decompress(blob)[:dsize]
        except zlib.error:
            return b""
    return b""


def _assemble(nodes: list):
    """
    Build inode name maps and reassembled file contents.

    Parameters
    ----------
    nodes : list
        Parsed nodes.

    Returns
    -------
    tuple
        (dirents, files) where files maps inode to bytes.
    """
    dirents = [n for n in nodes if n["kind"] == "dirent"]
    buffers = {}
    for node in nodes:
        if node["kind"] == "data" and node["payload"]:
            _buffer_node(buffers, node)
    return dirents, buffers


def _buffer_node(buffers: dict, node: dict) -> None:
    """
    Place a data node's payload into its inode buffer.

    Parameters
    ----------
    buffers : dict
        Inode number to bytearray buffer.
    node : dict
        Parsed data node.

    Returns
    -------
    None
    """
    buf = buffers.setdefault(node["ino"], bytearray())
    end = node["file_offset"] + len(node["payload"])
    if end > len(buf):
        buf.extend(b"\x00" * (end - len(buf)))
    buf[node["file_offset"]: end] = node["payload"]


def _path_for(ino: int, dirents: list, seen: int = 0) -> str:
    """
    Resolve a full path for an inode via its parent dirents.

    Parameters
    ----------
    ino : int
        Inode number.
    dirents : list
        Dirent nodes.
    seen : int
        Recursion guard.

    Returns
    -------
    str
        Path.
    """
    if seen > 64:
        return ""
    entry = _path_entry(ino, dirents)
    if entry is None:
        return ""
    return _path_name(entry, dirents, seen)


def _path_entry(ino: int, dirents: list):
    """
    Find the dirent for an inode.

    Parameters
    ----------
    ino : int
        Inode number.
    dirents : list
        Dirent nodes.

    Returns
    -------
    dict or None
        Matching dirent.
    """
    for entry in dirents:
        if entry["ino"] == ino:
            return entry
    return None


def _path_name(entry: dict, dirents: list, seen: int) -> str:
    """
    Build a path for a dirent, recursing through its parent.

    Parameters
    ----------
    entry : dict
        Dirent node.
    dirents : list
        Dirent nodes.
    seen : int
        Recursion guard.

    Returns
    -------
    str
        Path.
    """
    if entry["pino"] == 1:
        return "/" + entry["name"]
    parent = _path_for(entry["pino"], dirents, seen + 1)
    return parent + "/" + entry["name"]


def read_jffs2(data: bytes, outdir: str, max_bytes: int = 67108864) -> list:
    """
    Reconstruct regular files from a JFFS2 image.

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
    dirents, buffers = _assemble(list(iter_nodes(data)))
    written = []
    for entry in dirents:
        item = _jffs2_file(entry, dirents, buffers, outdir, max_bytes)
        if item:
            written.append(item)
    return written


def _jffs2_file(entry: dict, dirents: list, buffers: dict, outdir: str,
                max_bytes: int):
    """
    Reconstruct one regular file, or None for other entry types.

    Parameters
    ----------
    entry : dict
        Dirent node.
    dirents : list
        Dirent nodes.
    buffers : dict
        Inode number to payload buffer.
    outdir : str
        Destination directory.
    max_bytes : int
        Per-file cap.

    Returns
    -------
    dict or None
        Manifest entry.
    """
    if entry["dtype"] != DT_REG or entry["ino"] not in buffers:
        return None
    path = _path_for(entry["ino"], dirents) or "/" + entry["name"]
    payload = bytes(buffers[entry["ino"]])[:max_bytes]
    return _write_file(outdir, path, payload, max_bytes)
