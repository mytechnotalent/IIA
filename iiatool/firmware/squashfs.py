"""Native SquashFS v4 reader: superblock, metadata, inodes, and data blocks.

Supports directories, regular files, and symlinks with gzip, xz/lzma, lz4,
and zstd data blocks (lz4/zstd only when their optional modules exist).
Unsupported codecs degrade to an empty result rather than an error. Every
walk is bounded by a node budget so a malformed image cannot loop forever.
"""

import struct

from .archives import _write_file
from .compress import decompress

MAGIC_LE = b"hsqs"
MAGIC_BE = b"sqsh"

CODECS = {1: "gzip", 2: "lzma", 3: "lzo", 4: "xz", 5: "lz4", 6: "zstd"}

DIR_TYPE = 1
REG_TYPE = 2
SYMLINK_TYPE = 3
LDIR_TYPE = 8
LREG_TYPE = 9
LSYMLINK_TYPE = 10

META_UNCOMPRESSED = 0x8000
BLOCK_UNCOMPRESSED = 0x1000000
DATA_END = 0xFFFFFFFFFFFFFFFF
NODE_BUDGET = 200000


def _endian(data: bytes) -> str:
    """
    Choose the struct endianness prefix from the superblock magic.

    Parameters
    ----------
    data : bytes
        Image bytes.

    Returns
    -------
    str
        ``<`` for little-endian, ``>`` for big-endian.
    """
    return "<" if data[:4] == MAGIC_LE else ">"


def squashfs_info(data: bytes):
    """
    Parse a SquashFS superblock.

    Parameters
    ----------
    data : bytes
        Image bytes.

    Returns
    -------
    dict or None
        Superblock fields, or None when the magic is absent.
    """
    if len(data) < 96 or data[:4] not in (MAGIC_LE, MAGIC_BE):
        return None
    end = _endian(data)
    return {
        "endian": end,
        "inodes": struct.unpack_from(end + "I", data, 4)[0],
        "block_size": struct.unpack_from(end + "I", data, 12)[0],
        "fragments": struct.unpack_from(end + "I", data, 16)[0],
        "codec": CODECS.get(
            struct.unpack_from(end + "H", data, 20)[0], "unknown"
        ),
        "version": struct.unpack_from(end + "HH", data, 28),
        "root_inode": struct.unpack_from(end + "Q", data, 32)[0],
        "bytes_used": struct.unpack_from(end + "Q", data, 40)[0],
        "inode_table": struct.unpack_from(end + "Q", data, 64)[0],
        "dir_table": struct.unpack_from(end + "Q", data, 72)[0],
        "fragment_table": struct.unpack_from(end + "Q", data, 80)[0],
    }


def _meta_block(data: bytes, offset: int, end: str):
    """
    Read and decompress one metadata block.

    Parameters
    ----------
    data : bytes
        Image bytes.
    offset : int
        Metadata block offset.
    end : str
        Struct endianness prefix.

    Returns
    -------
    tuple
        (decompressed bytes, next block offset).
    """
    if offset + 2 > len(data):
        return b"", len(data)
    header = struct.unpack_from(end + "H", data, offset)[0]
    size = header & 0x7FFF
    raw = data[offset + 2: offset + 2 + size]
    cursor = offset + 2 + size
    body = raw if header & META_UNCOMPRESSED else _decompress_meta(data, raw)
    return body, cursor


def _decompress_meta(data: bytes, raw: bytes) -> bytes:
    """
    Decompress one SquashFS metadata block with the image codec.

    Parameters
    ----------
    data : bytes
        Image bytes.
    raw : bytes
        Compressed metadata bytes.

    Returns
    -------
    bytes
        Decompressed metadata.
    """
    info = squashfs_info(data)
    return decompress(info["codec"], raw) or b""


def _meta_read(data: bytes, info: dict, block: int, offset: int, length: int):
    """
    Read a span of metadata starting at a block/offset, crossing blocks.

    Parameters
    ----------
    data : bytes
        Image bytes.
    info : dict
        Superblock info.
    block : int
        Metadata block offset.
    offset : int
        Offset within the decompressed block.
    length : int
        Desired byte count.

    Returns
    -------
    tuple
        (bytes, next block offset, next offset).
    """
    collected, cursor = _meta_gather(data, info, block, offset, length)
    return bytes(collected[:length]), cursor, len(collected)


def _meta_gather(
    data: bytes, info: dict, block: int, offset: int, length: int
):
    """
    Gather metadata bytes across block boundaries.

    Parameters
    ----------
    data : bytes
        Image bytes.
    info : dict
        Superblock info.
    block : int
        Metadata block offset.
    offset : int
        Offset within the first block.
    length : int
        Desired byte count.

    Returns
    -------
    tuple
        (gathered bytes, next block offset).
    """
    first, cursor = _meta_block(data, block, info["endian"])
    collected = bytearray(first[offset:])
    while len(collected) < length and cursor < len(data) and first:
        first, cursor = _meta_block(data, cursor, info["endian"])
        collected += first
    return collected, cursor


def _inode_ref(ref: int) -> tuple:
    """
    Split an inode reference into its metadata block and offset.

    Parameters
    ----------
    ref : int
        Packed inode reference.

    Returns
    -------
    tuple
        (block offset, offset within block).
    """
    return ref >> 16, ref & 0xFFFF


def _inode(data: bytes, info: dict, ref: int):
    """
    Parse an inode referenced by a packed inode reference.

    Parameters
    ----------
    data : bytes
        Image bytes.
    info : dict
        Superblock info.
    ref : int
        Packed inode reference.

    Returns
    -------
    dict or None
        Inode fields.
    """
    block, offset = _inode_ref(ref)
    raw, _next, have = _meta_read(data, info, block, offset, 512)
    if len(raw) < 16:
        return None
    end = info["endian"]
    return _decode_inode(raw, struct.unpack_from(end + "H", raw, 0)[0], end)


def _decode_inode(raw: bytes, inode_type: int, end: str):
    """
    Decode inode type-specific fields.

    Parameters
    ----------
    raw : bytes
        Raw inode bytes.
    inode_type : int
        Inode type code.
    end : str
        Struct endianness prefix.

    Returns
    -------
    dict or None
        Inode fields.
    """
    if inode_type in (DIR_TYPE, LDIR_TYPE):
        return _decode_dir(raw, inode_type, end)
    if inode_type in (REG_TYPE, LREG_TYPE):
        return _decode_reg(raw, inode_type, end)
    if inode_type in (SYMLINK_TYPE, LSYMLINK_TYPE):
        return _decode_symlink(raw, inode_type, end)
    return {"type": inode_type}


def _decode_dir(raw: bytes, inode_type: int, end: str):
    """
    Decode a basic or extended directory inode.

    Parameters
    ----------
    raw : bytes
        Raw inode bytes.
    inode_type : int
        Inode type code.
    end : str
        Struct endianness prefix.

    Returns
    -------
    dict
        Directory inode fields.
    """
    if inode_type == DIR_TYPE:
        start, _nlink, size, offset = struct.unpack_from(end + "IIHH", raw, 16)
    else:
        start, size, offset = struct.unpack_from(end + "III", raw, 20)[0], 0, 0
        size, offset = struct.unpack_from(end + "HH", raw, 28)
    return {
        "kind": "dir",
        "dir_start": start,
        "dir_offset": offset,
        "size": size,
    }


def _decode_reg(raw: bytes, inode_type: int, end: str):
    """
    Decode a basic or extended regular-file inode.

    Parameters
    ----------
    raw : bytes
        Raw inode bytes.
    inode_type : int
        Inode type code.
    end : str
        Struct endianness prefix.

    Returns
    -------
    dict
        File inode fields.
    """
    start, frag, frag_off, size, sizes_at = _reg_header(raw, inode_type, end)
    return {
        "kind": "file",
        "blocks_start": start,
        "fragment": frag,
        "fragment_offset": frag_off,
        "size": size,
        "block_sizes": _reg_blocks(raw, end, sizes_at, size),
    }


def _reg_header(raw: bytes, inode_type: int, end: str):
    """
    Read the common regular-file inode header fields.

    Parameters
    ----------
    raw : bytes
        Raw inode bytes.
    inode_type : int
        Inode type code.
    end : str
        Struct endianness prefix.

    Returns
    -------
    tuple
        (start, fragment, fragment offset, size, block-size array offset).
    """
    if inode_type == REG_TYPE:
        start, frag, frag_off, size = struct.unpack_from(end + "IIII", raw, 16)
        return start, frag, frag_off, size, 32
    start = struct.unpack_from(end + "Q", raw, 16)[0]
    size = struct.unpack_from(end + "Q", raw, 24)[0]
    frag, frag_off = struct.unpack_from(end + "II", raw, 44)
    return start, frag, frag_off, size, 56


def _reg_blocks(raw: bytes, end: str, sizes_at: int, size: int) -> list:
    """
    Read a regular file's per-block size table.

    Parameters
    ----------
    raw : bytes
        Raw inode bytes.
    end : str
        Struct endianness prefix.
    sizes_at : int
        Offset of the first block-size entry.
    size : int
        File size.

    Returns
    -------
    list
        Block-size entries.
    """
    count = (size + 0x20000 - 1) // 0x20000 if size else 0
    return [
        struct.unpack_from(end + "I", raw, sizes_at + 4 * i)[0]
        for i in range(count)
    ]


def _decode_symlink(raw: bytes, inode_type: int, end: str):
    """
    Decode a basic or extended symlink inode.

    Parameters
    ----------
    raw : bytes
        Raw inode bytes.
    inode_type : int
        Inode type code.
    end : str
        Struct endianness prefix.

    Returns
    -------
    dict
        Symlink inode fields.
    """
    base = 20
    target_size = struct.unpack_from(end + "I", raw, base)[0]
    target = raw[base + 4: base + 4 + target_size].decode("utf-8", "ignore")
    return {"kind": "symlink", "target": target}


def _dir_entries(data: bytes, info: dict, inode: dict):
    """
    Yield directory entries referenced by a directory inode.

    Parameters
    ----------
    data : bytes
        Image bytes.
    info : dict
        Superblock info.
    inode : dict
        Directory inode.

    Yields
    ------
    dict
        Entries with name, inode ref, and type.
    """
    block = info["dir_table"] + inode["dir_start"]
    offset = inode["dir_offset"]
    remaining = [max(0, inode["size"] - 3)]
    for entries in _dir_chunks(data, info, block, offset, remaining):
        yield from entries


def _dir_header(header: bytes, end: str):
    """
    Parse a directory header and its entries.

    Parameters
    ----------
    header : bytes
        Directory buffer.
    end : str
        Struct endianness prefix.

    Returns
    -------
    tuple
        (entries, consumed bytes).
    """
    count, start, base = struct.unpack_from(end + "III", header, 0)
    return _parse_entries(header, 12, count + 1, start, base, end)


def _dir_chunks(
    data: bytes, info: dict, block: int, offset: int, remaining: list
):
    """
    Yield successive batches of directory entries.

    Parameters
    ----------
    data : bytes
        Image bytes.
    info : dict
        Superblock info.
    block : int
        Metadata block offset.
    offset : int
        Offset within the block.
    remaining : list
        Single-element remaining-byte counter.

    Yields
    ------
    list
        Batches of directory entries.
    """
    while remaining[0] > 0:
        header, block, offset = _meta_read(
            data, info, block, offset, remaining[0] + 12
        )
        if len(header) < 12:
            return
        entries, consumed = _dir_header(header, info["endian"])
        remaining[0] -= consumed
        yield entries


def _parse_entries(
    header: bytes, at: int, count: int, start: int, base: int, end: str
):
    """
    Parse directory entries following a directory header.

    Parameters
    ----------
    header : bytes
        Buffer containing the entries.
    at : int
        Start offset.
    count : int
        Number of entries.
    start : int
        Inode metadata block of the entries.
    base : int
        Base inode number.
    end : str
        Struct endianness prefix.

    Returns
    -------
    tuple
        (entries, consumed bytes).
    """
    return _entries_from(header, at, count, (start, base, end))


def _entries_from(header: bytes, pos: int, count: int, context: tuple):
    """
    Parse up to ``count`` directory entries from a buffer.

    Parameters
    ----------
    header : bytes
        Buffer containing the entries.
    pos : int
        Start offset.
    count : int
        Maximum number of entries.
    context : tuple
        (inode block, base inode number, struct endianness).

    Returns
    -------
    tuple
        (entries, consumed end offset).
    """
    entries = []
    for _ in range(count):
        result = _parse_entry(header, pos, context)
        if result is None:
            return entries, pos
        pos, entry = result
        entries.append(entry)
    return entries, pos


def _parse_entry(header: bytes, pos: int, context: tuple):
    """
    Parse one directory entry.

    Parameters
    ----------
    header : bytes
        Buffer containing the entry.
    pos : int
        Entry offset.
    context : tuple
        (inode block, base inode number, struct endianness).

    Returns
    -------
    tuple or None
        (next offset, entry) or None when the buffer is short.
    """
    if pos + 8 > len(header):
        return None
    offset, delta, entry_type, name, next_pos = _entry_raw(
        header, pos, context[2]
    )
    return next_pos, _entry_dict(offset, delta, entry_type, name, context)


def _entry_raw(header: bytes, pos: int, end: str):
    """
    Read the raw fields of one directory entry.

    Parameters
    ----------
    header : bytes
        Buffer containing the entry.
    pos : int
        Entry offset.
    end : str
        Struct endianness prefix.

    Returns
    -------
    tuple
        (offset, delta, type, name, next offset).
    """
    offset, delta, entry_type, name_size = struct.unpack_from(
        end + "HhHH", header, pos
    )
    pos += 8
    name = header[pos: pos + name_size + 1].decode("utf-8", "ignore")
    return offset, delta, entry_type, name, pos + name_size + 1


def _entry_dict(
    offset: int, delta: int, entry_type: int, name: str, context: tuple
) -> dict:
    """
    Build a directory entry dictionary from raw fields.

    Parameters
    ----------
    offset : int
        Entry metadata offset.
    delta : int
        Inode-number delta.
    entry_type : int
        Entry type code.
    name : str
        Entry name.
    context : tuple
        (inode block, base inode number, struct endianness).

    Returns
    -------
    dict
        Directory entry.
    """
    start, base, _end = context
    return {
        "name": name,
        "ref": (start << 16) | offset,
        "number": base + delta,
        "type": entry_type,
    }


def _file_data(data: bytes, info: dict, inode: dict, max_bytes: int) -> bytes:
    """
    Materialize a regular file's contents from data and fragment blocks.

    Parameters
    ----------
    data : bytes
        Image bytes.
    info : dict
        Superblock info.
    inode : dict
        File inode.
    max_bytes : int
        Output cap.

    Returns
    -------
    bytes
        File contents.
    """
    out = bytearray()
    pos = inode["blocks_start"]
    for entry in inode["block_sizes"]:
        pos = _append_block(data, info, out, pos, entry)
    return _apply_fragment(data, info, inode, out)[:max_bytes]


def _append_block(
    data: bytes, info: dict, out: bytearray, pos: int, entry: int
) -> int:
    """
    Append one file data block to the output.

    Parameters
    ----------
    data : bytes
        Image bytes.
    info : dict
        Superblock info.
    out : bytearray
        Accumulated file contents.
    pos : int
        Current data offset.
    entry : int
        Block-size entry.

    Returns
    -------
    int
        Next data offset.
    """
    size = entry & 0xFFFFFF
    if size == 0:
        out += b"\x00" * info["block_size"]
        return pos
    out += _block_bytes(data, info, pos, size, entry)
    return pos + size


def _block_bytes(
    data: bytes, info: dict, pos: int, size: int, entry: int
) -> bytes:
    """
    Read and decompress one on-disk data block.

    Parameters
    ----------
    data : bytes
        Image bytes.
    info : dict
        Superblock info.
    pos : int
        Block offset.
    size : int
        On-disk block size.
    entry : int
        Block-size entry.

    Returns
    -------
    bytes
        Decompressed block bytes.
    """
    raw = data[pos: pos + size]
    if entry & BLOCK_UNCOMPRESSED:
        return raw
    return decompress(info["codec"], raw) or b""


def _apply_fragment(
    data: bytes, info: dict, inode: dict, out: bytearray
) -> bytes:
    """
    Append the tail fragment referenced by a file inode, when present.

    Parameters
    ----------
    data : bytes
        Image bytes.
    info : dict
        Superblock info.
    inode : dict
        File inode.
    out : bytearray
        Accumulated block data.

    Returns
    -------
    bytes
        File contents including the fragment tail.
    """
    entry = _fragment_entry(data, info, inode["fragment"])
    if not entry or inode["fragment"] == 0xFFFFFFFF:
        return bytes(out[: inode["size"]])
    return _fragment_tail(data, info, inode, out, entry)


def _fragment_tail(
    data: bytes, info: dict, inode: dict, out: bytearray, entry: tuple
) -> bytes:
    """
    Append the fragment tail referenced by a file inode.

    Parameters
    ----------
    data : bytes
        Image bytes.
    info : dict
        Superblock info.
    inode : dict
        File inode.
    out : bytearray
        Accumulated block data.
    entry : tuple
        (start offset, size) of the fragment.

    Returns
    -------
    bytes
        File contents including the fragment tail.
    """
    raw = data[entry[0]: entry[0] + entry[1]]
    tail = decompress(info["codec"], raw) or raw
    begin = inode["fragment_offset"]
    return bytes(out) + tail[begin: begin + (inode["size"] - len(out))]


def _fragment_entry(data: bytes, info: dict, index: int):
    """
    Read a fragment entry from the fragment table.

    Parameters
    ----------
    data : bytes
        Image bytes.
    info : dict
        Superblock info.
    index : int
        Fragment index.

    Returns
    -------
    tuple or None
        (start offset, size) of the fragment.
    """
    if not info["fragment_table"] or index * 16 > 1 << 20:
        return None
    start_ref = _fragment_ref(data, info, index)
    if start_ref is None:
        return None
    return _fragment_slice(data, info, start_ref, index)


def _fragment_ref(data: bytes, info: dict, index: int):
    """
    Read the metadata-block reference for a fragment index.

    Parameters
    ----------
    data : bytes
        Image bytes.
    info : dict
        Superblock info.
    index : int
        Fragment index.

    Returns
    -------
    bytes or None
        Eight-byte reference or None.
    """
    start_ref, _b, _o = _meta_read(
        data, info, info["fragment_table"], index * 8, 8
    )
    return start_ref if len(start_ref) >= 8 else None


def _fragment_slice(data: bytes, info: dict, start_ref: bytes, index: int):
    """
    Read the fragment entry referenced by a fragment index.

    Parameters
    ----------
    data : bytes
        Image bytes.
    info : dict
        Superblock info.
    start_ref : bytes
        Metadata-block reference.
    index : int
        Fragment index.

    Returns
    -------
    tuple or None
        (start offset, size) of the fragment.
    """
    meta = info["endian"]
    meta_block = struct.unpack_from(meta + "Q", start_ref, 0)[0]
    entry, _b2, _o2 = _meta_read(
        data, info, meta_block, (index % 512) * 16, 16
    )
    if len(entry) < 16:
        return None
    return (
        struct.unpack_from(meta + "QI", entry, 0)[0],
        struct.unpack_from(meta + "I", entry, 8)[0],
    )


def _walk(
    data: bytes, info: dict, ref: int, prefix: str, depth: int, budget: list
):
    """
    Recursively walk a SquashFS directory tree.

    Parameters
    ----------
    data : bytes
        Image bytes.
    info : dict
        Superblock info.
    ref : int
        Directory inode reference.
    prefix : str
        Path prefix.
    depth : int
        Remaining recursion depth.
    budget : list
        Single-element mutable node counter.

    Yields
    ------
    tuple
        (path, inode) pairs for regular files.
    """
    if depth <= 0 or budget[0] <= 0:
        return
    inode = _inode(data, info, ref)
    if not inode or inode.get("kind") != "dir":
        return
    for entry in _dir_entries(data, info, inode):
        budget[0] -= 1
        yield from _walk_entry(data, info, entry, prefix, depth, budget)


def _walk_entry(
    data: bytes, info: dict, entry: dict, prefix: str, depth: int, budget: list
):
    """
    Yield from a directory entry, recursing into subdirectories.

    Parameters
    ----------
    data : bytes
        Image bytes.
    info : dict
        Superblock info.
    entry : dict
        Directory entry.
    prefix : str
        Path prefix.
    depth : int
        Remaining recursion depth.
    budget : list
        Single-element mutable node counter.

    Yields
    ------
    tuple
        (path, inode) pairs for regular files.
    """
    if entry["name"] in (".", ".."):
        return
    child = _inode(data, info, entry["ref"])
    if not child:
        return
    path = prefix + "/" + entry["name"]
    yield from _walk_child(data, info, entry, child, path, depth, budget)


def _walk_child(
    data: bytes, info: dict, entry: dict, child: dict, path: str, depth: int,
    budget: list,
):
    """
    Recurse into a directory child or yield a regular file.

    Parameters
    ----------
    data : bytes
        Image bytes.
    info : dict
        Superblock info.
    entry : dict
        Directory entry.
    child : dict
        Child inode.
    path : str
        Full child path.
    depth : int
        Remaining recursion depth.
    budget : list
        Single-element mutable node counter.

    Yields
    ------
    tuple
        (path, inode) pairs for regular files.
    """
    if child.get("kind") == "dir":
        yield from _walk(data, info, entry["ref"], path, depth - 1, budget)
    elif child.get("kind") == "file":
        yield path, child


def read_squashfs(
    data: bytes, outdir: str, max_bytes: int = 67108864, depth: int = 16
) -> list:
    """
    Extract a SquashFS v4 image.

    Parameters
    ----------
    data : bytes
        Image bytes.
    outdir : str
        Destination directory.
    max_bytes : int
        Per-file cap.
    depth : int
        Recursion depth cap.

    Returns
    -------
    list
        Manifest entries.
    """
    info = squashfs_info(data)
    if not info or info["version"][0] != 4:
        return []
    return _read_squashfs_tree(data, info, outdir, max_bytes, depth)


def _read_squashfs_tree(
    data: bytes, info: dict, outdir: str, max_bytes: int, depth: int
) -> list:
    """
    Extract every regular file in a SquashFS tree.

    Parameters
    ----------
    data : bytes
        Image bytes.
    info : dict
        Superblock info.
    outdir : str
        Destination directory.
    max_bytes : int
        Per-file cap.
    depth : int
        Recursion depth cap.

    Returns
    -------
    list
        Manifest entries.
    """
    written = []
    budget = [NODE_BUDGET]
    for path, inode in _walk(
        data, info, info["root_inode"], "", depth, budget
    ):
        payload = _file_data(data, info, inode, max_bytes)
        written.append(_write_file(outdir, path, payload, max_bytes))
    return written
