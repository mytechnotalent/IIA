"""Native readers for FAT12/16/32 and ext2/3/4 filesystems.

Both readers parse on-disk structures directly and recover directory trees
without mounting or root. Reads are bounds-checked and extraction reuses the
path-traversal-safe writer from the archive layer.
"""

import struct

from .archives import _write_file


def _u16(data: bytes, offset: int, endian: str = "<") -> int:
    """
    Read an unsigned 16-bit integer.

    Parameters
    ----------
    data : bytes
        Blob.
    offset : int
        Offset.
    endian : str
        Struct endianness prefix.

    Returns
    -------
    int
        Value.
    """
    return struct.unpack_from(endian + "H", data, offset)[0]


def _u32(data: bytes, offset: int, endian: str = "<") -> int:
    """
    Read an unsigned 32-bit integer.

    Parameters
    ----------
    data : bytes
        Blob.
    offset : int
        Offset.
    endian : str
        Struct endianness prefix.

    Returns
    -------
    int
        Value.
    """
    return struct.unpack_from(endian + "I", data, offset)[0]


def _fat_geometry(data: bytes):
    """
    Parse a FAT boot sector into geometry fields.

    Parameters
    ----------
    data : bytes
        Image bytes.

    Returns
    -------
    dict or None
        Geometry, or None when implausible.
    """
    if data[510:512] != b"\x55\xaa":
        return None
    bytes_per_sector = _u16(data, 11)
    if bytes_per_sector not in (512, 1024, 2048, 4096):
        return None
    return {
        "bps": bytes_per_sector,
        "spc": data[13],
        "reserved": _u16(data, 14),
        "fats": data[16],
        "root_entries": _u16(data, 17),
        "fat16_size": _u16(data, 22),
        "total16": _u16(data, 19),
        "fat32_size": _u32(data, 36),
        "total32": _u32(data, 32),
        "root_cluster": _u32(data, 44),
    }


def _fat_total_clusters(geo: dict) -> int:
    """
    Compute the data-cluster count to classify the FAT width.

    Parameters
    ----------
    geo : dict
        Geometry.

    Returns
    -------
    int
        Cluster count.
    """
    root_sectors = (geo["root_entries"] * 32 + geo["bps"] - 1) // geo["bps"]
    fat_size = geo["fat16_size"] or geo["fat32_size"]
    total = geo["total16"] or geo["total32"]
    data_sectors = (
        total - geo["reserved"] - geo["fats"] * fat_size - root_sectors
    )
    return data_sectors // geo["spc"]


def _fat_kind(geo: dict) -> int:
    """
    Classify a volume as FAT12, FAT16, or FAT32.

    Parameters
    ----------
    geo : dict
        Geometry.

    Returns
    -------
    int
        Bits per FAT entry (12, 16, or 32).
    """
    count = _fat_total_clusters(geo)
    if count < 4085:
        return 12
    if count < 65525:
        return 16
    return 32


def _fat_next(data: bytes, geo: dict, bits: int, cluster: int) -> int:
    """
    Follow one FAT entry to the next cluster.

    Parameters
    ----------
    data : bytes
        Image bytes.
    geo : dict
        Geometry.
    bits : int
        FAT width.
    cluster : int
        Current cluster.

    Returns
    -------
    int
        Next cluster (0x0FFFFFFF family sentinel at end of chain).
    """
    fat_start = geo["reserved"] * geo["bps"]
    if bits == 12:
        offset = fat_start + cluster + cluster // 2
        value = _u16(data, offset)
        return (value >> 4) if cluster & 1 else (value & 0x0FFF)
    if bits == 16:
        return _u16(data, fat_start + cluster * 2)
    return _u32(data, fat_start + cluster * 4) & 0x0FFFFFFF


def _cluster_bytes(data: bytes, geo: dict, cluster: int) -> bytes:
    """
    Read the bytes of one data cluster.

    Parameters
    ----------
    data : bytes
        Image bytes.
    geo : dict
        Geometry.
    cluster : int
        Cluster index.

    Returns
    -------
    bytes
        Cluster contents.
    """
    root_sectors = (geo["root_entries"] * 32 + geo["bps"] - 1) // geo["bps"]
    fat_size = geo["fat16_size"] or geo["fat32_size"]
    data_start = (
        geo["reserved"] + geo["fats"] * fat_size + root_sectors
    ) * geo["bps"]
    size = geo["spc"] * geo["bps"]
    offset = data_start + (cluster - 2) * size
    return data[offset: offset + size]


def _fat_end(bits: int) -> int:
    """
    Return the first end-of-chain sentinel for a FAT width.

    Parameters
    ----------
    bits : int
        FAT width (12, 16, or 32).

    Returns
    -------
    int
        Lowest reserved end-of-chain value.
    """
    return {12: 0xFF8, 16: 0xFFF8}.get(bits, 0x0FFFFFF8)


def _fat_chain(data: bytes, geo: dict, bits: int, start: int):
    """
    Collect the cluster chain for a file.

    Parameters
    ----------
    data : bytes
        Image bytes.
    geo : dict
        Geometry.
    bits : int
        FAT width.
    start : int
        First cluster.

    Yields
    ------
    int
        Cluster indices.
    """
    limit = _fat_total_clusters(geo) + 8
    cluster = start
    seen = 0
    while 2 <= cluster < _fat_end(bits) and seen < limit:
        yield cluster
        cluster = _fat_next(data, geo, bits, cluster)
        seen += 1


def _fat_read_chain(data: bytes, geo: dict, bits: int, start: int) -> bytes:
    """
    Read and concatenate a file's cluster chain.

    Parameters
    ----------
    data : bytes
        Image bytes.
    geo : dict
        Geometry.
    bits : int
        FAT width.
    start : int
        First cluster.

    Returns
    -------
    bytes
        File contents.
    """
    chunks = [
        _cluster_bytes(data, geo, c)
        for c in _fat_chain(data, geo, bits, start)
    ]
    return b"".join(chunks)


def _fat_lfn(entry: bytes) -> str:
    """
    Decode one long-filename fragment.

    Parameters
    ----------
    entry : bytes
        32-byte directory entry.

    Returns
    -------
    str
        Partial name fragment in reading order.
    """
    chars = []
    for start, end in ((1, 11), (14, 26), (28, 32)):
        for index in range(start, end, 2):
            code = _u16(entry, index)
            if code in (0x0000, 0xFFFF):
                break
            chars.append(chr(code))
    return "".join(chars)


def _fat_short_name(entry: bytes) -> str:
    """
    Decode an 8.3 short directory name.

    Parameters
    ----------
    entry : bytes
        32-byte directory entry.

    Returns
    -------
    str
        Short name.
    """
    base = entry[0:8].decode("ascii", "ignore").rstrip()
    ext = entry[8:11].decode("ascii", "ignore").rstrip()
    if entry[0] == 0x05:
        base = "\xe5" + base[1:]
    return base + ("." + ext if ext else "")


def _fat_entries(data: bytes, geo: dict, bits: int):
    """
    Yield (name, attr, size, cluster) for every directory entry.

    Parameters
    ----------
    data : bytes
        Image bytes.
    geo : dict
        Geometry.
    bits : int
        FAT width.

    Yields
    ------
    tuple
        Directory entry fields.
    """
    return _fat_iter(_fat_root(data, geo, bits))


def _fat_root(data: bytes, geo: dict, bits: int) -> bytes:
    """
    Read the root directory bytes for a FAT volume.

    Parameters
    ----------
    data : bytes
        Image bytes.
    geo : dict
        Geometry.
    bits : int
        FAT width.

    Returns
    -------
    bytes
        Root directory bytes.
    """
    if bits == 32:
        sectors = list(_fat_chain(data, geo, bits, geo["root_cluster"]))
        return b"".join(_cluster_bytes(data, geo, c) for c in sectors)
    start = _fat_root_start(geo)
    return data[start: start + geo["root_entries"] * 32]


def _fat_root_start(geo: dict) -> int:
    """
    Compute the byte offset of the FAT12/16 root directory.

    Parameters
    ----------
    geo : dict
        Geometry.

    Returns
    -------
    int
        Root directory offset.
    """
    fat_size = geo["fats"] * (geo["fat16_size"] or geo["fat32_size"])
    return (geo["reserved"] + fat_size) * geo["bps"]


def _fat_cluster(entry: bytes) -> int:
    """
    Read the starting cluster of a directory entry.

    Parameters
    ----------
    entry : bytes
        Directory entry.

    Returns
    -------
    int
        Starting cluster.
    """
    return (_u16(entry, 20) << 16) | _u16(entry, 26)


def _fat_record(entry: bytes, lfn: list):
    """
    Interpret one directory entry, updating long-filename state.

    Parameters
    ----------
    entry : bytes
        Directory entry.
    lfn : list
        Accumulated long-filename fragments.

    Returns
    -------
    tuple
        (record or None, new lfn list).
    """
    if entry[0] == 0xE5:
        return None, lfn
    if entry[11] == 0x0F:
        lfn.insert(0, _fat_lfn(entry))
        return None, lfn
    name = "".join(lfn) or _fat_short_name(entry)
    record = (name, entry[11], _u32(entry, 28), _fat_cluster(entry))
    return record, []


def _fat_iter(root: bytes):
    """
    Yield directory records from raw FAT root-directory bytes.

    Parameters
    ----------
    root : bytes
        Root directory bytes.

    Yields
    ------
    tuple
        (name, attr, size, cluster).
    """
    lfn = []
    for offset in range(0, len(root), 32):
        entry = root[offset: offset + 32]
        if len(entry) < 32 or entry[0] == 0x00:
            return
        record, lfn = _fat_record(entry, lfn)
        if record is not None:
            yield record


def read_fat(data: bytes, outdir: str, max_bytes: int = 67108864) -> list:
    """
    Extract a FAT12/16/32 image.

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
    geo = _fat_geometry(data)
    if not geo:
        return []
    return _read_fat_tree(data, geo, _fat_kind(geo), outdir, max_bytes)


def _read_fat_tree(
    data: bytes, geo: dict, bits: int, outdir: str, max_bytes: int
) -> list:
    """
    Extract every regular file in a FAT root directory.

    Parameters
    ----------
    data : bytes
        Image bytes.
    geo : dict
        Geometry.
    bits : int
        FAT width.
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
    for entry in _fat_entries(data, geo, bits):
        item = _fat_file(data, geo, bits, entry, outdir, max_bytes)
        if item:
            written.append(item)
    return written


def _fat_file(data: bytes, geo: dict, bits: int, entry: tuple, outdir: str,
              max_bytes: int):
    """
    Extract one FAT directory entry, or None for directories/volumes.

    Parameters
    ----------
    data : bytes
        Image bytes.
    geo : dict
        Geometry.
    bits : int
        FAT width.
    entry : tuple
        (name, attr, size, cluster).
    outdir : str
        Destination directory.
    max_bytes : int
        Per-file cap.

    Returns
    -------
    dict or None
        Manifest entry.
    """
    name, attr, size, cluster = entry
    if attr & 0x08 or attr & 0x10:
        return None
    payload = _fat_read_chain(data, geo, bits, cluster)[:size][:max_bytes]
    return _write_file(outdir, name, payload, max_bytes)


def _ext_superblock(data: bytes):
    """
    Parse an ext2/3/4 superblock.

    Parameters
    ----------
    data : bytes
        Image bytes.

    Returns
    -------
    dict or None
        Superblock fields, or None when implausible.
    """
    if data[1024 + 56: 1024 + 58] != b"\x53\xef":
        return None
    return {
        "inodes": _u32(data, 1024),
        "blocks": _u32(data, 1024 + 4),
        "log_block": _u32(data, 1024 + 24),
        "blocks_per_group": _u32(data, 1024 + 32),
        "inodes_per_group": _u32(data, 1024 + 40),
        "magic": _u16(data, 1024 + 56),
        "rev": _u32(data, 1024 + 76),
        "first_ino": _u32(data, 1024 + 84),
        "inode_size": _u16(data, 1024 + 88),
        "desc_size": _u16(data, 1024 + 254) if _u32(data, 1024 + 76) else 32,
    }


def _ext_block_size(sb: dict) -> int:
    """
    Compute the filesystem block size from its shift.

    Parameters
    ----------
    sb : dict
        Superblock.

    Returns
    -------
    int
        Block size in bytes.
    """
    return 1024 << sb["log_block"]


def _ext_group_desc(data: bytes, sb: dict, group: int, blk: int) -> dict:
    """
    Read a block-group descriptor.

    Parameters
    ----------
    data : bytes
        Image bytes.
    sb : dict
        Superblock.
    group : int
        Group index.
    blk : int
        Block size.

    Returns
    -------
    dict
        Inode table location.
    """
    table_block = 2 if blk == 1024 else 1
    rec = sb["desc_size"] or 32
    offset = table_block * blk + group * rec
    return {"inode_table": _u32(data, offset + 8)}


def _ext_inode(data: bytes, sb: dict, blk: int, ino: int):
    """
    Read an ext2/3/4 inode.

    Parameters
    ----------
    data : bytes
        Image bytes.
    sb : dict
        Superblock.
    blk : int
        Block size.
    ino : int
        Inode number.

    Returns
    -------
    dict or None
        Inode fields.
    """
    if ino < 1:
        return None
    offset = _ext_inode_offset(data, sb, blk, ino)
    size = sb["inode_size"] or 128
    if offset + size > len(data):
        return None
    return _ext_inode_fields(data, offset)


def _ext_inode_offset(data: bytes, sb: dict, blk: int, ino: int) -> int:
    """
    Compute the byte offset of an inode.

    Parameters
    ----------
    data : bytes
        Image bytes.
    sb : dict
        Superblock.
    blk : int
        Block size.
    ino : int
        Inode number.

    Returns
    -------
    int
        Inode byte offset.
    """
    group = (ino - 1) // sb["inodes_per_group"]
    index = (ino - 1) % sb["inodes_per_group"]
    desc = _ext_group_desc(data, sb, group, blk)
    return desc["inode_table"] * blk + index * (sb["inode_size"] or 128)


def _ext_inode_fields(data: bytes, offset: int) -> dict:
    """
    Parse the fields of an ext inode at a byte offset.

    Parameters
    ----------
    data : bytes
        Image bytes.
    offset : int
        Inode byte offset.

    Returns
    -------
    dict
        Inode fields.
    """
    mode = _u16(data, offset)
    blocks = [_u32(data, offset + 40 + 4 * i) for i in range(15)]
    return {
        "mode": mode,
        "size": _u32(data, offset + 4),
        "blocks": blocks,
        "is_dir": (mode & 0xF000) == 0x4000,
    }


def _ext_read_inode(data: bytes, sb: dict, blk: int, inode: dict) -> bytes:
    """
    Read the full content of an inode given its direct/indirect block list.

    Parameters
    ----------
    data : bytes
        Image bytes.
    sb : dict
        Superblock.
    blk : int
        Block size.
    inode : dict
        Inode.

    Returns
    -------
    bytes
        File content (bounded to the declared size).
    """
    chunks = []
    for pointer in inode["blocks"][:12]:
        if pointer:
            chunks.append(data[pointer * blk: pointer * blk + blk])
    chunks.append(_ext_indirect(data, sb, blk, inode["blocks"][12], 1))
    chunks.append(_ext_indirect(data, sb, blk, inode["blocks"][13], 2))
    return b"".join(chunks)[: inode["size"]]


def _ext_indirect(
    data: bytes, sb: dict, blk: int, pointer: int, depth: int
) -> bytes:
    """
    Recursively read single/double/triple indirect blocks.

    Parameters
    ----------
    data : bytes
        Image bytes.
    sb : dict
        Superblock.
    blk : int
        Block size.
    pointer : int
        Indirect block number.
    depth : int
        Remaining indirection depth.

    Returns
    -------
    bytes
        Collected content.
    """
    if not pointer or depth <= 0:
        return b""
    table = data[pointer * blk: (pointer + 1) * blk]
    chunks = []
    for off in range(0, len(table), 4):
        child = _u32(table, off)
        chunks.append(_ext_indirect_chunk(data, sb, blk, child, depth))
    return b"".join(chunks)


def _ext_indirect_chunk(
    data: bytes, sb: dict, blk: int, child: int, depth: int
) -> bytes:
    """
    Read one indirect-table child block or recurse further.

    Parameters
    ----------
    data : bytes
        Image bytes.
    sb : dict
        Superblock.
    blk : int
        Block size.
    child : int
        Child block number.
    depth : int
        Remaining indirection depth.

    Returns
    -------
    bytes
        Collected content.
    """
    if depth == 1:
        return data[child * blk: child * blk + blk] if child else b""
    return _ext_indirect(data, sb, blk, child, depth - 1)


def _ext_dir_entries(data: bytes, sb: dict, blk: int, inode: dict):
    """
    Parse directory entries from a directory inode.

    Parameters
    ----------
    data : bytes
        Image bytes.
    sb : dict
        Superblock.
    blk : int
        Block size.
    inode : dict
        Directory inode.

    Yields
    ------
    tuple
        (name, inode_number) pairs.
    """
    content = _ext_read_inode(data, sb, blk, inode)
    return _ext_scan(content)


def _ext_dirent(content: bytes, offset: int):
    """
    Parse one ext directory entry.

    Parameters
    ----------
    content : bytes
        Directory content.
    offset : int
        Entry offset.

    Returns
    -------
    tuple or None
        (name, inode, record length), or None when rec_len is invalid.
    """
    ino = _u32(content, offset)
    rec_len = _u16(content, offset + 4)
    if rec_len < 8:
        return None
    name_len = content[offset + 6]
    name = content[offset + 8: offset + 8 + name_len].decode("utf-8", "ignore")
    return name, ino, rec_len


def _ext_scan(content: bytes):
    """
    Yield valid ext directory entries.

    Parameters
    ----------
    content : bytes
        Directory content.

    Yields
    ------
    tuple
        (name, inode) pairs.
    """
    offset = 0
    while offset + 8 <= len(content):
        entry = _ext_dirent(content, offset)
        if entry is None:
            return
        if entry[1] and entry[0] not in (".", ".."):
            yield entry[0], entry[1]
        offset += entry[2]


def _ext_walk(data: bytes, sb: dict, blk: int, ino: int, prefix: str):
    """
    Recursively walk an ext directory tree.

    Parameters
    ----------
    data : bytes
        Image bytes.
    sb : dict
        Superblock.
    blk : int
        Block size.
    ino : int
        Directory inode number.
    prefix : str
        Path prefix.

    Yields
    ------
    tuple
        (path, inode_number, inode) for regular files.
    """
    inode = _ext_inode(data, sb, blk, ino)
    if inode is None:
        return
    for name, child in _ext_dir_entries(data, sb, blk, inode):
        yield from _ext_child(data, sb, blk, child, name, prefix)


def _ext_child(data: bytes, sb: dict, blk: int, child: int, name: str,
               prefix: str):
    """
    Yield a file record or recurse into a child directory.

    Parameters
    ----------
    data : bytes
        Image bytes.
    sb : dict
        Superblock.
    blk : int
        Block size.
    child : int
        Child inode number.
    name : str
        Entry name.
    prefix : str
        Path prefix.

    Yields
    ------
    tuple
        (path, inode_number, inode) for regular files.
    """
    child_inode = _ext_inode(data, sb, blk, child)
    if child_inode is None:
        return
    path = prefix + "/" + name
    if child_inode["is_dir"]:
        yield from _ext_walk(data, sb, blk, child, path)
    else:
        yield path, child, child_inode


def read_ext(data: bytes, outdir: str, max_bytes: int = 67108864) -> list:
    """
    Extract an ext2/3/4 image.

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
    sb = _ext_superblock(data)
    if not sb:
        return []
    return _read_ext_tree(data, sb, _ext_block_size(sb), outdir, max_bytes)


def _read_ext_tree(
    data: bytes, sb: dict, blk: int, outdir: str, max_bytes: int
) -> list:
    """
    Extract every regular file in an ext tree.

    Parameters
    ----------
    data : bytes
        Image bytes.
    sb : dict
        Superblock.
    blk : int
        Block size.
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
    for path, _ino, inode in _ext_walk(data, sb, blk, 2, ""):
        payload = _ext_read_inode(data, sb, blk, inode)[:max_bytes]
        written.append(_write_file(outdir, path, payload, max_bytes))
    return written
