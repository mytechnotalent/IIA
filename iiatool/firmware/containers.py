"""Kernel and boot containers: U-Boot uImage, FIT/FDT, Android boot/sparse."""

import struct

from .archives import _write_file
from .compress import decompress

UIMAGE_MAGIC = 0x27051956
FDT_MAGIC = 0xD00DFEED
SPARSE_MAGIC = 0xED26FF3A
BOOT_MAGIC = b"ANDROID!"

_COMP = {
    0: None,
    1: "gzip",
    2: "bzip2",
    3: "lzma",
    4: "lzo",
    5: "lz4",
    6: "zstd",
}
_OS = {0: "invalid", 1: "openbsd", 2: "netbsd", 3: "freebsd", 5: "linux"}
_ARCH = {2: "arm", 3: "x86", 5: "mips", 7: "arm64", 22: "arm64", 26: "riscv"}
_TYPE = {2: "kernel", 3: "ramdisk", 4: "multi", 5: "firmware", 7: "script"}


def uimage_info(data: bytes) -> dict:
    """
    Parse a U-Boot legacy image header.

    Parameters
    ----------
    data : bytes
        Image bytes.

    Returns
    -------
    dict or None
        Header fields, or None when the magic is absent.
    """
    if len(data) < 64 or struct.unpack_from(">I", data, 0)[0] != UIMAGE_MAGIC:
        return None
    size = struct.unpack_from(">I", data, 12)[0]
    comp = data[31]
    return {
        "data_size": size,
        "compression": _COMP.get(comp, "unknown({})".format(comp)),
        "os": _OS.get(data[28], "?"),
        "arch": _ARCH.get(data[29], "?"),
        "type": _TYPE.get(data[30], "?"),
        "name": data[32:64].split(b"\x00")[0].decode("utf-8", "ignore"),
        "payload_offset": 64,
    }


def extract_uimage(
    data: bytes, outdir: str, max_bytes: int = 67108864
) -> list:
    """
    Extract the payload of a U-Boot legacy image.

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
    info = uimage_info(data)
    if not info:
        return []
    body = _uimage_body(data, info, max_bytes)
    name = "{}-{}.bin".format(info["type"], info["arch"])
    return [_write_file(outdir, name, body, max_bytes)]


def _uimage_body(data: bytes, info: dict, max_bytes: int) -> bytes:
    """
    Decompress the payload of a U-Boot legacy image.

    Parameters
    ----------
    data : bytes
        Image bytes.
    info : dict
        Parsed header.
    max_bytes : int
        Output cap.

    Returns
    -------
    bytes
        Payload bytes.
    """
    start = info["payload_offset"]
    payload = data[start: start + info["data_size"]]
    codec = info["compression"]
    raw = decompress(codec, payload) if codec in _COMP.values() else payload
    return (raw if raw is not None else payload)[:max_bytes]


def _fdt_tokens(data: bytes, base: int):
    """
    Yield structure tokens from a flattened device tree.

    Parameters
    ----------
    data : bytes
        Blob.
    base : int
        Offset of the struct block.

    Yields
    ------
    tuple
        (token, offset, length, nameoff).
    """
    pos = base
    while pos + 4 <= len(data):
        pos, emitted, done = _fdt_step(data, pos)
        if emitted is not None:
            yield emitted
        if done:
            return


def _fdt_step(data: bytes, pos: int):
    """
    Process one flattened-device-tree structure token.

    Parameters
    ----------
    data : bytes
        Blob.
    pos : int
        Token offset.

    Returns
    -------
    tuple
        (next offset, emitted token tuple or None, done flag).
    """
    token = struct.unpack_from(">I", data, pos)[0]
    pos += 4
    if token == 1:
        return _fdt_begin(data, pos), (token, pos, 0, 0), False
    if token == 3:
        return _fdt_prop(data, pos, token)
    return pos, None, token != 4


def _fdt_begin(data: bytes, pos: int) -> int:
    """
    Skip a device-tree node name and return the aligned next offset.

    Parameters
    ----------
    data : bytes
        Blob.
    pos : int
        Name offset.

    Returns
    -------
    int
        Aligned offset after the name.
    """
    return (data.index(b"\x00", pos) + 4) & ~3


def _fdt_prop(data: bytes, pos: int, token: int):
    """
    Parse a device-tree property token.

    Parameters
    ----------
    data : bytes
        Blob.
    pos : int
        Offset after the token.
    token : int
        Token value.

    Returns
    -------
    tuple
        (next offset, emitted tuple, done flag).
    """
    length, nameoff = struct.unpack_from(">II", data, pos)
    pos += 8
    return (pos + length + 3) & ~3, (token, pos, length, nameoff), False


def _fdt_strings(data: bytes, strings_off: int, nameoff: int) -> str:
    """
    Resolve a device-tree property name from the strings block.

    Parameters
    ----------
    data : bytes
        Blob.
    strings_off : int
        Offset of the strings block.
    nameoff : int
        Name offset within the block.

    Returns
    -------
    str
        Property name.
    """
    start = strings_off + nameoff
    end = data.index(b"\x00", start)
    return data[start:end].decode("utf-8", "ignore")


def fdt_properties(data: bytes):
    """
    Yield (name, value) property pairs from a flattened device tree.

    Parameters
    ----------
    data : bytes
        Blob.

    Yields
    ------
    tuple
        (property name, value bytes) pairs.
    """
    if len(data) < 40 or struct.unpack_from(">I", data, 0)[0] != FDT_MAGIC:
        return
    struct_off, strings_off = struct.unpack_from(">II", data, 8)
    for token, offset, length, nameoff in _fdt_tokens(data, struct_off):
        if token != 3:
            continue
        name = _fdt_strings(data, strings_off, nameoff)
        yield name, data[offset: offset + length]


def extract_fit(data: bytes, outdir: str, max_bytes: int = 67108864) -> list:
    """
    Extract image payloads from a U-Boot FIT device tree.

    Parameters
    ----------
    data : bytes
        FIT bytes.
    outdir : str
        Destination directory.
    max_bytes : int
        Per-file cap.

    Returns
    -------
    list
        Manifest entries.
    """
    if struct.unpack_from(">I", data, 0)[0] != FDT_MAGIC:
        return []
    return _fit_images(data, outdir, max_bytes)


def _fit_images(data: bytes, outdir: str, max_bytes: int) -> list:
    """
    Extract every ``data`` property of a FIT image to disk.

    Parameters
    ----------
    data : bytes
        FIT bytes.
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
    index = 0
    for name, value in fdt_properties(data):
        if name != "data" or not value:
            continue
        index += 1
        written.append(
            _write_file(
                outdir, "fit-image-{}.bin".format(index), value, max_bytes
            )
        )
    return written


def extract_sparse(
    data: bytes, outdir: str, max_bytes: int = 67108864
) -> list:
    """
    Expand an Android sparse image to a raw image file.

    Parameters
    ----------
    data : bytes
        Sparse image bytes.
    outdir : str
        Destination directory.
    max_bytes : int
        Output cap.

    Returns
    -------
    list
        Manifest entries.
    """
    header = _sparse_header(data)
    if not header:
        return []
    raw = _sparse_expand(data, header, max_bytes)
    return [_write_file(outdir, "sparse-raw.img", raw, max_bytes)]


def _sparse_header(data: bytes):
    """
    Parse an Android sparse image header.

    Parameters
    ----------
    data : bytes
        Image bytes.

    Returns
    -------
    dict or None
        Header fields.
    """
    if len(data) < 28 or struct.unpack_from("<I", data, 0)[0] != SPARSE_MAGIC:
        return None
    blk, total_blks, chunks = struct.unpack_from("<III", data, 12)
    return {
        "blk": blk,
        "total_blks": total_blks,
        "chunks": chunks,
        "chunk_hdr": struct.unpack_from("<H", data, 10)[0],
        "file_hdr": struct.unpack_from("<H", data, 8)[0],
    }


def _sparse_expand(data: bytes, header: dict, max_bytes: int) -> bytes:
    """
    Walk sparse chunks and materialize the raw image.

    Parameters
    ----------
    data : bytes
        Sparse bytes.
    header : dict
        Parsed header.
    max_bytes : int
        Output cap.

    Returns
    -------
    bytes
        Raw image bytes.
    """
    out = bytearray()
    pos = header["file_hdr"]
    for _ in range(header["chunks"]):
        if pos + 12 > len(data) or len(out) >= max_bytes:
            break
        pos = _append_sparse(out, data, header, pos)
    return bytes(out[:max_bytes])


def _append_sparse(out: bytearray, data: bytes, header: dict, pos: int) -> int:
    """
    Append one sparse chunk to the output and return the next offset.

    Parameters
    ----------
    out : bytearray
        Accumulated raw image.
    data : bytes
        Sparse bytes.
    header : dict
        Parsed header.
    pos : int
        Chunk header offset.

    Returns
    -------
    int
        Next chunk header offset.
    """
    ctype, _res, count, total = struct.unpack_from("<HHII", data, pos)
    body = pos + header["chunk_hdr"]
    out += _sparse_chunk(data, body, ctype, count, total, header["blk"])
    return body + total


def _sparse_chunk(
    data: bytes, body: int, ctype: int, count: int, total: int, blk: int
) -> bytes:
    """
    Materialize one sparse chunk.

    Parameters
    ----------
    data : bytes
        Sparse bytes.
    body : int
        Chunk body offset.
    ctype : int
        Chunk type.
    count : int
        Block count.
    total : int
        Total chunk bytes.
    blk : int
        Block size.

    Returns
    -------
    bytes
        Chunk bytes.
    """
    if ctype == 0xCAC1:
        return data[body: body + count * blk]
    if ctype == 0xCAC2:
        fill = data[body: body + 4] or b"\x00"
        return fill * (count * blk // len(fill))
    if ctype == 0xCAC3:
        return b"\x00" * (count * blk)
    return b""


def _boot_sizes(data: bytes):
    """
    Parse kernel/ramdisk/second/dtb sizes from an Android boot image.

    Parameters
    ----------
    data : bytes
        Boot image bytes.

    Returns
    -------
    dict or None
        Sizes and page size.
    """
    if data[:8] != BOOT_MAGIC:
        return None
    kernel, ramdisk, second = struct.unpack_from("<III", data, 8)
    page = struct.unpack_from("<I", data, 36)[0] or 2048
    return {
        "kernel": kernel,
        "ramdisk": ramdisk,
        "second": second,
        "page": page,
        "dtb": (
            struct.unpack_from("<I", data, 40)[0] if len(data) >= 1632 else 0
        ),
    }


def extract_android_boot(
    data: bytes, outdir: str, max_bytes: int = 67108864
) -> list:
    """
    Extract kernel, ramdisk, second stage, and dtb from an Android boot image.

    Parameters
    ----------
    data : bytes
        Boot image bytes.
    outdir : str
        Destination directory.
    max_bytes : int
        Per-file cap.

    Returns
    -------
    list
        Manifest entries.
    """
    sizes = _boot_sizes(data)
    if not sizes:
        return []
    return _boot_payloads(data, sizes, outdir, max_bytes)


def _boot_payloads(
    data: bytes, sizes: dict, outdir: str, max_bytes: int
) -> list:
    """
    Extract each page-aligned payload from an Android boot image.

    Parameters
    ----------
    data : bytes
        Boot image bytes.
    sizes : dict
        Parsed payload sizes.
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
    pos = sizes["page"]
    for label in ("kernel", "ramdisk", "second", "dtb"):
        size = sizes[label]
        if size:
            written.append(
                _boot_write(data, pos, size, label, outdir, max_bytes)
            )
        pos = _boot_page(pos + size, sizes["page"])
    return written


def _boot_write(
    data: bytes, pos: int, size: int, label: str, outdir: str, max_bytes: int
) -> dict:
    """
    Write one Android boot payload to disk.

    Parameters
    ----------
    data : bytes
        Boot image bytes.
    pos : int
        Payload offset.
    size : int
        Payload size.
    label : str
        Payload label.
    outdir : str
        Destination directory.
    max_bytes : int
        Payload cap.

    Returns
    -------
    dict
        Manifest entry.
    """
    payload = data[pos: pos + size][:max_bytes]
    return _write_file(outdir, label + ".bin", payload, max_bytes)


def _boot_page(value: int, page: int) -> int:
    """
    Round a boot-image offset up to a page boundary.

    Parameters
    ----------
    value : int
        Raw offset.
    page : int
        Page size.

    Returns
    -------
    int
        Page-aligned offset.
    """
    return (value + page - 1) // page * page
