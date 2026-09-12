"""UBI erase-block scanning and logical-volume reconstruction.

UBI stacks erase blocks (PEBs) each carrying an EC header and a volume
identifier (VID) header. This module scans PEBs, groups their logical erase
blocks (LEBs) by volume id, orders them, and reconstructs one image per
volume so the contained filesystem can be identified or carved.
"""

import struct

from .archives import _write_file

EC_MAGIC = b"UBI#"
VID_MAGIC = b"UBI!"
INTERNAL_VID = 0x7FF


def ubi_info(data: bytes):
    """
    Parse the first UBI erase-counter header.

    Parameters
    ----------
    data : bytes
        Image bytes.

    Returns
    -------
    dict or None
        EC header fields, or None when the magic is absent.
    """
    if data[:4] != EC_MAGIC or len(data) < 64:
        return None
    return {
        "version": data[4],
        "vid_offset": struct.unpack_from(">I", data, 8)[0],
        "data_offset": struct.unpack_from(">I", data, 12)[0],
        "image_seq": struct.unpack_from(">I", data, 16)[0],
    }


def _vid_header(data: bytes, peb: int, info: dict):
    """
    Parse a VID header within one PEB.

    Parameters
    ----------
    data : bytes
        Image bytes.
    peb : int
        PEB base offset.
    info : dict
        EC header info.

    Returns
    -------
    dict or None
        VID fields.
    """
    at = peb + info["vid_offset"]
    if data[at: at + 4] != VID_MAGIC:
        return None
    vol_id, lnum, size = struct.unpack_from(">III", data, at + 8)
    return {
        "vol_id": vol_id,
        "lnum": lnum,
        "data_size": size,
        "data_at": peb + info["data_offset"],
    }


def _leb_payload(data: bytes, vid: dict) -> bytes:
    """
    Read the payload bytes of one logical erase block.

    Parameters
    ----------
    data : bytes
        Image bytes.
    vid : dict
        VID fields.

    Returns
    -------
    bytes
        Payload bytes.
    """
    start = vid["data_at"]
    return data[start: start + vid["data_size"]]


def read_ubi(data: bytes, outdir: str, max_bytes: int = 67108864) -> list:
    """
    Reconstruct every logical volume in a UBI image.

    Parameters
    ----------
    data : bytes
        Image bytes.
    outdir : str
        Destination directory.
    max_bytes : int
        Per-volume output cap.

    Returns
    -------
    list
        Manifest entries (one per volume).
    """
    info = ubi_info(data)
    if not info:
        return []
    peb_size = _peb_size(data, info)
    volumes = _collect_volumes(data, info, peb_size)
    return _write_volumes(volumes, outdir, max_bytes)


def _peb_size(data: bytes, info: dict) -> int:
    """
    Infer the erase-block size from the image length and data offset.

    Parameters
    ----------
    data : bytes
        Image bytes.
    info : dict
        EC header info.

    Returns
    -------
    int
        PEB size in bytes.
    """
    first = info["data_offset"] + 4
    head = len(data)
    for candidate in (0x20000, 0x1F000, 0x40000, 0x10000, 0x1E000):
        if head % candidate < first:
            return candidate
    return first


def _collect_volumes(data: bytes, info: dict, peb_size: int):
    """
    Group LEB payloads by volume id in logical-number order.

    Parameters
    ----------
    data : bytes
        Image bytes.
    info : dict
        EC header info.
    peb_size : int
        Erase-block size.

    Returns
    -------
    list
        Sorted (vol_id, payload) pairs.
    """
    parts = {}
    for peb in range(0, len(data) - peb_size + 1, peb_size):
        _add_volume_part(parts, data, info, peb)
    return _sorted_volumes(parts)


def _add_volume_part(parts: dict, data: bytes, info: dict, peb: int) -> None:
    """
    Add one PEB's payload to its volume bucket when it is a data PEB.

    Parameters
    ----------
    parts : dict
        Volume id to (lnum, payload) bucket.
    data : bytes
        Image bytes.
    info : dict
        EC header info.
    peb : int
        PEB base offset.

    Returns
    -------
    None
    """
    if data[peb: peb + 4] != EC_MAGIC:
        return
    vid = _vid_header(data, peb, info)
    if not vid or vid["vol_id"] == INTERNAL_VID:
        return
    parts.setdefault(vid["vol_id"], []).append(
        (vid["lnum"], _leb_payload(data, vid))
    )


def _sorted_volumes(parts: dict) -> list:
    """
    Concatenate and order each volume's logical erase blocks.

    Parameters
    ----------
    parts : dict
        Volume id to (lnum, payload) bucket.

    Returns
    -------
    list
        Sorted (vol_id, payload) pairs.
    """
    return sorted(
        (vol, b"".join(payload for _lnum, payload in sorted(chunks)))
        for vol, chunks in parts.items()
    )


def _write_volumes(volumes, outdir: str, max_bytes: int) -> list:
    """
    Write reconstructed volumes to disk.

    Parameters
    ----------
    volumes : list
        (vol_id, payload) pairs.
    outdir : str
        Destination directory.
    max_bytes : int
        Per-volume cap.

    Returns
    -------
    list
        Manifest entries.
    """
    written = []
    for vol_id, payload in volumes:
        name = "ubi-volume-{}.bin".format(vol_id)
        written.append(_write_file(outdir, name, payload, max_bytes))
    return written
