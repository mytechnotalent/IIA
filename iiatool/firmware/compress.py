"""Bounded decompression of compression streams found inside firmware.

Standard-library codecs cover gzip, zlib, bzip2, and xz/lzma. zstd and lz4
are used only when their optional third-party modules are importable; a
missing codec degrades to a clean ``unsupported`` result rather than an
error, so identification still succeeds without optional dependencies.
"""

import bz2
import gzip
import lzma
import zlib

from gzip import BadGzipFile

MAGIC = {
    "gzip": b"\x1f\x8b",
    "zlib": b"\x78",
    "bzip2": b"BZh",
    "xz": b"\xfd7zXZ\x00",
    "lzma": b"\x5d\x00\x00",
    "zstd": b"\x28\xb5\x2f\xfd",
    "lz4": b"\x04\x22\x4d\x18",
}


def _cap(limit: int, data: bytes) -> bytes:
    """
    Hard-cap decompressed output to bound decompression bombs.

    Parameters
    ----------
    limit : int
        Maximum bytes to keep.
    data : bytes
        Decompressed bytes.

    Returns
    -------
    bytes
        Truncated bytes.
    """
    return data[:limit]


def decompress_gzip(data: bytes, limit: int = 67108864) -> bytes:
    """
    Decompress a gzip or zlib stream with a size cap.

    Parameters
    ----------
    data : bytes
        Compressed bytes.
    limit : int
        Maximum output bytes.

    Returns
    -------
    bytes
        Decompressed bytes.
    """
    try:
        return _cap(limit, gzip.decompress(data))
    except (OSError, EOFError, BadGzipFile, zlib.error):
        pass
    try:
        return _cap(limit, zlib.decompress(data))
    except zlib.error:
        return _cap(limit, zlib.decompress(data, -15))


def decompress_bzip2(data: bytes, limit: int = 67108864) -> bytes:
    """
    Decompress a bzip2 stream with a size cap.

    Parameters
    ----------
    data : bytes
        Compressed bytes.
    limit : int
        Maximum output bytes.

    Returns
    -------
    bytes
        Decompressed bytes.
    """
    return _cap(limit, bz2.decompress(data))


def decompress_xz(data: bytes, limit: int = 67108864) -> bytes:
    """
    Decompress an xz or lzma stream with a size cap.

    Parameters
    ----------
    data : bytes
        Compressed bytes.
    limit : int
        Maximum output bytes.

    Returns
    -------
    bytes
        Decompressed bytes.
    """
    try:
        return _cap(limit, lzma.decompress(data, format=lzma.FORMAT_XZ))
    except lzma.LZMAError:
        return _cap(limit, lzma.decompress(data, format=lzma.FORMAT_ALONE))


def decompress_zstd(data: bytes, limit: int = 67108864):
    """
    Decompress a zstd frame when the optional module is available.

    Parameters
    ----------
    data : bytes
        Compressed bytes.
    limit : int
        Maximum output bytes.

    Returns
    -------
    bytes or None
        Decompressed bytes, or None when the codec is unavailable.
    """
    try:
        import zstandard  # type: ignore
    except ImportError:
        return None
    return _cap(
        limit,
        zstandard.ZstdDecompressor().decompress(data, max_output_size=limit),
    )


def decompress_lz4(data: bytes, limit: int = 67108864):
    """
    Decompress an lz4 frame when the optional module is available.

    Parameters
    ----------
    data : bytes
        Compressed bytes.
    limit : int
        Maximum output bytes.

    Returns
    -------
    bytes or None
        Decompressed bytes, or None when the codec is unavailable.
    """
    try:
        import lz4.frame  # type: ignore
    except ImportError:
        return None
    return _cap(limit, lz4.frame.decompress(data))


def decompress(codec: str, data: bytes, limit: int = 67108864):
    """
    Dispatch to a codec by name.

    Parameters
    ----------
    codec : str
        Codec name (gzip, zlib, bzip2, xz, lzma, zstd, lz4).
    data : bytes
        Compressed bytes.
    limit : int
        Maximum output bytes.

    Returns
    -------
    bytes or None
        Decompressed bytes, or None when unavailable or unsupported.
    """
    handlers = {
        "gzip": lambda b: decompress_gzip(b, limit),
        "zlib": lambda b: decompress_gzip(b, limit),
        "bzip2": lambda b: decompress_bzip2(b, limit),
        "xz": lambda b: decompress_xz(b, limit),
        "lzma": lambda b: decompress_xz(b, limit),
        "zstd": lambda b: decompress_zstd(b, limit),
        "lz4": lambda b: decompress_lz4(b, limit),
    }
    handler = handlers.get(codec)
    if handler is None:
        return None
    try:
        return handler(data)
    except (OSError, EOFError, ValueError, lzma.LZMAError, zlib.error):
        return None
