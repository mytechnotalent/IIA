"""Tests for U-Boot, Android sparse/boot, and device-tree containers."""

import gzip
import struct
import zlib

from iiatool.firmware import containers


def _uimage(payload: bytes, comp: int = 1, name: bytes = b"test") -> bytes:
    """
    Build a U-Boot legacy image.

    Parameters
    ----------
    payload : bytes
        Image payload.
    comp : int
        Compression code.
    name : bytes
        Image name.

    Returns
    -------
    bytes
        U-Boot image bytes.
    """
    dcrc = zlib.crc32(payload) & 0xFFFFFFFF
    header = struct.pack(">IIIII", 0x27051956, 0, 0, len(payload), 0)
    header += struct.pack(">II", 0, dcrc)
    header += bytes([5, 7, 2, comp])
    header += name.ljust(32, b"\x00")
    hcrc = zlib.crc32(header) & 0xFFFFFFFF
    header = header[:4] + struct.pack(">I", hcrc) + header[8:]
    return header + payload


def _sparse(raw: bytes, blk: int = 4096) -> bytes:
    """
    Build an Android sparse image with one raw chunk.

    Parameters
    ----------
    raw : bytes
        Raw image bytes.
    blk : int
        Block size.

    Returns
    -------
    bytes
        Sparse image bytes.
    """
    blocks = max(1, len(raw) // blk)
    raw = raw.ljust(blocks * blk, b"\x00")
    header = struct.pack(
        "<IHHHHIIII", 0xED26FF3A, 1, 0, 28, 12, blk, blocks, 1, 0
    )
    chunk = struct.pack("<HHII", 0xCAC1, 0, blocks, blocks * blk) + raw
    return header + chunk


def _boot(kernel: bytes, ramdisk: bytes = b"", page: int = 2048) -> bytes:
    """
    Build a minimal Android boot image (header version 0).

    Parameters
    ----------
    kernel : bytes
        Kernel payload.
    ramdisk : bytes
        Ramdisk payload.
    page : int
        Page size.

    Returns
    -------
    bytes
        Boot image bytes.
    """
    header = b"ANDROID!"
    header += struct.pack("<III", len(kernel), len(ramdisk), 0)
    header += struct.pack("<IIII", 0, 0, 0, 0)
    header += struct.pack("<I", page)
    header += struct.pack("<II", 0, 0)
    header = header.ljust(page, b"\x00")
    body = kernel.ljust(-(-len(kernel) // page) * page, b"\x00")
    body += ramdisk.ljust(-(-len(ramdisk) // page) * page, b"\x00")
    return header + body


def _fdt(value: bytes) -> bytes:
    """
    Build a minimal flattened device tree with one ``data`` property.

    Parameters
    ----------
    value : bytes
        Property value.

    Returns
    -------
    bytes
        FDT bytes.
    """
    struct_block = struct.pack(">I", 1) + b"images\x00".ljust(8, b"\x00")
    padded = value + b"\x00" * (-len(value) % 4)
    struct_block += struct.pack(">III", 3, len(value), 0) + padded
    struct_block += struct.pack(">I", 2) + struct.pack(">I", 9)
    strings = b"data\x00"
    off_mem = 40
    off_struct = off_mem + 16
    off_strings = off_struct + len(struct_block)
    total = off_strings + len(strings)
    header = struct.pack(
        ">IIIIIIIIII",
        0xD00DFEED,
        total,
        off_struct,
        off_strings,
        off_mem,
        17,
        16,
        0,
        len(strings),
        len(struct_block),
    )
    return header + b"\x00" * 16 + struct_block + strings


class TestUimage:
    def test_info_none(self):
        assert containers.uimage_info(b"nope") is None

    def test_info_fields(self):
        info = containers.uimage_info(_uimage(gzip.compress(b"k")))
        assert info["type"] == "kernel"
        assert info["compression"] == "gzip"

    def test_extract_gzip(self, tmp_path):
        data = _uimage(gzip.compress(b"kernel-data"))
        manifest = containers.extract_uimage(data, str(tmp_path))
        assert manifest[0]["size"] == len(b"kernel-data")

    def test_extract_uncompressed(self, tmp_path):
        data = _uimage(b"raw-kernel", comp=0)
        manifest = containers.extract_uimage(data, str(tmp_path))
        assert manifest[0]["size"] == len(b"raw-kernel")

    def test_extract_bad(self, tmp_path):
        assert containers.extract_uimage(b"junk", str(tmp_path)) == []


class TestSparse:
    def test_header_none(self):
        assert containers._sparse_header(b"junk") is None

    def test_expand_raw(self, tmp_path):
        raw = b"a" * 4096
        manifest = containers.extract_sparse(_sparse(raw), str(tmp_path))
        assert manifest[0]["size"] >= 4096

    def test_fill_and_dontcare(self, tmp_path):
        header = struct.pack(
            "<IHHHHIIII", 0xED26FF3A, 1, 0, 28, 12, 4096, 2, 2, 0
        )
        fill = struct.pack("<HHII", 0xCAC2, 0, 1, 4) + b"\xff\xff\xff\xff"
        dont = struct.pack("<HHII", 0xCAC3, 0, 1, 0)
        data = header + fill + dont
        manifest = containers.extract_sparse(data, str(tmp_path))
        assert manifest[0]["size"] >= 8192

    def test_unknown_chunk_type(self):
        assert containers._sparse_chunk(b"", 0, 0x9999, 1, 0, 4096) == b""


class TestAndroidBoot:
    def test_sizes(self):
        sizes = containers._boot_sizes(_boot(b"K" * 10))
        assert sizes["kernel"] == 10

    def test_extract(self, tmp_path):
        data = _boot(b"KERNEL", b"RAMDISK")
        manifest = containers.extract_android_boot(data, str(tmp_path))
        names = {entry["member"] for entry in manifest}
        assert {"kernel.bin", "ramdisk.bin"} <= names

    def test_not_boot(self, tmp_path):
        assert containers.extract_android_boot(b"junk", str(tmp_path)) == []


class TestFdt:
    def test_properties(self):
        props = dict(containers.fdt_properties(_fdt(b"HELLO")))
        assert props["data"] == b"HELLO"

    def test_extract_fit(self, tmp_path):
        manifest = containers.extract_fit(_fdt(b"IMAGE!"), str(tmp_path))
        assert manifest[0]["size"] == 6

    def test_extract_fit_bad(self, tmp_path):
        assert containers.extract_fit(b"junk", str(tmp_path)) == []

    def test_fdt_strings(self):
        data = _fdt(b"X")
        strings_off = struct.unpack_from(">I", data, 12)[0]
        assert containers._fdt_strings(data, strings_off, 0).startswith("data")
