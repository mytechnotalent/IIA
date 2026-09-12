"""Tests for tar, zip, cpio, and ISO 9660 handling."""

import io
import struct
import tarfile
import zipfile

import pytest

from iiatool.firmware import archives


def _tar_bytes(name: str, payload: bytes) -> bytes:
    """
    Build an in-memory tar archive.

    Parameters
    ----------
    name : str
        Member name.
    payload : bytes
        Member content.

    Returns
    -------
    bytes
        Tar archive bytes.
    """
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w") as archive:
        info = tarfile.TarInfo(name)
        info.size = len(payload)
        archive.addfile(info, io.BytesIO(payload))
    return buf.getvalue()


def _zip_bytes(name: str, payload: bytes) -> bytes:
    """
    Build an in-memory zip archive.

    Parameters
    ----------
    name : str
        Member name.
    payload : bytes
        Member content.

    Returns
    -------
    bytes
        Zip archive bytes.
    """
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as archive:
        archive.writestr(name, payload)
    return buf.getvalue()


def _field(value: int, width: int = 8) -> bytes:
    """
    Render a cpio newc hexadecimal field.

    Parameters
    ----------
    value : int
        Field value.
    width : int
        Field width in characters.

    Returns
    -------
    bytes
        ASCII field.
    """
    return "{:0{}x}".format(value, width).encode()


def _cpio_bytes(name: str, payload: bytes) -> bytes:
    """
    Build a cpio newc archive.

    Parameters
    ----------
    name : str
        Member name.
    payload : bytes
        Member content.

    Returns
    -------
    bytes
        Cpio archive bytes.
    """
    body = name.encode() + b"\x00"
    header = b"070701"
    for value in (
        0,
        0o100644,
        0,
        0,
        1,
        0,
        len(payload),
        0,
        0,
        0,
        0,
        len(body),
        0,
    ):
        header += _field(value)
    out = header + body
    out += b"\x00" * (-len(out) % 4)
    out += payload
    out += b"\x00" * (-len(payload) % 4)
    trailer = (
        b"070701" + _field(0) * 11 + _field(11) + _field(0) + b"TRAILER!!!\x00"
    )
    out += trailer + b"\x00" * (-len(trailer) % 4)
    return out


def _iso_record(extent: int, size: int, flags: int, name: bytes) -> bytes:
    """
    Build one ISO 9660 directory record.

    Parameters
    ----------
    extent : int
        Extent sector.
    size : int
        Data size.
    flags : int
        Entry flags.
    name : bytes
        Entry name (without terminator).

    Returns
    -------
    bytes
        Directory record.
    """
    rec = bytearray()
    rec += bytes([0, 0])
    rec += struct.pack("<I", extent)
    rec += struct.pack(">I", extent)
    rec += struct.pack("<I", size)
    rec += struct.pack(">I", size)
    rec += b"\x00" * 7
    rec += bytes([flags, 0, 0])
    rec += struct.pack("<H", 1)
    rec += struct.pack(">H", 1)
    rec += bytes([len(name)])
    rec += name
    if len(rec) % 2:
        rec += b"\x00"
    rec[0] = len(rec)
    return bytes(rec)


def _iso_bytes(payload: bytes) -> bytes:
    """
    Build a minimal ISO 9660 image with a single file.

    Parameters
    ----------
    payload : bytes
        File content.

    Returns
    -------
    bytes
        ISO image bytes.
    """
    img = bytearray(24 * 2048)
    root = _iso_record(20, 2048, 0x02, b"\x00")
    pvd = bytearray(2048)
    pvd[0:7] = b"\x01CD001\x01"
    pvd[156: 156 + len(root)] = root
    img[16 * 2048: 16 * 2048 + 2048] = pvd
    dot = _iso_record(20, 2048, 0x02, b"\x00")
    dotdot = _iso_record(20, 2048, 0x02, b"\x01")
    data = _iso_record(23, len(payload), 0x00, b"A.TXT;1")
    directory = (dot + dotdot + data).ljust(2048, b"\x00")
    img[20 * 2048: 20 * 2048 + 2048] = directory
    img[23 * 2048: 23 * 2048 + len(payload)] = payload
    return bytes(img)


class TestTar:
    def test_list_and_extract(self, tmp_path):
        data = _tar_bytes("dir/a.txt", b"hello")
        assert "dir/a.txt" in archives.list_tar(data)
        manifest = archives.extract_tar(data, str(tmp_path))
        assert manifest[0]["size"] == 5

    def test_unsafe_member_rejected(self, tmp_path):
        data = _tar_bytes("../escape.txt", b"x")
        with pytest.raises(ValueError):
            archives.extract_tar(data, str(tmp_path))


class TestZip:
    def test_list_and_extract(self, tmp_path):
        data = _zip_bytes("a.txt", b"hello")
        assert "a.txt" in archives.list_zip(data)
        manifest = archives.extract_zip(data, str(tmp_path))
        assert manifest[0]["member"] == "a.txt"

    def test_directory_entries_skipped(self, tmp_path):
        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w") as archive:
            archive.writestr("dir/", b"")
            archive.writestr("dir/a.txt", b"hi")
        manifest = archives.extract_zip(buf.getvalue(), str(tmp_path))
        assert len(manifest) == 1


class TestCpio:
    def test_list_and_extract(self, tmp_path):
        data = _cpio_bytes("a.txt", b"hello")
        assert archives.list_cpio(data) == ["a.txt"]
        manifest = archives.extract_cpio(data, str(tmp_path))
        assert manifest[0]["size"] == 5

    def test_invalid_magic(self):
        assert archives.list_cpio(b"not a cpio archive") == []


class TestIso:
    def test_list_and_extract(self, tmp_path):
        data = _iso_bytes(b"hello")
        assert archives.list_iso(data) == ["/A.TXT;1"]
        manifest = archives.extract_iso(data, str(tmp_path))
        assert manifest[0]["size"] == 5

    def test_no_root(self):
        assert archives.list_iso(b"\x00" * 4096) == []


class TestSafeJoin:
    def test_inside_root(self, tmp_path):
        assert archives.safe_join(str(tmp_path), "a/b").startswith(
            str(tmp_path)
        )

    def test_absolute_stripped(self, tmp_path):
        assert archives.safe_join(str(tmp_path), "/a").endswith("a")
