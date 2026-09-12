"""Additional branch tests for firmware readers."""

import io
import struct
import tarfile

from iiatool.firmware import archives, upx


class TestTarDir:
    def test_directory_member_skipped(self, tmp_path):
        buf = io.BytesIO()
        with tarfile.open(fileobj=buf, mode="w") as archive:
            info = tarfile.TarInfo("adir")
            info.type = tarfile.DIRTYPE
            archive.addfile(info)
        assert archives.extract_tar(buf.getvalue(), str(tmp_path)) == []


class TestCpioOld:
    def test_old_name_parse(self):
        header = bytearray(256)
        header[59:65] = b"000004"
        header[65:76] = b"00000000005"
        header[76:80] = b"abc\x00"
        name, size, header_size = archives._cpio_name(bytes(header), False)
        assert name == "abc"
        assert size == 5
        assert header_size == 80


def _rec(extent, size, flags, name):
    """Build an ISO directory record."""
    out = bytearray()
    out += bytes([0, 0])
    out += struct.pack("<I", extent) + struct.pack(">I", extent)
    out += struct.pack("<I", size) + struct.pack(">I", size)
    out += b"\x00" * 7
    out += bytes([flags, 0, 0])
    out += struct.pack("<H", 1) + struct.pack(">H", 1)
    out += bytes([len(name)]) + name
    if len(out) % 2:
        out += b"\x00"
    out[0] = len(out)
    return bytes(out)


class TestIsoNested:
    def _iso(self):
        img = bytearray(24 * 2048)
        root_rec = _rec(20, 2048, 0x02, b"\x00")
        pvd = bytearray(2048)
        pvd[0:7] = b"\x01CD001\x01"
        pvd[156: 156 + len(root_rec)] = root_rec
        img[16 * 2048: 16 * 2048 + 2048] = pvd
        root = _rec(20, 2048, 0x02, b"\x00") + _rec(20, 2048, 0x02, b"\x01")
        root += _rec(21, 2048, 0x02, b"SUB")
        img[20 * 2048: 20 * 2048 + len(root)] = root
        sub = _rec(21, 2048, 0x02, b"\x00") + _rec(21, 2048, 0x02, b"\x01")
        sub += _rec(22, 5, 0x00, b"B.TXT;1")
        img[21 * 2048: 21 * 2048 + len(sub)] = sub
        img[22 * 2048: 22 * 2048 + 5] = b"hello"
        return bytes(img)

    def test_nested_walk(self):
        assert archives.list_iso(self._iso()) == ["/SUB/B.TXT;1"]

    def test_nested_extract(self, tmp_path):
        manifest = archives.extract_iso(self._iso(), str(tmp_path))
        assert manifest[0]["size"] == 5


class TestUpxFields:
    def test_no_valid_window(self):
        assert upx._pack_fields(b"x" * 40, 20) == {}
