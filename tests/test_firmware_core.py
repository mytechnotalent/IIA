"""Tests for entropy, carving, UPX detection, compression, and signatures."""

import bz2
import gzip
import lzma
import struct
import tarfile
import zipfile

import pytest

from iiatool.firmware import carve, compress, entropy, signatures, upx

HIGH = bytes(range(256)) * 32


class TestEntropy:
    def test_shannon_empty(self):
        assert entropy._shannon(b"") == 0.0

    def test_shannon_uniform(self):
        assert entropy._shannon(b"\x00\x00\x00\x00") == 0.0

    def test_shannon_maximal(self):
        assert entropy._shannon(bytes(range(256))) == 8.0

    def test_windows_stops_on_partial(self):
        rows = list(entropy._windows(b"x" * 300, 128, 128))
        assert len(rows) == 2

    def test_merge_regions(self):
        rows = [
            {"offset": 0, "size": 16, "entropy": 7.9},
            {"offset": 16, "size": 16, "entropy": 7.8},
            {"offset": 32, "size": 16, "entropy": 1.0},
        ]
        regions = entropy._merge(rows, 7.5)
        assert len(regions) == 1
        assert regions[0]["start"] == 0
        assert regions[0]["end"] == 32

    def test_merge_trailing_region(self):
        rows = [{"offset": 0, "size": 8, "entropy": 7.9}]
        assert entropy._merge(rows, 7.5)[0]["end"] == 8

    def test_entropy_pass_high(self):
        result = entropy.entropy_pass(HIGH, size=256, step=256, threshold=7.5)
        assert result["overall_entropy"] == 8.0
        assert result["regions"]

    def test_entropy_pass_low(self):
        result = entropy.entropy_pass(b"\x00" * 4096, threshold=7.5)
        assert result["regions"] == []

    def test_extend_existing(self):
        current = {"start": 0, "end": 8, "peak": 7.6}
        grown = entropy._extend(
            current, {"offset": 8, "size": 8, "entropy": 7.9}
        )
        assert grown["end"] == 16
        assert grown["peak"] == 7.9


class TestCarve:
    def test_carve_writes_regions(self, tmp_path):
        data = b"A" * 100 + b"B" * 100
        findings = [
            {"offset": 0, "type": "alpha"},
            {"offset": 100, "type": "beta"},
        ]
        manifest = carve.carve_findings(data, findings, str(tmp_path))
        assert len(manifest) == 2
        assert manifest[0]["size"] == 100
        assert manifest[1]["size"] == 100

    def test_safe_label(self):
        assert carve._safe("we/?ird") == "we_ird"

    def test_empty_label(self):
        assert carve._safe("//") == "region"

    def test_skips_empty_range(self):
        assert list(carve._regions([{"offset": 5, "type": "x"}], 5)) == []


class TestUpx:
    def test_not_packed(self):
        assert upx.detect_upx(b"MZ" + b"\x00" * 500)["packed"] is False

    def _packed(self):
        header = struct.pack("<IIIIIBBBBII", 1, 2, 3, 4, 5, 0, 0, 0, 5, 1, 2)
        trailer = b"UPX!" + b"\x00" * 8
        return b"\x00" * 16 + header + b"payload" + trailer

    def test_packed_detected(self):
        result = upx.detect_upx(self._packed())
        assert result["packed"] is True
        assert result["marker_offset"] > 0
        assert result["zeroed_header"] is True

    def test_host_format_elf(self):
        assert upx._host_format(b"\x7fELFxxxx") == "ELF"

    def test_host_format_unknown(self):
        assert upx._host_format(b"zzzz") == "unknown"

    def test_decode_header_rejects_level(self):
        window = struct.pack("<IIIIII", 1, 2, 3, 4, 5, 6)
        window = window[:23] + bytes([99]) + b"\x00" * 8
        assert upx._decode_header(window) is None

    def test_decode_header_short(self):
        assert upx._decode_header(b"\x00" * 10) is None

    def test_candidate_windows(self):
        data = b"x" * 40 + b"UPX!" + b"y" * 40
        windows = list(upx._candidate_windows(data, 40))
        assert windows


class TestCompress:
    def test_gzip_roundtrip(self):
        payload = b"hello firmware" * 100
        assert compress.decompress_gzip(gzip.compress(payload)) == payload

    def test_zlib_roundtrip(self):
        import zlib

        payload = b"zlib data" * 50
        assert compress.decompress_gzip(zlib.compress(payload)) == payload

    def test_bzip2_roundtrip(self):
        payload = b"bzip data" * 50
        assert compress.decompress_bzip2(bz2.compress(payload)) == payload

    def test_xz_roundtrip(self):
        payload = b"xz data" * 50
        assert compress.decompress_xz(lzma.compress(payload)) == payload

    def test_lzma_alone_roundtrip(self):
        payload = b"lzma data" * 50
        blob = lzma.compress(payload, format=lzma.FORMAT_ALONE)
        assert compress.decompress_xz(blob) == payload

    def test_dispatch_all(self):
        payload = b"dispatch" * 20
        assert compress.decompress("gzip", gzip.compress(payload)) == payload
        assert compress.decompress("bzip2", bz2.compress(payload)) == payload
        assert compress.decompress("xz", lzma.compress(payload)) == payload

    def test_dispatch_unknown(self):
        assert compress.decompress("nope", b"x") is None

    def test_dispatch_bad_data(self):
        assert compress.decompress("gzip", b"not compressed") is None

    def test_zstd_roundtrip(self):
        zstandard = pytest.importorskip("zstandard")
        payload = b"zstd data" * 20
        blob = zstandard.ZstdCompressor().compress(payload)
        assert compress.decompress_zstd(blob) == payload

    def test_lz4_roundtrip(self):
        lz4_frame = pytest.importorskip("lz4.frame")
        payload = b"lz4 data" * 20
        blob = lz4_frame.compress(payload)
        assert compress.decompress_lz4(blob) == payload

    def test_optional_codecs_missing(self, monkeypatch):
        import builtins

        real_import = builtins.__import__

        def blocked(name, *args, **kwargs):
            if name in ("zstandard", "lz4.frame"):
                raise ImportError(name)
            return real_import(name, *args, **kwargs)

        monkeypatch.setattr(builtins, "__import__", blocked)
        assert compress.decompress_zstd(b"junk") is None
        assert compress.decompress_lz4(b"junk") is None

    def test_cap(self):
        assert compress._cap(2, b"abcdef") == b"ab"


class TestSignatures:
    def test_scan_gzip(self):
        data = gzip.compress(b"x" * 100)
        types = {f["type"] for f in signatures.scan_bytes(data)}
        assert "gzip" in types

    def test_scan_xz(self):
        data = lzma.compress(b"x" * 100)
        assert "xz" in {f["type"] for f in signatures.scan_bytes(data)}

    def test_scan_zip(self):
        import io

        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w") as archive:
            archive.writestr("a.txt", "hi")
        types = {f["type"] for f in signatures.scan_bytes(buf.getvalue())}
        assert "zip" in types

    def test_scan_tar(self):
        import io

        buf = io.BytesIO()
        with tarfile.open(fileobj=buf, mode="w") as archive:
            info = tarfile.TarInfo("a.txt")
            payload = b"hello"
            info.size = len(payload)
            archive.addfile(info, io.BytesIO(payload))
        types = {f["type"] for f in signatures.scan_bytes(buf.getvalue())}
        assert "tar" in types

    @pytest.mark.parametrize(
        "magic,expected",
        [
            (b"hsqs" + b"\x00" * 28, "squashfs-le"),
            (b"sqsh" + b"\x00" * 28, "squashfs-be"),
            (b"UBI#" + b"\x00" * 60, "ubi"),
            (b"XFSB" + b"\x00" * 100, "xfs"),
            (b"\x7fELF" + b"\x00" * 100, "elf"),
            (b"ANDROID!" + b"\x00" * 100, "android boot"),
        ],
    )
    def test_fixed_magics(self, magic, expected):
        types = {f["type"] for f in signatures.scan_bytes(magic)}
        assert expected in types

    def test_ext_validator_rejects_bad_shift(self):
        data = bytearray(4096)
        data[1080:1082] = b"\x53\xef"
        struct.pack_into("<I", data, 1080 + 24, 99)
        assert signatures._valid_ext(bytes(data), 0) is False

    def test_ext_validator_accepts(self):
        data = bytearray(4096)
        data[1080:1082] = b"\x53\xef"
        struct.pack_into("<I", data, 1080 + 24, 3)
        assert signatures._valid_ext(bytes(data), 0) is True

    def test_cramfs_validator(self):
        data = bytearray(200)
        data[:4] = b"\x45\x3d\xcd\x28"
        struct.pack_into("<I", data, 12, 150)
        assert signatures._valid_cramfs(bytes(data), 0) is True
        struct.pack_into("<I", data, 12, 0)
        assert signatures._valid_cramfs(bytes(data), 0) is False

    def test_squashfs_validator(self):
        data = bytearray(64)
        data[:4] = b"hsqs"
        struct.pack_into("<H", data, 28, 4)
        assert signatures._valid_squashfs(bytes(data), 0) is True
        struct.pack_into("<H", data, 28, 9)
        assert signatures._valid_squashfs(bytes(data), 0) is False

    def test_tar_checksum_none(self):
        assert signatures._tar_checksum(b"\x00" * 512) is None

    def test_tar_checksum_invalid(self):
        header = bytearray(512)
        header[148:156] = b"0000000\x00"
        assert signatures._tar_checksum(bytes(header)) is None

    def test_iso_validator(self):
        assert signatures._valid_iso(b"\x01", 1) is True
        assert signatures._valid_iso(b"\x05", 1) is False

    def test_crc32(self):
        assert signatures._crc32(b"") == 0

    def test_primary_empty(self):
        assert signatures._primary([]) is None

    def test_dedupe_keeps_strongest(self):
        rows = [
            {"offset": 0, "type": "a", "confidence": 0.5, "source": "x"},
            {"offset": 0, "type": "a", "confidence": 0.9, "source": "y"},
        ]
        assert signatures._dedupe(rows)[0]["confidence"] == 0.9

    def test_scan_file(self, tmp_path):
        target = tmp_path / "fw.bin"
        target.write_bytes(gzip.compress(b"z" * 50))
        result = signatures.scan_file(str(target))
        assert result["primary"]["type"] == "gzip"

    def test_scan_file_broad(self, tmp_path):
        target = tmp_path / "a.png"
        target.write_bytes(b"\x89PNG\r\n\x1a\n" + b"\x00" * 20)
        result = signatures.scan_file(str(target), broad=True)
        assert "png" in {f["type"] for f in result["findings"]}
