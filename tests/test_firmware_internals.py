"""Branch-level tests for firmware parser internals."""

import gzip
import struct

import pytest

from iiatool.firmware import (
    archives,
    containers,
    extract,
    filesystems,
    jffs2,
    signatures,
    squashfs,
    ubi,
)


def _sb(codec: int = 1, fragment_table: int = 0) -> bytearray:
    """
    Build a minimal valid SquashFS superblock buffer.

    Parameters
    ----------
    codec : int
        Compression id.
    fragment_table : int
        Fragment table offset.

    Returns
    -------
    bytearray
        Superblock bytes.
    """
    sb = bytearray(96)
    sb[0:4] = b"hsqs"
    struct.pack_into("<I", sb, 12, 4096)
    struct.pack_into("<H", sb, 20, codec)
    struct.pack_into("<Q", sb, 80, fragment_table)
    return sb


class TestFatInternals:
    def test_geometry_bad_bps(self):
        data = bytearray(512)
        struct.pack_into("<H", data, 11, 999)
        data[510:512] = b"\x55\xaa"
        assert filesystems._fat_geometry(bytes(data)) is None

    def test_kind_fat16(self):
        geo = {
            "bps": 512,
            "spc": 1,
            "reserved": 1,
            "fats": 2,
            "root_entries": 0,
            "fat16_size": 100,
            "total16": 20000,
            "fat32_size": 0,
            "total32": 0,
            "root_cluster": 0,
        }
        assert filesystems._fat_kind(geo) == 16

    def test_kind_fat32(self):
        geo = {
            "bps": 512,
            "spc": 1,
            "reserved": 1,
            "fats": 2,
            "root_entries": 0,
            "fat16_size": 0,
            "total16": 0,
            "fat32_size": 100,
            "total32": 90000,
            "root_cluster": 0,
        }
        assert filesystems._fat_kind(geo) == 32

    def test_next_fat16(self):
        data = bytearray(4096)
        struct.pack_into("<H", data, 512 + 2 * 2, 0x1234)
        geo = {"reserved": 1, "bps": 512}
        assert filesystems._fat_next(data, geo, 16, 2) == 0x1234

    def test_next_fat32(self):
        data = bytearray(4096)
        struct.pack_into("<I", data, 512 + 2 * 4, 0x0ABCDEF)
        geo = {"reserved": 1, "bps": 512}
        assert filesystems._fat_next(data, geo, 32, 2) == 0x0ABCDEF

    def test_lfn_terminators(self):
        entry = bytearray(32)
        struct.pack_into("<H", entry, 1, 0x0000)
        assert "".join(filesystems._fat_lfn(entry)) == ""

    def test_entries_lfn_and_specials(self):
        data = bytearray(4096)
        geo = {
            "bps": 512,
            "spc": 1,
            "reserved": 1,
            "fats": 2,
            "root_entries": 16,
            "fat16_size": 1,
            "total16": 12,
            "fat32_size": 0,
            "total32": 0,
            "root_cluster": 0,
        }
        root = 1536
        lfn = bytearray(32)
        lfn[0] = 0x41
        lfn[11] = 0x0F
        struct.pack_into("<H", lfn, 1, ord("Z"))
        data[root: root + 32] = lfn
        deleted = bytearray(32)
        deleted[0] = 0xE5
        data[root + 32: root + 64] = deleted
        short = bytearray(32)
        short[0:11] = b"B       TXT"
        short[11] = 0x20
        data[root + 64: root + 96] = short
        data[root + 96] = 0x00
        entries = list(filesystems._fat_entries(bytes(data), geo, 12))
        assert any(name.startswith("Z") for name, *_ in entries)

    def test_read_chain_fat16(self):
        data = bytearray(8192)
        geo = {
            "bps": 512,
            "spc": 1,
            "reserved": 1,
            "fats": 2,
            "root_entries": 0,
            "fat16_size": 1,
            "total16": 20000,
            "fat32_size": 0,
            "total32": 0,
            "root_cluster": 2,
        }
        assert filesystems._fat_read_chain(data, geo, 16, 2) == b"\x00" * 512


class TestExtInternals:
    def test_inode_out_of_bounds(self):
        data = bytearray(3000)
        struct.pack_into("<I", data, 2048 + 8, 100000)
        sb = {"inodes_per_group": 16, "inode_size": 128, "desc_size": 32}
        assert filesystems._ext_inode(bytes(data), sb, 1024, 2) is None

    def test_indirect_depth_two(self):
        blk = 1024
        data = bytearray(8 * blk)
        struct.pack_into("<I", data, 5 * blk, 6)
        struct.pack_into("<I", data, 6 * blk, 7)
        data[7 * blk: 7 * blk + 3] = b"abc"
        assert (
            filesystems._ext_indirect(bytes(data), {}, blk, 5, 2)[:3] == b"abc"
        )

    def test_dir_entries_bad_rec_len(self):
        sb = {"inode_size": 128, "inodes_per_group": 16, "desc_size": 32}
        inode = {"kind": "dir", "size": 16, "blocks": [5] * 15, "is_dir": True}
        data = bytearray(20 * 1024)
        struct.pack_into("<I", data, 5 * 1024, 2)
        assert (
            list(filesystems._ext_dir_entries(bytes(data), sb, 1024, inode))
            == []
        )


class TestSquashfsInternals:
    def test_decode_inode_unknown(self):
        raw = struct.pack("<H", 99) + b"\x00" * 30
        assert squashfs._decode_inode(raw, 99, "<") == {"type": 99}

    def test_decode_dir_extended(self):
        raw = bytearray(40)
        struct.pack_into("<I", raw, 20, 0)
        struct.pack_into("<HH", raw, 28, 20, 0)
        result = squashfs._decode_dir(bytes(raw), 8, "<")
        assert result["size"] == 20

    def test_decode_reg_extended(self):
        raw = bytearray(64)
        struct.pack_into("<Q", raw, 16, 96)
        struct.pack_into("<Q", raw, 24, 5)
        struct.pack_into("<II", raw, 44, 0xFFFFFFFF, 0)
        struct.pack_into("<I", raw, 56, 0x1000000 | 5)
        result = squashfs._decode_reg(bytes(raw), 9, "<")
        assert result["size"] == 5

    def test_meta_block_compressed(self):
        data = bytes(_sb()) + struct.pack("<H", len(gzip.compress(b"meta")))
        data += gzip.compress(b"meta")
        block, nxt = squashfs._meta_block(data, 96, "<")
        assert block == b"meta"

    def test_file_data_compressed_and_zero(self):
        info = squashfs.squashfs_info(bytes(_sb()))
        comp = gzip.compress(b"hello")
        data = bytes(_sb()) + comp
        inode = {
            "blocks_start": 96,
            "block_sizes": [len(comp)],
            "size": 5,
            "fragment": 0xFFFFFFFF,
            "fragment_offset": 0,
        }
        assert squashfs._file_data(data, info, inode, 1024) == b"hello"
        inode["block_sizes"] = [0]
        assert (
            squashfs._file_data(data, info, inode, 1024)[:4]
            == b"\x00\x00\x00\x00"
        )

    def _fragment_image(self):
        f, m = 200, 300
        data = bytearray(_sb(fragment_table=f))
        data += b"ABCDE"
        data += b"\x00" * (f - len(data))
        data += struct.pack("<H", 0x8000 | 8) + struct.pack("<Q", m)
        data += b"\x00" * (m - len(data))
        entry = struct.pack("<QI", 96, 5) + struct.pack("<I", 0)
        data += struct.pack("<H", 0x8000 | len(entry)) + entry
        return bytes(data)

    def test_fragment_entry(self):
        data = self._fragment_image()
        info = squashfs.squashfs_info(data)
        assert squashfs._fragment_entry(data, info, 0) == (96, 5)

    def test_fragment_entry_absent(self):
        info = squashfs.squashfs_info(bytes(_sb()))
        assert squashfs._fragment_entry(bytes(_sb()), info, 0) is None

    def test_apply_fragment(self):
        data = self._fragment_image()
        info = squashfs.squashfs_info(data)
        inode = {"fragment": 0, "fragment_offset": 0, "size": 5}
        assert (
            squashfs._apply_fragment(data, info, inode, bytearray())
            == b"ABCDE"
        )

    def test_walk_missing_inode(self):
        info = squashfs.squashfs_info(bytes(_sb()))
        assert list(squashfs._walk(bytes(_sb()), info, 0, "", 4, [10])) == []


class TestJffs2Internals:
    def test_endian_little(self):
        assert jffs2._endian(b"\x85\x19", 0) == "<"

    def test_endian_none(self):
        assert jffs2._endian(b"zz", 0) is None

    def test_iter_skips_garbage_and_padding(self):
        node = b"\x19\x85" + struct.pack(">HI", 0x2004, 12) + b"\x00" * 4
        data = b"zzzz" + node
        assert list(jffs2.iter_nodes(data)) == []

    def test_iter_unknown_type(self):
        node = b"\x19\x85" + struct.pack(">HI", 0x9999, 12) + b"\x00" * 4
        assert list(jffs2.iter_nodes(node)) == []

    def test_iter_invalid_totlen(self):
        node = b"\x19\x85" + struct.pack(">HI", 0xE001, 2) + b"\x00" * 4
        assert list(jffs2.iter_nodes(node)) == []

    def test_parse_inode_with_data(self):
        body = struct.pack(">I", 2) + struct.pack(">I", 0)
        body += struct.pack(">I", 0o100644) + struct.pack(">HH", 0, 0)
        body += struct.pack(">I", 5) + struct.pack(">III", 0, 0, 0)
        body += struct.pack(">I", 0) + struct.pack(">II", 5, 5)
        body += bytes([0, 0]) + struct.pack(">H", 0) + b"hello"
        node = b"\x19\x85" + struct.pack(">H", 0xE002)
        node += struct.pack(">I", 12 + len(body)) + b"\x00" * 4 + body
        parsed = jffs2._parse_inode(node, 0, ">")
        assert parsed["payload"] == b"hello"

    def test_path_recursion(self):
        dirents = [
            {"kind": "dirent", "pino": 1, "ino": 2, "name": "d", "dtype": 4},
            {"kind": "dirent", "pino": 2, "ino": 3, "name": "f", "dtype": 8},
        ]
        assert jffs2._path_for(3, dirents) == "/d/f"

    def test_path_depth_guard(self):
        dirents = [
            {"kind": "dirent", "pino": 3, "ino": 3, "name": "x", "dtype": 4}
        ]
        assert jffs2._path_for(3, dirents, 99) == ""


class TestSignatureInternals:
    def test_apply_validator_reject(self):
        assert (
            signatures._apply_validator("ext", b"\x00" * 100, 0, 0.9) == -1.0
        )

    def test_apply_validator_missing(self):
        assert signatures._apply_validator("unknown", b"", 0, 0.5) == 0.5

    def test_valid_gzip(self):
        assert signatures._valid_gzip(b"", 0) is True

    def test_valid_uimage(self):
        assert signatures._valid_uimage(b"\x00" * 100, 0) is False

    def test_valid_squashfs_short(self):
        assert signatures._valid_squashfs(b"hsqs", 0) is False

    def test_find_all_limit(self):
        data = b"aaaa"
        assert len(list(signatures._find_all(data, b"a", 2))) == 2

    def test_scan_searchable_limit(self):
        data = b"\x1f\x8b\x08" * 3
        found = signatures._scan_searchable(
            data, (("gzip", b"\x1f\x8b\x08", 0.5),), 1
        )
        assert len(found) == 1

    def test_scan_file_missing(self):
        assert signatures.scan_file("/nonexistent")["findings"] == []


class TestUbiInternals:
    def test_vid_header_none(self):
        info = {"vid_offset": 64, "data_offset": 128}
        assert ubi._vid_header(b"\x00" * 200, 0, info) is None

    def test_leb_payload(self):
        assert (
            ubi._leb_payload(b"abcdef", {"data_at": 1, "data_size": 3})
            == b"bcd"
        )

    def test_peb_size_fallback(self):
        info = {"data_offset": 128}
        assert ubi._peb_size(b"\x00" * 100, info) >= 132

    def test_collect_skips_internal(self):
        data = bytearray(0x20000)
        data[0:4] = b"UBI#"
        struct.pack_into(">I", data, 8, 64)
        struct.pack_into(">I", data, 12, 128)
        data[64:68] = b"UBI!"
        struct.pack_into(">I", data, 72, 0x7FF)
        info = ubi.ubi_info(bytes(data))
        assert ubi._collect_volumes(bytes(data), info, 0x20000) == []


class TestContainerInternals:
    def test_decode_header_valid(self):
        window = bytearray(struct.pack("<IIIIII", 1, 2, 3, 4, 5, 0))
        window[23] = 3
        window += b"\x00" * 4
        assert upx_fields(bytes(window))["level"] == 3

    def test_boot_page(self):
        assert containers._boot_page(1, 2048) == 2048

    def test_boot_sizes_none(self):
        assert containers._boot_sizes(b"junk") is None

    def test_sparse_expand_bounds(self):
        header = {
            "blk": 4096,
            "total_blks": 1,
            "chunks": 5,
            "chunk_hdr": 12,
            "file_hdr": 28,
        }
        assert containers._sparse_expand(b"\x00" * 28, header, 4096) == b""

    def test_fdt_properties_bad(self):
        assert list(containers.fdt_properties(b"junk")) == []


def upx_fields(window):
    """
    Decode a PackHeader window through the UPX module.

    Parameters
    ----------
    window : bytes
        Candidate window.

    Returns
    -------
    dict
        Parsed fields.
    """
    from iiatool.firmware import upx

    return upx._decode_header(window)


class TestArchiveInternals:
    def test_iso_record_zero(self):
        assert archives._iso_record(b"\x00" * 64, 0) is None

    def test_extract_iso_no_root(self, tmp_path):
        assert archives.extract_iso(b"\x00" * 4096, str(tmp_path)) == []

    def test_safe_join_escape(self, tmp_path):
        with pytest.raises(ValueError):
            archives.safe_join(str(tmp_path), "../evil")


class TestExtractInternals:
    def test_container_start(self):
        assert extract._container_start({"type": "tar", "offset": 257}) == 0
        assert extract._container_start({"type": "gzip", "offset": 9}) == 9

    def test_run_handler_exception(self, tmp_path, monkeypatch):
        def boom(data, outdir, max_bytes):
            raise OSError("nope")

        monkeypatch.setitem(extract.REGISTRY, "gzip", boom)
        state = {"depth": 1, "files": 0, "bytes": 0}
        assert extract._run({"type": "gzip"}, b"x", str(tmp_path), state) == []

    def test_write_manifest_error(self, tmp_path, monkeypatch):
        monkeypatch.setattr("os.path.join", lambda *a: "/nonexistent/dir/x")
        extract._write_manifest(str(tmp_path), {"entries": []})
