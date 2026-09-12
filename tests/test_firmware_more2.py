"""More branch tests for firmware internals (ubi, fat, ext, jffs2)."""

import struct

from iiatool.firmware import containers, filesystems, jffs2, ubi


class TestFdtTokens:
    def _block(self, with_nop):
        buf = bytearray()
        if with_nop:
            buf += struct.pack(">I", 4)
        buf += struct.pack(">I", 1) + b"n\x00\x00\x00"
        buf += (
            struct.pack(">I", 3)
            + struct.pack(">II", 1, 0)
            + b"\x00\x00\x00\x00"
        )
        buf += struct.pack(">I", 9)
        return bytes(buf)

    def test_nop_and_end(self):
        tokens = list(containers._fdt_tokens(self._block(True), 0))
        assert any(t[0] == 3 for t in tokens)

    def test_end_only(self):
        tokens = list(containers._fdt_tokens(self._block(False), 0))
        assert any(t[0] == 3 for t in tokens)


class TestFitSkip:
    def _fdt(self):
        struct_block = struct.pack(">I", 1) + b"images\x00".ljust(8, b"\x00")
        struct_block += struct.pack(">III", 3, 4, 0) + b"\x00\x00\x00\x00"
        struct_block += struct.pack(">I", 2) + struct.pack(">I", 9)
        strings = b"other\x00"
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

    def test_other_property_skipped(self, tmp_path):
        assert containers.extract_fit(self._fdt(), str(tmp_path)) == []


class TestSparseInvalid:
    def test_invalid(self, tmp_path):
        assert containers.extract_sparse(b"junk", str(tmp_path)) == []


class TestUbiEdges:
    def test_peb_size_fallback(self):
        assert ubi._peb_size(b"\x00" * 12345, {"data_offset": 128}) == 132

    def test_collect_skips_non_ubi(self):
        info = {"vid_offset": 64, "data_offset": 128}
        assert ubi._collect_volumes(b"\x00" * 0x20000, info, 0x20000) == []


class TestFatEdges:
    def test_short_name_e5(self):
        entry = bytearray(32)
        entry[0] = 0x05
        entry[1:8] = b"BCDEFGH"
        assert filesystems._fat_short_name(entry).startswith("\xe5")

    def test_entries_fat32(self):
        geo = {
            "bps": 512,
            "spc": 1,
            "reserved": 1,
            "fats": 2,
            "root_entries": 0,
            "fat16_size": 0,
            "fat32_size": 1,
            "total16": 0,
            "total32": 90000,
            "root_cluster": 2,
        }
        data = bytearray(4096)
        struct.pack_into("<I", data, 512 + 2 * 4, 0x0FFFFFF8)
        entry = bytearray(32)
        entry[0:11] = b"A       TXT"
        entry[11] = 0x20
        struct.pack_into("<H", entry, 26, 2)
        struct.pack_into("<I", entry, 28, 5)
        data[1536:1568] = entry
        data[1568] = 0x00
        entries = list(filesystems._fat_entries(bytes(data), geo, 32))
        assert entries and entries[0][0] == "A.TXT"

    def test_read_fat_skips_directory(self, monkeypatch, tmp_path):
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
        monkeypatch.setattr(filesystems, "_fat_geometry", lambda d: geo)
        monkeypatch.setattr(
            filesystems,
            "_fat_entries",
            lambda d, g, b: [("dir", 0x10, 0, 2), ("f", 0x20, 0, 2)],
        )
        monkeypatch.setattr(
            filesystems, "_fat_read_chain", lambda *a: b"hello"
        )
        manifest = filesystems.read_fat(b"x" * 3000, str(tmp_path))
        assert len(manifest) == 1 and manifest[0]["member"] == "f"


class TestExtWalkEdges:
    def test_walk_missing_inode(self, monkeypatch):
        monkeypatch.setattr(filesystems, "_ext_inode", lambda *a: None)
        assert list(filesystems._ext_walk(b"", {}, 1024, 2, "")) == []

    def test_walk_child_missing(self, monkeypatch):
        monkeypatch.setattr(
            filesystems,
            "_ext_inode",
            lambda data, sb, blk, ino: {"is_dir": False} if ino == 2 else None,
        )
        monkeypatch.setattr(
            filesystems, "_ext_dir_entries", lambda *a: iter([("child", 99)])
        )
        assert list(filesystems._ext_walk(b"", {}, 1024, 2, "")) == []

    def test_walk_recurses_dir(self, monkeypatch):
        def fake_inode(data, sb, blk, ino):
            return {
                "ino": ino,
                "is_dir": ino in (2, 3),
                "size": 0,
                "blocks": [0] * 15,
            }

        def fake_entries(data, sb, blk, inode):
            children = {2: [("sub", 3)], 3: [("leaf", 4)]}.get(
                inode["ino"], []
            )
            return iter(children)

        monkeypatch.setattr(filesystems, "_ext_inode", fake_inode)
        monkeypatch.setattr(filesystems, "_ext_dir_entries", fake_entries)
        results = list(filesystems._ext_walk(b"", {}, 1024, 2, ""))
        assert results[0][0] == "/sub/leaf"


class TestJffs2Edges:
    def _inode_node(self, csize):
        body = struct.pack(">I", 2) + struct.pack(">I", 0)
        body += struct.pack(">I", 0o100644) + struct.pack(">HH", 0, 0)
        body += struct.pack(">I", 5) + struct.pack(">III", 0, 0, 0)
        body += struct.pack(">I", 0) + struct.pack(">II", csize, csize)
        body += (
            bytes([0, 0]) + struct.pack(">H", 0) + (b"hello" if csize else b"")
        )
        node = b"\x19\x85" + struct.pack(">H", 0xE002)
        node += struct.pack(">I", 12 + len(body)) + b"\x00" * 4 + body
        return node

    def test_parse_node_inode(self):
        node = self._inode_node(0)
        parsed = jffs2._parse_node(node, 0, len(node), jffs2.INODE, ">")
        assert parsed["kind"] == "inode"

    def test_parse_inode_zero_size(self):
        node = self._inode_node(0)
        parsed = jffs2._parse_inode(node, 0, ">")
        assert parsed["ino"] == 2

    def test_path_no_match(self):
        assert jffs2._path_for(99, []) == ""

    def test_read_skips_non_regular(self, monkeypatch, tmp_path):
        nodes = [
            {"kind": "dirent", "pino": 1, "ino": 2, "name": "d", "dtype": 4},
            {"kind": "data", "ino": 2, "file_offset": 0, "payload": b"x"},
        ]
        monkeypatch.setattr(jffs2, "iter_nodes", lambda data: iter(nodes))
        assert jffs2.read_jffs2(b"", str(tmp_path)) == []
