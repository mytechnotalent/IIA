"""Final branch tests for signatures, squashfs, sbom, secrets, vulns."""

import struct

from iiatool.firmware import signatures, squashfs
from iiatool.static import sbom, secrets, vulns


def _sb(fragment_table=0):
    """Build a minimal SquashFS superblock."""
    sb = bytearray(96)
    sb[0:4] = b"hsqs"
    struct.pack_into("<I", sb, 12, 4096)
    struct.pack_into("<H", sb, 20, 1)
    struct.pack_into("<H", sb, 28, 4)
    struct.pack_into("<Q", sb, 80, fragment_table)
    return sb


class TestSignatureEdges:
    def test_valid_tar_short(self):
        assert signatures._valid_tar(b"", 257) is False

    def test_tar_checksum_bad_octal(self):
        header = bytearray(512)
        header[148:156] = b"abcdefgh"
        assert signatures._tar_checksum(bytes(header)) is None

    def test_valid_uimage_short(self):
        assert signatures._valid_uimage(b"", 0) is False

    def test_valid_zip_short(self):
        assert signatures._valid_zip(b"", 0) is False


class TestVulnEdges:
    def test_match_none(self):
        mirror = {"advisories": [{"component": "a", "cve": "X"}]}
        result = vulns.join_cves([{"name": "a", "version": "1"}], mirror)
        assert result["findings"] == []


class TestStaticIter:
    def test_secrets_iter_file(self):
        assert list(secrets._iter_files(__file__)) == [__file__]

    def test_sbom_iter_file(self):
        assert list(sbom._iter_files(__file__)) == [__file__]

    def test_kernel_component_none(self):
        assert sbom._kernel_component(b"no kernel banner") == []


class TestSquashfsEdges:
    def test_meta_block_short(self):
        assert squashfs._meta_block(b"", 0, "<") == (b"", 0)

    def test_decode_inode_symlink(self):
        raw = struct.pack("<HHHHII", 3, 0, 0, 0, 0, 1)
        raw += struct.pack("<II", 1, 5) + b"hello"
        assert squashfs._decode_inode(raw, 3, "<")["target"] == "hello"

    def test_dir_entries_short_header(self):
        data = bytes(_sb())
        data += struct.pack("<H", 0x8000 | 4) + b"abcd"
        info = squashfs.squashfs_info(data)
        inode = {"dir_start": 0, "dir_offset": 0, "size": 10}
        assert list(squashfs._dir_entries(data, info, inode)) == []

    def test_parse_entries_break(self):
        assert squashfs._parse_entries(b"\x00" * 12, 12, 1, 0, 0, "<") == (
            [],
            12,
        )

    def test_apply_fragment_missing_entry(self):
        data = bytes(_sb())
        info = squashfs.squashfs_info(data)
        inode = {"fragment": 0, "fragment_offset": 0, "size": 3}
        assert (
            squashfs._apply_fragment(data, info, inode, bytearray(b"abc"))
            == b"abc"
        )

    def test_fragment_entry_short_header(self):
        data = bytearray(_sb(fragment_table=200))
        data += b"\x00" * (200 - len(data))
        data += struct.pack("<H", 0x8000 | 4) + b"abcd"
        info = squashfs.squashfs_info(bytes(data))
        assert squashfs._fragment_entry(bytes(data), info, 0) is None

    def test_fragment_entry_short_entry(self):
        data = bytearray(_sb(fragment_table=200))
        data += b"\x00" * (200 - len(data))
        data += struct.pack("<H", 0x8000 | 8) + struct.pack("<Q", 300)
        data += b"\x00" * (300 - len(data))
        data += struct.pack("<H", 0x8000 | 4) + b"abcd"
        info = squashfs.squashfs_info(bytes(data))
        assert squashfs._fragment_entry(bytes(data), info, 0) is None

    def test_walk_depth_zero(self):
        assert list(squashfs._walk(b"", {}, 0, "", 0, [1])) == []

    def test_walk_budget_zero(self):
        assert list(squashfs._walk(b"", {}, 0, "", 5, [0])) == []

    def test_walk_skips_dot(self, monkeypatch):
        monkeypatch.setattr(squashfs, "_inode", lambda *a: {"kind": "dir"})
        monkeypatch.setattr(
            squashfs,
            "_dir_entries",
            lambda *a: iter([{"name": ".", "ref": 1}]),
        )
        assert list(squashfs._walk(b"", {}, 0, "", 5, [10])) == []

    def test_walk_child_none(self, monkeypatch):
        monkeypatch.setattr(
            squashfs,
            "_inode",
            lambda data, info, ref: {"kind": "dir"} if ref == 0 else None,
        )
        monkeypatch.setattr(
            squashfs,
            "_dir_entries",
            lambda *a: iter([{"name": "f", "ref": 1}]),
        )
        assert list(squashfs._walk(b"", {}, 0, "", 5, [10])) == []

    def test_walk_recurses(self, monkeypatch):
        kinds = {0: "dir", 1: "dir", 2: "file"}

        def fake_inode(data, info, ref):
            return {"kind": kinds.get(ref, "file"), "id": ref}

        def fake_entries(data, info, inode):
            children = {
                0: [{"name": "sub", "ref": 1}],
                1: [{"name": "leaf", "ref": 2}],
            }.get(inode["id"], [])
            return iter(children)

        monkeypatch.setattr(squashfs, "_inode", fake_inode)
        monkeypatch.setattr(squashfs, "_dir_entries", fake_entries)
        results = list(squashfs._walk(b"", {}, 0, "", 5, [10]))
        assert results[0][0] == "/sub/leaf"
