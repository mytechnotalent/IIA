"""Tests for FAT, ext, SquashFS, UBI, and JFFS2 native readers."""

import struct

from iiatool.firmware import filesystems, jffs2, squashfs, ubi


def _fat12(payload: bytes) -> bytes:
    """
    Build a minimal FAT12 image with one file.

    Parameters
    ----------
    payload : bytes
        File content (<= 512 bytes).

    Returns
    -------
    bytes
        FAT12 image bytes.
    """
    bps, spc, reserved, fats, roots, fatsz = 512, 1, 1, 2, 16, 1
    root_sectors = (roots * 32 + bps - 1) // bps
    data_start = (reserved + fats * fatsz + root_sectors) * bps
    img = bytearray(data_start + bps)
    struct.pack_into("<H", img, 11, bps)
    img[13] = spc
    struct.pack_into("<H", img, 14, reserved)
    img[16] = fats
    struct.pack_into("<H", img, 17, roots)
    struct.pack_into("<H", img, 19, 12)
    struct.pack_into("<H", img, 22, fatsz)
    img[510:512] = b"\x55\xaa"
    fat = bytearray(bps)
    fat[0:3] = bytes([0xF0, 0xFF, 0xFF])
    fat[3], fat[4] = 0xFF, 0x0F
    img[512:1024] = fat
    img[1024:1536] = fat
    root_at = (reserved + fats * fatsz) * bps
    entry = bytearray(32)
    entry[0:11] = b"A       TXT"
    entry[11] = 0x20
    struct.pack_into("<H", entry, 26, 2)
    struct.pack_into("<I", entry, 28, len(payload))
    img[root_at: root_at + 32] = entry
    img[data_start: data_start + len(payload)] = payload
    return bytes(img)


def _ext2(payload: bytes) -> bytes:
    """
    Build a minimal ext2 image with a root dir and one file.

    Parameters
    ----------
    payload : bytes
        File content.

    Returns
    -------
    bytes
        ext2 image bytes.
    """
    blk = 1024
    data = bytearray(9 * blk)
    sb = 1024
    struct.pack_into("<I", data, sb, 16)
    struct.pack_into("<I", data, sb + 4, 8)
    struct.pack_into("<I", data, sb + 24, 0)
    struct.pack_into("<I", data, sb + 32, 8192)
    struct.pack_into("<I", data, sb + 40, 16)
    data[sb + 56: sb + 58] = b"\x53\xef"
    struct.pack_into("<I", data, sb + 76, 0)
    struct.pack_into("<I", data, sb + 84, 11)
    struct.pack_into("<H", data, sb + 88, 128)
    struct.pack_into("<I", data, 2048 + 8, 5)
    it = 5120
    struct.pack_into("<H", data, it + 128, 0x41ED)
    struct.pack_into("<I", data, it + 128 + 4, blk)
    struct.pack_into("<I", data, it + 128 + 40, 7)
    fin = it + 11 * 128
    struct.pack_into("<H", data, fin, 0x81A4)
    struct.pack_into("<I", data, fin + 4, len(payload))
    struct.pack_into("<I", data, fin + 40, 8)
    data[7168:7180] = _ext_ent(2, b".", 12)
    data[7180:7192] = _ext_ent(2, b"..", 12)
    data[7192:8192] = _ext_ent(12, b"A.TXT", 1000)
    data[8192: 8192 + len(payload)] = payload
    return bytes(data)


def _ext_ent(ino: int, name: bytes, rec_len: int) -> bytes:
    """
    Build one ext directory entry.

    Parameters
    ----------
    ino : int
        Inode number.
    name : bytes
        Entry name.
    rec_len : int
        Record length.

    Returns
    -------
    bytes
        Padded directory entry.
    """
    entry = struct.pack("<IHBB", ino, rec_len, len(name), 0) + name
    return entry.ljust(rec_len, b"\x00")


def _squashfs(payload: bytes) -> bytes:
    """
    Build a minimal uncompressed-metadata SquashFS v4 image.

    Parameters
    ----------
    payload : bytes
        File content.

    Returns
    -------
    bytes
        SquashFS image bytes.
    """
    blk, m, d = 4096, 104, 174
    sb = bytearray(96)
    sb[0:4] = b"hsqs"
    struct.pack_into("<I", sb, 4, 2)
    struct.pack_into("<I", sb, 12, blk)
    struct.pack_into("<H", sb, 20, 1)
    struct.pack_into("<H", sb, 28, 4)
    struct.pack_into("<Q", sb, 32, (m << 16))
    struct.pack_into("<Q", sb, 40, d + 27)
    struct.pack_into("<Q", sb, 64, m)
    struct.pack_into("<Q", sb, 72, d)
    data = bytearray(sb) + payload
    data += b"\x00" * (m - len(data))
    root = struct.pack("<HHHHII", 1, 0o755, 0, 0, 0, 1)
    root += struct.pack("<IIHH", 0, 2, 28, 0) + struct.pack("<I", 1)
    file_inode = struct.pack("<HHHHII", 2, 0o644, 0, 0, 0, 2)
    file_inode += struct.pack("<IIII", 96, 0xFFFFFFFF, 0, len(payload))
    file_inode += struct.pack("<I", 0x1000000 | len(payload))
    inode_raw = root + file_inode
    data += struct.pack("<H", 0x8000 | len(inode_raw)) + inode_raw
    listing = struct.pack("<III", 0, m, 1)
    listing += struct.pack("<HhHH", 32, 1, 2, 4) + b"A.TXT"
    data += struct.pack("<H", 0x8000 | len(listing)) + listing
    return bytes(data)


def _ubi(payload: bytes) -> bytes:
    """
    Build a one-PEB UBI image with a single volume.

    Parameters
    ----------
    payload : bytes
        Volume payload.

    Returns
    -------
    bytes
        UBI image bytes.
    """
    data = bytearray(0x20000)
    data[0:4] = b"UBI#"
    data[4] = 1
    struct.pack_into(">I", data, 8, 64)
    struct.pack_into(">I", data, 12, 128)
    struct.pack_into(">I", data, 16, 1)
    data[64:68] = b"UBI!"
    data[68] = 1
    struct.pack_into(">I", data, 72, 0)
    struct.pack_into(">I", data, 76, 0)
    struct.pack_into(">I", data, 80, len(payload))
    data[128: 128 + len(payload)] = payload
    return bytes(data)


def _jffs2(payload: bytes) -> bytes:
    """
    Build a JFFS2 image with one dirent and one data node.

    Parameters
    ----------
    payload : bytes
        File content.

    Returns
    -------
    bytes
        JFFS2 image bytes.
    """
    body = struct.pack(">IIIIBBH", 1, 0, 2, 0, 1, 8, 0) + b"A"
    dirent = b"\x19\x85" + struct.pack(">H", 0xE001)
    dirent += struct.pack(">I", 12 + len(body)) + b"\x00" * 4 + body
    dirent += b"\x00" * (-len(dirent) % 4)
    data_body = struct.pack(">IIIII", 2, 0, 0, len(payload), len(payload))
    data_body += bytes([0, 0]) + payload
    data_node = b"\x19\x85" + struct.pack(">H", 0xE003)
    data_node += (
        struct.pack(">I", 12 + len(data_body)) + b"\x00" * 4 + data_body
    )
    return dirent + data_node


class TestFat:
    def test_geometry_none(self):
        assert filesystems._fat_geometry(b"\x00" * 512) is None

    def test_kind_fat12(self):
        assert (
            filesystems._fat_kind(filesystems._fat_geometry(_fat12(b"x")))
            == 12
        )

    def test_short_name(self):
        entry = bytearray(32)
        entry[0:11] = b"A       TXT"
        assert filesystems._fat_short_name(entry) == "A.TXT"

    def test_lfn(self):
        entry = bytearray(32)
        struct.pack_into("<H", entry, 1, ord("A"))
        assert "A" in filesystems._fat_lfn(entry)

    def test_read(self, tmp_path):
        manifest = filesystems.read_fat(_fat12(b"hello"), str(tmp_path))
        assert manifest[0]["member"] == "A.TXT"
        assert manifest[0]["size"] == 5

    def test_read_bad(self, tmp_path):
        assert filesystems.read_fat(b"\x00" * 512, str(tmp_path)) == []

    def test_next_and_chain(self, tmp_path):
        data = _fat12(b"hello")
        geo = filesystems._fat_geometry(data)
        assert filesystems._fat_next(data, geo, 12, 2) == 0xFFF
        assert list(filesystems._fat_chain(data, geo, 12, 2)) == [2]
        assert filesystems._fat_read_chain(data, geo, 12, 2)[:5] == b"hello"

    def test_cluster_bytes(self):
        data = _fat12(b"hello")
        geo = filesystems._fat_geometry(data)
        assert filesystems._cluster_bytes(data, geo, 2)[:5] == b"hello"


class TestExt:
    def test_superblock_none(self):
        assert filesystems._ext_superblock(b"\x00" * 2048) is None

    def test_block_size(self):
        assert filesystems._ext_block_size({"log_block": 0}) == 1024

    def test_read(self, tmp_path):
        manifest = filesystems.read_ext(_ext2(b"hello"), str(tmp_path))
        assert manifest[0]["member"] == "/A.TXT"
        assert manifest[0]["size"] == 5

    def test_read_bad(self, tmp_path):
        assert filesystems.read_ext(b"\x00" * 2048, str(tmp_path)) == []

    def test_inode_none(self):
        assert (
            filesystems._ext_inode(
                b"\x00" * 2048, {"inodes_per_group": 16}, 1024, 0
            )
            is None
        )

    def test_indirect_empty(self):
        assert filesystems._ext_indirect(b"", {}, 1024, 0, 1) == b""

    def test_group_desc(self):
        sb = {"desc_size": 32}
        data = bytearray(4096)
        struct.pack_into("<I", data, 2048 + 8, 5)
        assert (
            filesystems._ext_group_desc(data, sb, 0, 1024)["inode_table"] == 5
        )


class TestSquashfs:
    def test_info_none(self):
        assert squashfs.squashfs_info(b"junk") is None

    def test_info_fields(self):
        info = squashfs.squashfs_info(_squashfs(b"hello"))
        assert info["codec"] == "gzip"
        assert info["version"] == (4, 0)

    def test_endian_be(self):
        assert squashfs._endian(b"sqsh") == ">"

    def test_inode_ref(self):
        assert squashfs._inode_ref((104 << 16) | 32) == (104, 32)

    def test_read(self, tmp_path):
        manifest = squashfs.read_squashfs(_squashfs(b"hello"), str(tmp_path))
        assert manifest[0]["member"] == "/A.TXT"
        assert manifest[0]["size"] == 5

    def test_read_bad_version(self, tmp_path):
        data = bytearray(_squashfs(b"hello"))
        struct.pack_into("<H", data, 28, 3)
        assert squashfs.read_squashfs(bytes(data), str(tmp_path)) == []

    def test_read_bad_magic(self, tmp_path):
        assert squashfs.read_squashfs(b"junk", str(tmp_path)) == []

    def test_meta_block_uncompressed(self):
        block, nxt = squashfs._meta_block(
            struct.pack("<H", 0x8000 | 3) + b"abc", 0, "<"
        )
        assert block == b"abc"
        assert nxt == 5

    def test_decode_symlink(self):
        raw = struct.pack("<HHHHII", 3, 0, 0, 0, 0, 1) + struct.pack(
            "<II", 1, 5
        )
        raw += b"hello"
        assert squashfs._decode_symlink(raw, 3, "<")["target"] == "hello"


class TestUbi:
    def test_info_none(self):
        assert ubi.ubi_info(b"junk") is None

    def test_info_fields(self):
        info = ubi.ubi_info(_ubi(b"hello"))
        assert info["vid_offset"] == 64

    def test_read(self, tmp_path):
        manifest = ubi.read_ubi(_ubi(b"hello"), str(tmp_path))
        assert manifest[0]["member"] == "ubi-volume-0.bin"
        assert manifest[0]["size"] == 5

    def test_read_bad(self, tmp_path):
        assert ubi.read_ubi(b"junk", str(tmp_path)) == []

    def test_peb_size(self):
        info = ubi.ubi_info(_ubi(b"hello"))
        assert ubi._peb_size(_ubi(b"hello"), info) == 0x20000


class TestJffs2:
    def test_nodes(self):
        nodes = list(jffs2.iter_nodes(_jffs2(b"hello")))
        assert any(n["kind"] == "dirent" for n in nodes)
        assert any(n["kind"] == "data" for n in nodes)

    def test_read(self, tmp_path):
        manifest = jffs2.read_jffs2(_jffs2(b"hello"), str(tmp_path))
        assert manifest[0]["member"] == "/A"
        assert manifest[0]["size"] == 5

    def test_decompress_unknown(self):
        assert jffs2._decompress(99, b"x", 1) == b""

    def test_decompress_zlib(self):
        import zlib

        assert jffs2._decompress(1, zlib.compress(b"hi"), 2) == b"hi"

    def test_decompress_bad_zlib(self):
        assert jffs2._decompress(1, b"not-zlib", 2) == b""

    def test_align(self):
        assert jffs2._align(5) == 8

    def test_empty(self, tmp_path):
        assert jffs2.read_jffs2(b"", str(tmp_path)) == []
