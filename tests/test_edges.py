"""Edge-branch tests for static modules and remaining parser branches."""

from iiatool.firmware import signatures, upx
from iiatool.static import licenses, sbom, secrets, vulns


class TestLicenseEdges:
    def test_bsd_discard(self):
        text = (
            "redistribution and use in source and binary forms "
            "neither the name"
        )
        ids = licenses._ids_from_text(text)
        assert "BSD-3-Clause" in ids and "BSD-2-Clause" not in ids

    def test_scan_file_missing(self):
        assert licenses._scan_file("/nonexistent") == []

    def test_iter_files_directory(self, tmp_path):
        (tmp_path / "a").write_text("x")
        assert list(licenses._iter_files(str(tmp_path)))


class TestSecretEdges:
    def test_entropy_value(self):
        assert secrets._entropy_value(b"aaaa") == 0.0

    def test_jwt_structural_invalid(self):
        assert secrets._jwt_structural(b"!!!.!!!.!!!") is False

    def test_scan_file_missing(self):
        assert secrets.scan_file("/nonexistent") == []

    def test_iter_files_directory(self, tmp_path):
        (tmp_path / "a").write_text("x")
        assert list(secrets._iter_files(str(tmp_path)))


class TestSbomEdges:
    def test_parse_status_no_trailing_blank(self):
        result = sbom._parse_status("Package: a\nVersion: 1")
        assert result[0]["name"] == "a"

    def test_parse_status_apk_no_blank(self):
        result = sbom._parse_status("P:a\nV:1")
        assert result[0]["source"] == "apk"

    def test_from_file_missing(self):
        assert sbom._from_file("/nonexistent") == []

    def test_iter_files_directory(self, tmp_path):
        (tmp_path / "a").write_text("x")
        assert list(sbom._iter_files(str(tmp_path)))

    def test_from_file_status_missing_read(self, tmp_path):
        target = tmp_path / "status"
        target.mkdir()
        assert sbom._from_file(str(target)) == []


class TestVulnEdges:
    def test_in_range_empty_clause(self):
        assert vulns._in_range("1.0", ">=1.0,,<2.0") is True

    def test_summary_empty(self):
        summary = vulns._summary([])
        assert summary["total"] == 0
        assert summary["top_cvss"] is None


class TestSignatureEdges:
    def test_valid_gzip(self):
        assert signatures._valid_gzip(b"", 0) is True

    def test_valid_cramfs_short(self):
        assert signatures._valid_cramfs(b"", 0) is False

    def test_valid_iso(self):
        assert signatures._valid_iso(b"\x01", 1) is True

    def test_valid_uimage_mismatch(self):
        assert signatures._valid_uimage(b"\x00" * 100, 0) is False

    def test_valid_squashfs_ok(self):
        data = bytearray(64)
        data[0:4] = b"hsqs"
        data[28:30] = b"\x04\x00"
        assert signatures._valid_squashfs(bytes(data), 0) is True

    def test_apply_validator_accepts(self):
        data = bytearray(64)
        data[0:4] = b"hsqs"
        data[28:30] = b"\x04\x00"
        assert (
            signatures._apply_validator("squashfs", bytes(data), 0, 0.9) > 0.9
        )


class TestUpxEdges:
    def test_zeroed_header_false(self):
        assert upx._zeroed_header(b"\x01" + b"\x00" * 20) is False

    def test_pack_fields_found(self):
        header = bytearray(32)
        header[23] = 3
        data = b"x" * 40 + b"UPX!" + bytes(header) + b"y" * 40
        result = upx._pack_fields(data, 40)
        assert result.get("level") == 3
