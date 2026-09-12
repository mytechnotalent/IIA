"""Tests for the secrets, SBOM, license, and CVE static passes."""

import base64
import json

from iiatool.static import licenses, sbom, secrets, vulns


def _b64(part: bytes) -> str:
    """
    Base64url-encode bytes without padding.

    Parameters
    ----------
    part : bytes
        Input bytes.

    Returns
    -------
    str
        Encoded text.
    """
    return base64.urlsafe_b64encode(part).rstrip(b"=").decode()


def _jwt(header=b'{"alg":"HS256"}', payload=b'{"sub":"1"}') -> str:
    """
    Build a syntactically valid JWT for testing.

    Parameters
    ----------
    header : bytes
        Header JSON.
    payload : bytes
        Payload JSON.

    Returns
    -------
    str
        JWT string.
    """
    return _b64(header) + "." + _b64(payload) + ".signaturepart"


class TestSecrets:
    def test_aws(self):
        found = secrets.scan_text("key = AKIA" + "B" * 16, "x")
        assert any(f["rule"] == "aws-access-key-id" for f in found)

    def test_github(self):
        found = secrets.scan_text("t = ghp_" + "b" * 36, "x")
        assert any(f["rule"] == "github-token" for f in found)

    def test_jwt_structural(self):
        found = secrets.scan_text("token " + _jwt(), "x")
        assert any(
            f["rule"] == "jwt" and f["tier"] == "structural" for f in found
        )

    def test_jwt_invalid_header(self):
        bad = "eyJ" + "bm90anNvbg" + "." + "eyJzdWIiOiIxIn0" + "." + "abcdefgh"
        assert not any(f["rule"] == "jwt" for f in secrets.scan_text(bad, "x"))

    def test_crypt_validated(self):
        value = "$6$" + "abcdefgh$" + "ijklmnop"
        found = secrets.scan_text("root:" + value, "x")
        assert any(f["tier"] == "validated" for f in found)

    def test_secret_assignment(self):
        payload = "pass" + "word = " + '"' + "hunter2hunter2" + '"'
        found = secrets.scan_text(payload, "x")
        assert any(f["rule"] == "secret-assignment" for f in found)

    def test_private_key(self):
        payload = "-----BEGIN RSA " + "PRIVATE KEY-----"
        found = secrets.scan_text(payload, "x")
        assert any(f["rule"] == "private-key" for f in found)

    def test_placeholder_ignored(self):
        assert secrets.scan_text('token = "<secret>"', "x") == []

    def test_db_uri(self):
        found = secrets.scan_text("mongodb://user:pass@host/db", "x")
        assert any(f["rule"] == "db-uri" for f in found)

    def test_credential_file_flag(self, tmp_path):
        target = tmp_path / ".env"
        target.write_text("X=1")
        found = secrets.scan_file(str(target))
        assert any(f["rule"] == "credential-file" for f in found)

    def test_shadow_empty(self, tmp_path):
        target = tmp_path / "shadow"
        target.write_text("root:" + "" + ":0:0:root:/root:/bin/sh")
        found = secrets.scan_file(str(target))
        assert any(f["rule"] == "empty-password" for f in found)

    def test_shadow_weak(self, tmp_path):
        target = tmp_path / "shadow"
        target.write_text("root:" + "$1$" + "abcdefgh$" + "ijklmnop" + ":0:0")
        found = secrets.scan_file(str(target))
        assert any(f["rule"] == "weak-hash" for f in found)

    def test_scan_secrets_dir(self, tmp_path):
        (tmp_path / "a.txt").write_text("AKIA" + "B" * 16)
        result = secrets.scan_secrets(str(tmp_path))
        assert result["count"] >= 1

    def test_scan_secrets_missing(self):
        assert secrets.scan_secrets("/nonexistent").get("count") in (None, 0)

    def test_redact(self):
        assert secrets._redact(b"abcdefghij") == "abcdef..."


class TestLicenses:
    def test_spdx_tag(self, tmp_path):
        target = tmp_path / "a.c"
        target.write_text("// SPDX-License-Identifier: MIT")
        result = licenses.scan_licenses(str(target))
        assert "MIT" in result["summary"]

    def test_gpl_text(self, tmp_path):
        target = tmp_path / "LICENSE"
        target.write_text("GNU General Public License Version 3")
        result = licenses.scan_licenses(str(target))
        assert "GPL-3.0-only" in result["summary"]

    def test_summary_counts(self):
        findings = [
            {"id": "MIT", "source": "text", "path": "a"},
            {"id": "MIT", "source": "text", "path": "b"},
        ]
        assert licenses._summarize(findings)["MIT"]["count"] == 2

    def test_iter_files_file(self, tmp_path):
        target = tmp_path / "x"
        target.write_text("hi")
        assert list(licenses._iter_files(str(target))) == [str(target)]


class TestSbom:
    def test_parse_status_opkg(self):
        text = "Package: openssl\nVersion: 1.1.1k\n\n"
        result = sbom._parse_status(text)
        assert result[0]["name"] == "openssl"

    def test_parse_status_apk(self):
        text = "P:busybox\nV:1.35.0\n"
        result = sbom._parse_status(text)
        assert result[0]["source"] == "apk"

    def test_parse_status_dpkg(self):
        text = "Package: zlib\nVersion: 1.2\nStatus: install ok\n\n"
        assert sbom._parse_status(text)[0]["source"] == "dpkg"

    def test_banner_components(self):
        data = b"OpenSSL 1.1.1k and BusyBox v1.35.0"
        names = {c["name"] for c in sbom._banner_components(data)}
        assert {"openssl", "busybox"} <= names

    def test_libc_component(self):
        found = sbom._libc_components("libuClibc-1.0.30.so")
        assert found[0]["name"] == "uclibc"

    def test_kernel_component(self):
        found = sbom._kernel_component(b"Linux version 6.6.1 foo")
        assert found[0]["version"] == "6.6.1"

    def test_build_sbom_dir(self, tmp_path):
        (tmp_path / "fw.bin").write_bytes(
            b"OpenSSL 1.1.1k Linux version 6.6.1"
        )
        result = sbom.build_sbom(str(tmp_path))
        assert result["count"] >= 2
        assert result["components"][0]["purl"].startswith("pkg:generic/")

    def test_purl_without_version(self):
        assert sbom._purl({"name": "x"}) == "pkg:generic/x"

    def test_cpe(self):
        value = sbom._cpe(
            {"name": "openssl", "vendor": "openssl", "version": "1.1"}
        )
        assert value.startswith("cpe:2.3:a:openssl:openssl:1.1")

    def test_merge_sources(self):
        merged = sbom._merge(
            [
                {"name": "a", "version": "1", "source": "x"},
                {"name": "a", "version": "1", "source": "y"},
            ]
        )
        assert merged[0]["sources"] == ["x", "y"]

    def test_cyclonedx(self):
        doc = sbom.to_cyclonedx(
            {
                "components": [
                    {"name": "a", "version": "1", "purl": "p", "cpe": "c"}
                ]
            }
        )
        assert doc["bomFormat"] == "CycloneDX"
        assert doc["components"][0]["purl"] == "p"

    def test_spdx(self):
        doc = sbom.to_spdx(
            {
                "path": "fw",
                "components": [{"name": "a", "version": "1", "purl": "p"}],
            }
        )
        assert doc["spdxVersion"] == "SPDX-2.3"
        assert doc["packages"][0]["name"] == "a"

    def test_from_file_status(self, tmp_path):
        target = tmp_path / "status"
        target.write_text("Package: openssl\nVersion: 1.1.1k\n\n")
        assert sbom._from_file(str(target))[0]["name"] == "openssl"

    def test_from_file_missing(self):
        assert sbom._from_file("/nonexistent") == []


class TestVulns:
    def test_vkey_compare(self):
        assert vulns._compare("1.1.1", "1.1.1k") == -1
        assert vulns._compare("2.0", "1.9") == 1
        assert vulns._compare("1.0", "1.0") == 0

    def test_in_range(self):
        assert vulns._in_range("1.0.2", ">=1.0.0,<1.1.1k") is True
        assert vulns._in_range("1.2.0", ">=1.0.0,<1.1.1k") is False

    def test_clause_operators(self):
        assert vulns._clause("1.0", "<=1.0") is True
        assert vulns._clause("1.0", ">0.9") is True
        assert vulns._clause("1.0", "==1.0") is True
        assert vulns._clause("1.0", "1.0") is True

    def test_load_mirror(self, tmp_path):
        target = tmp_path / "mirror.json"
        target.write_text(json.dumps({"advisories": [{"cve": "CVE-X"}]}))
        assert (
            vulns.load_mirror(str(target))["advisories"][0]["cve"] == "CVE-X"
        )

    def test_load_mirror_missing(self):
        assert vulns.load_mirror("/nonexistent")["advisories"] == []

    def _mirror(self):
        return {
            "advisories": [
                {
                    "component": "openssl",
                    "cve": "CVE-1",
                    "affected": ">=1.0.0,<1.1.1k",
                    "cvss": 9.8,
                    "severity": "critical",
                    "kev": True,
                    "epss": 0.9,
                },
                {
                    "component": "zlib",
                    "cve": "CVE-2",
                    "fixed": "2.0",
                    "cvss": 5.0,
                },
                {"component": "x", "cve": "CVE-3", "version": "1.2.3"},
            ]
        }

    def test_join_affected_range(self):
        result = vulns.join_cves(
            [{"name": "openssl", "version": "1.0.2"}], self._mirror()
        )
        assert result["findings"][0]["matched_by"] == "affected-range"

    def test_join_fixed_version(self):
        result = vulns.join_cves(
            [{"name": "zlib", "version": "1.9"}], self._mirror()
        )
        assert result["findings"][0]["matched_by"] == "fixed-version"

    def test_join_exact_version(self):
        result = vulns.join_cves(
            [{"name": "x", "version": "1.2.3"}], self._mirror()
        )
        assert result["findings"][0]["matched_by"] == "exact-version"

    def test_join_cpe_when_no_version(self):
        result = vulns.join_cves(
            [{"name": "openssl", "version": ""}], self._mirror()
        )
        assert result["findings"][0]["matched_by"] == "cpe"

    def test_join_no_match(self):
        result = vulns.join_cves(
            [{"name": "other", "version": "1.0"}], self._mirror()
        )
        assert result["findings"] == []

    def test_summary(self):
        result = vulns.join_cves(
            [{"name": "openssl", "version": "1.0.2"}], self._mirror()
        )
        assert result["summary"]["total"] == 1
        assert result["summary"]["kev"] == 1
        assert result["summary"]["top_cvss"] == 9.8
