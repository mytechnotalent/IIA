"""Coverage tests for report.py formatters (all branches populated)."""

from iiatool import report
from iiatool.utils import _init_intel


def _rich_intel():
    """Build a fully populated single-host intel dictionary."""
    intel = _init_intel("192.168.1.50", "00:11:22:33:44:55")
    intel["regulatory"] = {
        "platform": "esp32",
        "mcu": "ESP32-S3",
        "radio": "Wi-Fi",
    }
    intel["vendor_oui"] = {
        "company": "Acme",
        "source": "IEEE",
        "model_claimed": "X1",
        "mac_flags": "unicast",
    }
    intel["open_ports"] = [
        {"port": 80, "service": "http", "banner": "Server: x"}
    ]
    intel["vulnerabilities"] = {
        "sources": ["curated"],
        "ports": [
            {
                "port": 80,
                "service": "http",
                "severity": "HIGH",
                "top_score": 9.8,
                "banner": "Server: x",
                "risks": ["r1"],
                "cves": [
                    {
                        "id": "CVE-X",
                        "score": 9.8,
                        "summary": "s",
                        "source": "curated",
                    }
                ],
            }
        ],
    }
    intel["cloud_c2"] = [
        {
            "ip": "1.1.1.1",
            "org": "Org",
            "city": "C",
            "region": "R",
            "hostname": "h",
            "ports": [443],
        }
    ]
    intel["pcap_forensics"] = {
        "observed_domains": ["a.example"],
        "mqtt_topics": ["t/1"],
    }
    intel["ble_telemetry"] = {
        "adv": {
            "manufacturer_data": [
                {"company": "Acme", "company_id": 76, "hex": "00"}
            ],
            "service_uuids": ["abcd"],
            "tx_power": -4,
            "appearance": 1,
            "connectable": True,
        },
        "device_info": {
            "model": "m",
            "firmware": "f",
            "dev_id": "d",
            "manufacturer": "Acme",
            "serial": "s",
        },
    }
    intel["blue_team_risk_assessment"] = [
        {"severity": "LOW", "vuln": "v", "detail": "d"}
    ]
    return intel


def _rich_giant():
    """Build a fully populated network-wide giant dictionary."""
    wifi = {
        "ssid": "x",
        "bssid": "00:11:22:33:44:55",
        "band": "5 GHz",
        "channel": 36,
        "rssi": -40,
        "security": "WPA3",
    }
    host = _init_intel("192.168.1.50", "00:11:22:33:44:55")
    host["device_type"] = "host"
    host["vendor_oui"] = {
        "company": "Acme",
        "source": "IEEE",
        "model_claimed": "X1",
        "mac_flags": "unicast",
    }
    host["regulatory"] = {
        "fcc_grant": {"grant": "ABC", "url": "u"},
        "platform": "esp32",
        "mcu": "ESP32",
        "radio": "Wi-Fi",
    }
    host["open_ports"] = [{"port": 80, "service": "http", "banner": "b"}]
    host["vulnerabilities"] = {
        "ports": [
            {
                "port": 80,
                "service": "http",
                "severity": "HIGH",
                "top_score": 9.8,
                "cves": [
                    {
                        "id": "CVE-X",
                        "score": 9.8,
                        "summary": "s",
                        "source": "c",
                    }
                ],
            }
        ],
        "findings": [
            {
                "severity": "HIGH",
                "service": "http",
                "port": 80,
                "top_cve": "CVE-X",
            }
        ],
    }
    host["cloud_c2"] = [
        {
            "ip": "1.1.1.1",
            "org": "O",
            "city": "C",
            "country": "US",
            "ports": [443],
        }
    ]
    host["pcap_forensics"] = {"observed_domains": ["a.example"]}
    host["ble_telemetry"] = {
        "device_info": {
            "model": "m",
            "firmware": "f",
            "dev_id": "d",
            "manufacturer": "mfr",
            "serial": "s",
        },
        "adv": {
            "manufacturer_data": [
                {"company": "A", "company_id": 1, "hex": "00"}
            ],
            "service_uuids": ["u"],
        },
    }
    host["blue_team_risk_assessment"] = [
        {"severity": "LOW", "vuln": "v", "detail": "d"}
    ]
    wifi_audit = _init_intel("", "00:11:22:33:44:55")
    wifi_audit["device_type"] = "wifi"
    wifi_audit["target"]["name"] = "x"
    wifi_audit["wifi"] = {
        "channel": 36,
        "band": "5 GHz",
        "rssi": -40,
        "security": "WPA3",
    }
    bt_audit = _init_intel("", "aa:bb:cc:dd:ee:ff")
    bt_audit["device_type"] = "bluetooth_classic"
    bt_audit["bluetooth_classic"] = {
        "major_type": "Audio",
        "minor_type": "Headset",
    }
    return {
        "timestamp": "t",
        "spectrum": {
            "wifi_networks": [wifi],
            "observability_notes": ["note"],
            "ble_devices": [{"x": 1}],
            "bt_classic": [{"x": 1}],
            "mdns_services": [{"x": 1}],
            "local_hosts": [{"x": 1}],
        },
        "device_audits": [wifi_audit, host, bt_audit],
    }


def _rich_firmware():
    """Build a fully populated firmware document."""
    return {
        "timestamp": "t",
        "path": "fw.bin",
        "identification": {
            "size": 10,
            "primary": {"type": "gzip", "confidence": 0.9},
            "findings": [
                {
                    "offset": 0,
                    "type": "gzip",
                    "confidence": 0.9,
                    "source": "fixed",
                }
            ],
        },
        "entropy": {
            "overall_entropy": 7.9,
            "block_size": 4096,
            "threshold": 7.5,
            "regions": [{"start": 0, "end": 16, "peak": 7.9}],
        },
        "upx": {
            "packed": True,
            "marker_offset": 100,
            "host_format": "ELF",
            "zeroed_header": True,
        },
        "extraction": {"files": 1, "entries": [{"path": "a", "type": "gzip"}]},
        "secrets": {
            "count": 1,
            "findings": [
                {
                    "rule": "aws",
                    "tier": "pattern",
                    "evidence": "AKIA...",
                    "location": "x:1",
                }
            ],
        },
        "sbom": {
            "count": 1,
            "components": [
                {
                    "name": "openssl",
                    "version": "1.1.1k",
                    "purl": "pkg:generic/openssl@1.1.1k",
                }
            ],
        },
        "licenses": {"summary": {"MIT": {"count": 1, "paths": ["LICENSE"]}}},
        "cve": {
            "findings": [
                {
                    "cve": "CVE-X",
                    "component": "openssl",
                    "version": "1.1.1k",
                    "cvss": 9.8,
                    "severity": "critical",
                    "matched_by": "affected-range",
                }
            ],
            "summary": {"total": 1, "kev": 1, "top_cvss": 9.8},
        },
    }


class TestMarkdownReport:
    def test_full(self):
        md = report._format_markdown_report(_rich_intel())
        assert "## Open Ports" in md
        assert "## Cloud C2 Endpoints" in md
        assert "## MQTT Topics" in md
        assert "## BLE Device Info" in md

    def test_empty(self):
        intel = _init_intel("192.168.1.50", "00:11:22:33:44:55")
        intel["blue_team_risk_assessment"] = []
        assert "Executive Summary" in report._format_markdown_report(intel)

    def test_export(self, tmp_path):
        report._export_reports(
            _rich_intel(), str(tmp_path / "r.json"), str(tmp_path / "r.md")
        )
        assert (tmp_path / "r.json").exists()

    def test_risk_findings(self):
        assert report._build_risk_findings()


class TestGiantReport:
    def test_full(self):
        md = report._format_giant_markdown(_rich_giant())
        assert "Wi-Fi Networks" in md
        assert "Vulnerability assessment" in md
        assert "C2 endpoints" in md

    def test_empty(self):
        md = report._format_giant_markdown(
            {"spectrum": {}, "device_audits": []}
        )
        assert "Network-Wide" in md


class TestFirmwareReport:
    def test_full(self):
        md = report._format_firmware_markdown(_rich_firmware())
        assert "## Identification" in md
        assert "## Entropy" in md
        assert "## Extraction" in md
        assert "## Embedded Secrets" in md
        assert "## Component CVEs" in md

    def test_empty(self):
        md = report._format_firmware_markdown({"path": "x"})
        assert "Firmware and Static Analysis" in md

    def test_export(self, tmp_path):
        report._export_firmware_reports(
            _rich_firmware(), str(tmp_path / "f.json"), str(tmp_path / "f.md")
        )
        assert (tmp_path / "f.md").exists()
