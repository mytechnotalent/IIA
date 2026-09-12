"""Tests for the report generation phase."""

import json

from iiatool import report
from iiatool.utils import _init_intel


def _sample_intel():
    intel = _init_intel("10.0.0.5", "00:11:22:33:44:55")
    intel["open_ports"] = [
        {"port": 443, "service": "https", "banner": "Apache/2.4.49"},
    ]
    intel["vulnerabilities"] = {
        "sources": ["NVD API 2.0"],
        "ports": [
            {
                "port": 443,
                "service": "https",
                "severity": "HIGH",
                "banner": "Apache/2.4.49",
                "risks": ["Path traversal surface"],
                "cves": [
                    {
                        "id": "CVE-2021-41773",
                        "score": 9.8,
                        "summary": "RCE",
                        "source": "NVD live",
                    }
                ],
            }
        ],
    }
    intel["cloud_c2"] = [
        {
            "ip": "1.2.3.4",
            "org": "ASN",
            "city": "SF",
            "region": "CA",
            "ports": [443],
            "hostname": "x.com",
        }
    ]
    return intel


class TestRiskFindings:
    def test_baseline_findings(self):
        findings = report._build_risk_findings()
        assert len(findings) == 2
        assert findings[0]["severity"] == "INFORMATIONAL"


class TestSummaryLines:
    def test_headers_section_present(self):
        intel = _sample_intel()
        lines = report._build_summary_lines(intel)
        joined = "\n".join(lines)
        assert "Blue Team IoT Intelligence" in joined
        assert "Executive Summary" in joined
        assert "10.0.0.5" in joined

    def test_vendor_from_intel(self):
        intel = _sample_intel()
        intel["vendor_oui"] = {"company": "Electric Imp"}
        joined = "\n".join(report._build_summary_lines(intel))
        assert "Electric Imp" in joined


class TestFormatMarkdownReport:
    def test_renders_sections(self):
        md = report._format_markdown_report(_sample_intel())
        assert "## Vulnerability Assessment" in md
        assert "CVE-2021-41773" in md
        assert "## Open Ports" in md

    def test_risk_findings_section(self):
        intel = _sample_intel()
        intel["blue_team_risk_assessment"] = [
            {
                "severity": "MEDIUM",
                "vuln": "BLE Wi-Fi Survey Leakage",
                "detail": "Visible SSIDs",
            }
        ]
        md = report._format_markdown_report(intel)
        assert "BLE Wi-Fi Survey Leakage" in md

    def test_empty_intel_report_renders(self):
        intel = _init_intel("10.0.0.5", "00:11:22:33:44:55")
        md = report._format_markdown_report(intel)
        assert md.strip()


class TestExportReports:
    def test_writes_json_and_markdown(self, tmp_path):
        intel = _sample_intel()
        json_path = str(tmp_path / "rep.json")
        md_path = str(tmp_path / "rep.md")
        report._export_reports(intel, json_path, md_path)
        data = json.loads(open(json_path).read())
        assert data["target"]["ip"] == "10.0.0.5"
        assert "# Blue Team" in open(md_path).read()

    def test_risk_findings_appended(self, tmp_path):
        intel = _sample_intel()
        report._export_reports(intel, str(tmp_path / "rep.json"), "")
        assert len(intel["blue_team_risk_assessment"]) == 2


class TestFormatGiantMarkdown:
    def _sample_giant(self):
        return {
            "timestamp": "2026-01-01T00:00:00",
            "spectrum": {
                "wifi_networks": [
                    {
                        "ssid": "Home",
                        "bssid": "00:11:22:33:44:55",
                        "band": "5 GHz",
                        "channel": "44",
                        "rssi": "-45",
                        "security": "WPA2 Personal",
                    },
                ],
                "ble_devices": [],
                "bt_classic": [],
                "mdns_services": ["_http._tcp.local."],
                "local_hosts": [],
                "observability_notes": ["note"],
            },
            "device_audits": [_sample_intel()],
        }

    def test_giant_report_renders(self):
        md = report._format_giant_markdown(self._sample_giant())
        assert "Network-Wide" in md
        assert "Home" in md
        assert "WPA2 Personal" in md
        assert "Wi-Fi networks" in md
