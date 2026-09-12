"""Tests for the vulnerability assessment phase."""

from iiatool import cve
from iiatool.utils import _init_intel


class TestSeverityLabel:
    def test_critical(self):
        assert cve._severity_label(9.8, {}) == "CRITICAL"

    def test_high(self):
        assert cve._severity_label(7.5, {}) == "HIGH"

    def test_medium(self):
        assert cve._severity_label(5.0, {}) == "MEDIUM"

    def test_low(self):
        assert cve._severity_label(2.0, {}) == "LOW"

    def test_none_is_low(self):
        assert cve._severity_label(None, {}) == "LOW"


class TestBannerProduct:
    def test_regex_product(self):
        assert (
            cve._banner_product("SSH-2.0-OpenSSH_9.0", "ssh", 22) == "openssh"
        )

    def test_ssh_port_fallback(self):
        assert cve._banner_product("", "ssh", 22) == "openssh"

    def test_mqtt_port_fallback(self):
        assert (
            cve._banner_product("eMQTT-hub 1.2", "mqtt", 1883) == "mosquitto"
        )

    def test_bare_rfb_banner_is_not_realvnc(self):
        assert cve._banner_product("RFB 003.008", "vnc", 5900) == ""

    def test_explicit_realvnc_banner(self):
        assert cve._banner_product("RealVNC 5.3", "vnc", 5900) == "realvnc"

    def test_openssl_cert_banner_not_treated_as_product(self):
        assert (
            cve._banner_product("CN=x, O=x, issuer=OpenSSL", "https", 443)
            == ""
        )

    def test_unknown_banner(self):
        assert cve._banner_product("HTTP/1.1 200 OK", "http", 80) == ""


class TestAssessOnePort:
    def test_http_port_verdict_no_live_lookup(self, monkeypatch):
        monkeypatch.setattr(cve, "_lookup_nvd_cves", lambda kw: [])
        verdict = cve._assess_one_port(
            {
                "port": 80,
                "host": "",
                "service": "http",
                "banner": "HTTP/1.1 200 OK",
            }
        )
        assert verdict["port"] == 80
        assert verdict["service"] == "http"
        assert "Apache" in verdict["risks"][0] or verdict["risks"]

    def test_unknown_port_default_risk(self, monkeypatch):
        monkeypatch.setattr(cve, "_lookup_nvd_cves", lambda kw: [])
        verdict = cve._assess_one_port(
            {
                "port": 42424,
                "host": "",
                "service": "?",
                "banner": "",
            }
        )
        assert verdict["cves"] == []
        assert verdict["severity"] == "LOW"

    def test_dns_port_no_probe_when_no_host(self, monkeypatch):
        monkeypatch.setattr(cve, "_lookup_nvd_cves", lambda kw: [])
        verdict = cve._assess_one_port(
            {
                "port": 53,
                "host": "",
                "service": "dns",
                "banner": "",
            }
        )
        assert verdict["risks"]

    def test_netgear_outdated_firmware(self, monkeypatch):
        monkeypatch.setattr(cve, "_lookup_nvd_cves", lambda kw: [])
        verdict = cve._assess_one_port(
            {
                "port": 80,
                "host": "10.0.0.1",
                "service": "http",
                "banner": "NETGEAR R6700v3 firmware 1.0.3.88_10.0.50",
            }
        )
        ids = {c["id"] for c in verdict["cves"]}
        assert "CVE-2022-27641" in ids

    def test_netgear_current_firmware(self, monkeypatch):
        monkeypatch.setattr(cve, "_lookup_nvd_cves", lambda kw: [])
        verdict = cve._assess_one_port(
            {
                "port": 80,
                "host": "10.0.0.1",
                "service": "http",
                "banner": "NETGEAR R6700v3 firmware 1.0.5.128_10.0.104",
            }
        )
        assert any(
            c["id"].startswith("NETGEAR-baseline-1.0.5.128")
            for c in verdict["cves"]
        )

    def test_unknown_https_has_no_blanket_apache_cve(self, monkeypatch):
        monkeypatch.setattr(cve, "_lookup_nvd_cves", lambda kw: [])
        verdict = cve._assess_one_port(
            {
                "port": 443,
                "host": "",
                "service": "https",
                "banner": "",
            }
        )
        assert verdict["cves"] == []
        assert verdict["severity"] == "LOW"

    def test_confirmed_apache_is_flagged(self, monkeypatch):
        monkeypatch.setattr(cve, "_lookup_nvd_cves", lambda kw: [])
        verdict = cve._assess_one_port(
            {
                "port": 443,
                "host": "",
                "service": "https",
                "banner": "Server: Apache/2.4.49",
            }
        )
        ids = {c["id"] for c in verdict["cves"]}
        assert "CVE-2021-41773" in ids

    def test_dns_unidentified_has_no_blanket_cve(self, monkeypatch):
        monkeypatch.setattr(cve, "_lookup_nvd_cves", lambda kw: [])
        monkeypatch.setattr(
            "iiatool.scan._probe_dns_version", lambda ip, timeout=3.0: ""
        )
        verdict = cve._assess_one_port(
            {
                "port": 53,
                "host": "10.0.0.1",
                "service": "dns",
                "banner": "",
            }
        )
        assert verdict["cves"] == []
        assert verdict["severity"] == "LOW"

    def test_apple_screensharing_not_flagged_as_realvnc(self, monkeypatch):
        monkeypatch.setattr(cve, "_lookup_nvd_cves", lambda kw: [])
        verdict = cve._assess_one_port(
            {
                "port": 5900,
                "host": "",
                "service": "vnc",
                "banner": "RFB 003.889 | Apple Screen Sharing",
            }
        )
        assert verdict["cves"] == []
        assert verdict["severity"] == "LOW"


class TestAssessVulnerabilities:
    def test_no_open_ports(self):
        intel = _init_intel("1.1.1.1", "aa:bb:cc:dd:ee:ff")
        intel["open_ports"] = []
        cve._assess_vulnerabilities(intel)
        assert intel["vulnerabilities"]["ports_exposed"] == 0

    def test_findings_appended_for_high_severity(self, monkeypatch):
        high = {
            "port": 23,
            "host": "",
            "service": "telnet",
            "banner": "",
        }
        monkeypatch.setattr(
            cve,
            "_assess_one_port",
            lambda rec: {
                "port": 23,
                "service": "telnet",
                "severity": "HIGH",
                "cves": [
                    {"id": "CVE-2020-10177", "score": 10.0, "summary": "x"}
                ],
            },
        )
        intel = _init_intel("1.1.1.1", "aa:bb:cc:dd:ee:ff")
        intel["open_ports"] = [high]
        cve._assess_vulnerabilities(intel)
        assert intel["vulnerabilities"]["ports_exposed"] == 1
        assert intel["blue_team_risk_assessment"]


class TestWifiSecurity:
    def test_open_network_high_risk(self):
        intel = _init_intel("10.0.0.3", "aa:bb:cc:dd:ee:ff")
        intel["target"]["name"] = "Cafe"
        intel["wifi"] = {}
        cve._assess_wifi_security(
            intel, {"security": "Open", "band": "2.4 GHz"}
        )
        assert intel["blue_team_risk_assessment"][0]["severity"] == "HIGH"

    def test_wpa2_secured_informational(self):
        intel = _init_intel("10.0.0.3", "aa:bb:cc:dd:ee:ff")
        intel["target"]["name"] = "Cafe"
        intel["wifi"] = {}
        cve._assess_wifi_security(
            intel, {"security": "WPA2 Personal", "band": "5 GHz"}
        )
        assert (
            intel["blue_team_risk_assessment"][0]["severity"]
            == "INFORMATIONAL"
        )
        assert intel["wifi"]["hardening"]


class TestBtSecurity:
    def test_informational_peer(self):
        intel = _init_intel("10.0.0.3", "aa:bb:cc:dd:ee:ff")
        intel["target"]["name"] = "Headset"
        cve._assess_bt_security(intel, {})
        assert (
            intel["blue_team_risk_assessment"][0]["severity"]
            == "INFORMATIONAL"
        )
