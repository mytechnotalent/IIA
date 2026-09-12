"""Coverage tests for cve.py (NVD lookup, port/device assessment)."""

import json
import urllib.error

import pytest

from iiatool import cve
from iiatool.utils import _init_intel


class _Resp:
    """Fake urlopen response."""

    def __init__(self, payload):
        """Store payload bytes."""
        self.payload = payload

    def __enter__(self):
        """Enter context."""
        return self

    def __exit__(self, *args):
        """Exit context."""
        return False

    def read(self):
        """Return payload bytes."""
        return self.payload


@pytest.fixture(autouse=True)
def _reset_cve():
    """Reset module globals between tests."""
    cve._CVE_CACHE.clear()
    cve._CVE_BUDGET = 99
    cve._CVE_LAST_REQUEST = 0.0
    yield


def _nvd_payload():
    """Build a realistic NVD payload with metric variations."""
    return {
        "vulnerabilities": [
            {
                "cve": {
                    "id": "CVE-1",
                    "metrics": {
                        "cvssMetricV31": [{"cvssData": {"baseScore": 9.1}}]
                    },
                    "descriptions": [{"lang": "en", "value": "english"}],
                }
            },
            {
                "cve": {
                    "id": "CVE-2",
                    "metrics": {"cvssMetricV2": [{"cvssData": {}}]},
                    "descriptions": [],
                }
            },
            {
                "cve": {
                    "id": "CVE-3",
                    "metrics": {},
                    "descriptions": [{"lang": "fr", "value": "x"}],
                }
            },
            {
                "cve": {
                    "id": "CVE-4",
                    "metrics": {"cvssMetricV31": "bad"},
                    "descriptions": [{"lang": "en", "value": "y"}],
                }
            },
        ]
    }


class TestNvdLookup:
    def test_short_keyword(self):
        assert cve._lookup_nvd_cves("") == []
        assert cve._lookup_nvd_cves("ab") == []

    def test_success(self, monkeypatch):
        monkeypatch.setattr(
            cve.urllib.request,
            "urlopen",
            lambda *a, **k: _Resp(json.dumps(_nvd_payload()).encode()),
        )
        records = cve._lookup_nvd_cves("openssl")
        assert records[0]["id"] == "CVE-1"
        assert records[0]["score"] == 9.1

    def test_cache_hit(self, monkeypatch):
        monkeypatch.setattr(
            cve.urllib.request,
            "urlopen",
            lambda *a, **k: _Resp(json.dumps(_nvd_payload()).encode()),
        )
        first = cve._lookup_nvd_cves("openssl")
        second = cve._lookup_nvd_cves("openssl")
        assert first is second

    def test_budget_exhausted(self):
        cve._CVE_BUDGET = 0
        assert cve._lookup_nvd_cves("openssl") == []

    def test_rate_limit_wait(self, monkeypatch):
        calls = []
        monkeypatch.setattr(cve._time, "sleep", lambda s: calls.append(s))
        monkeypatch.setattr(cve._time, "monotonic", lambda: 100.0)
        monkeypatch.setattr(
            cve.urllib.request,
            "urlopen",
            lambda *a, **k: _Resp(b'{"vulnerabilities": []}'),
        )
        cve._CVE_LAST_REQUEST = 100.0
        cve._lookup_nvd_cves("openssl")
        assert calls

    def test_network_error(self, monkeypatch):
        def boom(*a, **k):
            raise urllib.error.URLError("x")

        monkeypatch.setattr(cve.urllib.request, "urlopen", boom)
        assert cve._lookup_nvd_cves("openssl") == []


class TestBannerProduct:
    def test_regex(self):
        assert cve._banner_product("OpenSSH_9", "ssh", 22) == "openssh"

    def test_ssh_fallback(self):
        assert cve._banner_product("", "ssh", 22) == "openssh"

    def test_mqtt(self):
        assert cve._banner_product("mqtt", "mqtt", 1883) == "mosquitto"

    def test_realvnc(self):
        assert cve._banner_product("RealVNC 5", "vnc", 5900) == "realvnc"

    def test_dnsmasq(self):
        assert cve._banner_product("dnsmasq", "dns", 53) == "dnsmasq"

    def test_none(self):
        assert cve._banner_product("nothing", "?", 9999) == ""


class TestAssessOnePort:
    def _assess(self, monkeypatch, **record):
        monkeypatch.setattr(cve, "_lookup_nvd_cves", lambda kw: [])
        base = {"port": 9999, "host": "", "service": "?", "banner": ""}
        base.update(record)
        return cve._assess_one_port(base)

    def test_default(self, monkeypatch):
        assert self._assess(monkeypatch)["severity"] == "LOW"

    def test_netgear_current(self, monkeypatch):
        verdict = self._assess(
            monkeypatch,
            port=80,
            service="http",
            banner="NETGEAR R6700v3 firmware 1.0.5.128_10.0.104",
        )
        assert "NETGEAR-baseline" in verdict["cves"][0]["id"]

    def test_netgear_outdated(self, monkeypatch):
        verdict = self._assess(
            monkeypatch,
            port=80,
            service="http",
            banner="NETGEAR R6700v3 firmware 1.0.3.88",
        )
        assert verdict["cves"]

    def test_netgear_unconfirmed(self, monkeypatch):
        verdict = self._assess(
            monkeypatch, port=80, service="http", banner="NETGEAR httpd"
        )
        assert "not confirmed" in verdict["risks"][0]

    def test_dns_current(self, monkeypatch):
        monkeypatch.setattr(
            "iiatool.scan._probe_dns_version",
            lambda ip, timeout=3.0: "dnsmasq-2.93",
        )
        verdict = self._assess(
            monkeypatch, port=53, service="dns", host="1.1.1.1"
        )
        assert verdict["cves"] == []

    def test_dns_2_87(self, monkeypatch):
        monkeypatch.setattr(
            "iiatool.scan._probe_dns_version",
            lambda ip, timeout=3.0: "dnsmasq-2.88",
        )
        verdict = self._assess(
            monkeypatch, port=53, service="dns", host="1.1.1.1"
        )
        assert verdict["cves"]

    def test_dns_2_86(self, monkeypatch):
        monkeypatch.setattr(
            "iiatool.scan._probe_dns_version",
            lambda ip, timeout=3.0: "dnsmasq-2.86",
        )
        verdict = self._assess(
            monkeypatch, port=53, service="dns", host="1.1.1.1"
        )
        assert verdict["cves"]

    def test_dns_2_83(self, monkeypatch):
        monkeypatch.setattr(
            "iiatool.scan._probe_dns_version",
            lambda ip, timeout=3.0: "dnsmasq-2.84",
        )
        verdict = self._assess(
            monkeypatch, port=53, service="dns", host="1.1.1.1"
        )
        assert verdict["cves"]

    def test_dns_old(self, monkeypatch):
        monkeypatch.setattr(
            "iiatool.scan._probe_dns_version",
            lambda ip, timeout=3.0: "dnsmasq-2.80",
        )
        verdict = self._assess(
            monkeypatch, port=53, service="dns", host="1.1.1.1"
        )
        assert verdict["cves"]

    def test_dns_no_version(self, monkeypatch):
        monkeypatch.setattr(
            "iiatool.scan._probe_dns_version",
            lambda ip, timeout=3.0: "dnsmasq",
        )
        verdict = self._assess(
            monkeypatch, port=53, service="dns", host="1.1.1.1"
        )
        assert "version not confirmed" in verdict["risks"][0]

    def test_dns_bind(self, monkeypatch):
        monkeypatch.setattr(
            "iiatool.scan._probe_dns_version",
            lambda ip, timeout=3.0: "bind 9.18",
        )
        verdict = self._assess(
            monkeypatch, port=53, service="dns", host="1.1.1.1"
        )
        assert verdict["cves"]

    def test_dns_no_host(self, monkeypatch):
        verdict = self._assess(monkeypatch, port=53, service="dns", host="")
        assert verdict is not None

    def test_haproxy(self, monkeypatch):
        verdict = self._assess(
            monkeypatch,
            port=8443,
            service="https-alt",
            banner="Server: haproxy",
        )
        assert verdict["cves"]

    def test_apache(self, monkeypatch):
        verdict = self._assess(
            monkeypatch,
            port=443,
            service="https",
            banner="Server: Apache/2.4.49",
        )
        assert verdict["cves"]

    def test_realvnc(self, monkeypatch):
        verdict = self._assess(
            monkeypatch, port=5900, service="vnc", banner="RealVNC 5.3"
        )
        assert verdict["cves"]

    def test_live_lookup(self, monkeypatch):
        monkeypatch.setattr(
            cve,
            "_lookup_nvd_cves",
            lambda kw: [{"id": "CVE-9", "score": 8.0, "summary": "x"}],
        )
        verdict = cve._assess_one_port(
            {
                "port": 80,
                "host": "",
                "service": "http",
                "banner": "Server: nginx/1.20",
            }
        )
        assert any(c["id"] == "CVE-9" for c in verdict["cves"])


class TestAssessVulnerabilities:
    def test_no_ports(self):
        intel = _init_intel("1.1.1.1", "00:11:22:33:44:55")
        intel["open_ports"] = []
        cve._assess_vulnerabilities(intel)
        assert intel["vulnerabilities"]["ports_exposed"] == 0

    def test_with_findings(self, monkeypatch):
        verdicts = {
            23: {
                "port": 23,
                "service": "telnet",
                "severity": "HIGH",
                "cves": [{"id": "CVE-X"}],
                "top_score": 9.0,
            },
            80: {"port": 80, "service": "http", "severity": "LOW", "cves": []},
        }
        monkeypatch.setattr(
            cve, "_assess_one_port", lambda rec: verdicts[rec["port"]]
        )
        intel = _init_intel("1.1.1.1", "00:11:22:33:44:55")
        intel["open_ports"] = [{"port": 23}, {"port": 80}]
        cve._assess_vulnerabilities(intel)
        assert intel["vulnerabilities"]["findings"][0]["top_cve"] == "CVE-X"
        assert intel["blue_team_risk_assessment"]

    def test_finding_without_cve(self, monkeypatch):
        monkeypatch.setattr(
            cve,
            "_assess_one_port",
            lambda rec: {
                "port": 23,
                "service": "telnet",
                "severity": "CRITICAL",
                "cves": [],
            },
        )
        intel = _init_intel("1.1.1.1", "00:11:22:33:44:55")
        intel["open_ports"] = [{"port": 23}]
        cve._assess_vulnerabilities(intel)
        assert intel["vulnerabilities"]["findings"][0]["top_cve"] is None


class TestWifiBtSecurity:
    def test_open_wifi(self):
        intel = _init_intel("", "00:11:22:33:44:55")
        intel["target"]["name"] = "net"
        intel["wifi"] = {}
        cve._assess_wifi_security(
            intel, {"security": "Open", "band": "2.4 GHz"}
        )
        assert intel["blue_team_risk_assessment"][0]["severity"] == "HIGH"

    def test_secured_wifi(self):
        intel = _init_intel("", "00:11:22:33:44:55")
        intel["target"]["name"] = "net"
        intel["wifi"] = {}
        cve._assess_wifi_security(
            intel, {"security": "WPA3 Personal", "band": "5 GHz"}
        )
        assert intel["wifi"]["hardening"]

    def test_bt_security(self):
        intel = _init_intel("", "aa:bb:cc:dd:ee:ff")
        intel["target"]["name"] = "peer"
        cve._assess_bt_security(intel, {})
        assert (
            intel["blue_team_risk_assessment"][0]["severity"]
            == "INFORMATIONAL"
        )
