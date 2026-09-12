"""Tests for the Wi-Fi scanning, discovery, and audit phases."""

from iiatool import scan


class TestChannelBand:
    def test_24ghz(self):
        assert scan._channel_band("6") == "2.4 GHz"

    def test_5ghz(self):
        assert scan._channel_band("36") == "5 GHz"

    def test_unknown(self):
        assert scan._channel_band("") == "unknown"


AIRPORT_SAMPLE = (
    "SSID BSSID RSSI CHANNEL HT CC SECURITY (auth/unicast/group)\n"
    "MyWifi aa:bb:cc:dd:ee:ff -45 6 Y US WPA2(PSK/AES/AES)\n"
    "Guest a1:b2:c3:d4:e5:f6 -77 149 Y US WPA2(PSK/TKIP/AES)\n"
)


class TestParseAirportScan:
    def test_parse_two_networks(self):
        networks = scan._parse_airport_scan(AIRPORT_SAMPLE)
        assert len(networks) == 2
        assert networks[0]["ssid"] == "MyWifi"
        assert networks[0]["bssid"] == "AA:BB:CC:DD:EE:FF"
        assert networks[0]["band"] == "2.4 GHz"
        assert networks[1]["band"] == "5 GHz"

    def test_security_captured(self):
        networks = scan._parse_airport_scan(AIRPORT_SAMPLE)
        assert networks[0]["security"] == "WPA2(PSK/AES/AES)"

    def test_empty_rows(self):
        assert scan._parse_airport_scan("") == []


SYSPROF_SAMPLE = """   Current Network Information:
            MyWifi:
               PHY Mode: 802.11ac
               Channel: 44 (5GHz, 80 MHz)
               Security: WPA2 Personal
               Signal / Noise: -45 dBm / -90 dBm
   Other Local Wi-Fi Networks:
            Guest:
               PHY Mode: 802.11ac
               Channel: 6
               Security: WPA2 Personal
               Signal / Noise: -60 dBm / -90 dBm
"""


class TestParseSysprofWifi:
    def test_parse_networks_with_band(self):
        networks = scan._parse_sysprof_wifi(SYSPROF_SAMPLE)
        assert len(networks) == 2
        by_ssid = {n["ssid"]: n for n in networks}
        assert by_ssid["MyWifi"]["band"] == "5 GHz"
        assert by_ssid["MyWifi"]["channel"] == "44"
        assert by_ssid["MyWifi"]["current"] is True
        assert by_ssid["Guest"]["current"] is False

    def test_empty_output(self):
        assert scan._parse_sysprof_wifi("") == []


class TestSysprofBandMap:
    def test_band_map(self):
        out = "  Supported Channels: 1, 2 (2GHz) 36, 40 (5GHz)"
        mapping = scan._sysprof_band_map(out)
        assert mapping[2] == "2.4 GHz"
        assert mapping[40] == "5 GHz"


class TestScanHostPortsParsing:
    def test_empty_ip_returns_empty(self):
        assert scan._scan_host_ports("") == []


class TestAuditWifiNetwork:
    def test_audits_network_and_adds_risk(self, monkeypatch):
        spy = {}
        monkeypatch.setattr(
            scan, "_auto_vendor_lookup", lambda intel, mac: spy.update(mac=mac)
        )

        def fake_wifi_security(intel, network):
            intel["blue_team_risk_assessment"].append({"severity": "INFO"})

        monkeypatch.setattr(
            "iiatool.cve._assess_wifi_security", fake_wifi_security
        )
        network = {
            "bssid": "aa:bb:cc:dd:ee:ff",
            "ssid": "MyWifi",
            "band": "5 GHz",
        }
        intel = scan._audit_wifi_network(network)
        assert intel["device_type"] == "wifi"
        assert intel["target"]["name"] == "MyWifi"
        assert spy["mac"] == "aa:bb:cc:dd:ee:ff"


class TestAuditBtClassicPeer:
    def test_audits_peer(self, monkeypatch):
        monkeypatch.setattr(
            scan, "_auto_vendor_lookup", lambda intel, mac: None
        )

        def fake_bt_security(intel, peer):
            intel["blue_team_risk_assessment"].append({"severity": "INFO"})

        monkeypatch.setattr(
            "iiatool.cve._assess_bt_security", fake_bt_security
        )
        peer = {"name": "Headset", "address": "aa:bb:cc:dd:ee:ff"}
        intel = scan._audit_bt_classic_peer(peer)
        assert intel["device_type"] == "bluetooth_classic"
        assert intel["bluetooth_classic"]["major_type"] == ""
