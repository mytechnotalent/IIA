"""Coverage tests for scan.py using fakes for subprocess and sockets."""

import json
import struct
import subprocess
import types

from iiatool import scan


def _run_stub(stdout="", returncode=0, raises=None):
    """Build a subprocess.run replacement."""

    def stub(*args, **kwargs):
        if raises:
            raise raises
        return types.SimpleNamespace(stdout=stdout, returncode=returncode)

    return stub


class _Sock:
    """Fake connected socket with queued recv responses."""

    def __init__(self, responses=(), raise_recv=False):
        """Initialize with queued responses."""
        self.responses = list(responses)
        self.raise_recv = raise_recv

    def __enter__(self):
        """Enter context."""
        return self

    def __exit__(self, *args):
        """Exit context."""
        return False

    def settimeout(self, value):
        """Accept a timeout."""
        return None

    def sendall(self, data):
        """Record sent bytes."""
        self.sent = data

    def recv(self, size):
        """Return the next queued response or empty bytes."""
        if self.raise_recv:
            raise OSError("recv")
        return self.responses.pop(0) if self.responses else b""

    def close(self):
        """Close the socket."""
        return None


class _UDP:
    """Fake UDP socket."""

    def __init__(self, data=None):
        """Initialize with response data."""
        self.data = data

    def settimeout(self, value):
        """Accept a timeout."""
        return None

    def sendto(self, query, addr):
        """Record the query."""
        self.query = query

    def recvfrom(self, size):
        """Return the response or raise."""
        if self.data is None:
            raise OSError("timeout")
        return self.data, ("1.1.1.1", 53)

    def close(self):
        """Close the socket."""
        return None


class _SockMod:
    """Fake socket module."""

    AF_INET = 2
    SOCK_DGRAM = 2
    SOCK_STREAM = 1

    def __init__(self, conn=None, sock=None):
        """Store factories."""
        self.create_connection = conn
        self.socket = sock


def _patch_conn(monkeypatch, sock):
    """Patch scan.socket.create_connection to return a socket."""
    monkeypatch.setattr(scan, "socket", _SockMod(conn=lambda *a, **k: sock))


class TestChannelAndParsers:
    def test_channel_band(self):
        assert scan._channel_band("") == "unknown"
        assert scan._channel_band("6") == "2.4 GHz"
        assert scan._channel_band("36") == "5 GHz"

    def test_airport(self):
        rows = (
            "SSID BSSID RSSI CHANNEL HT CC SECURITY\n"
            "MyNet aa:bb:cc:dd:ee:ff -40 6 Y US WPA2\n"
            "badline no mac here\n"
        )
        nets = scan._parse_airport_scan(rows)
        assert nets[0]["bssid"] == "AA:BB:CC:DD:EE:FF"
        assert nets[0]["band"] == "2.4 GHz"

    def test_airport_short(self):
        rows = "hdr\nX aa:bb:cc:dd:ee:ff\n"
        nets = scan._parse_airport_scan(rows)
        assert nets[0]["rssi"] == "N/A"

    def test_sysprof_band_map(self):
        assert scan._sysprof_band_map("1 (2GHz)") == {1: "2.4 GHz"}

    def test_sysprof_wifi(self):
        out = "\n".join(
            [
                "          Current Network Information:",
                "            MyNet:",
                "              PHY Mode: 802.11ac",
                "              Channel: 36 (5GHz, 80MHz)",
                "              Security: WPA2 Personal",
                "              Signal / Noise: -40 dBm",
                "          Other Local Wi-Fi Networks:",
                "            Neighbor:",
                "              Channel: 6",
                "              Network Type: Infrastructure",
            ]
        )
        nets = scan._parse_sysprof_wifi(out)
        assert nets[0]["ssid"] == "MyNet"
        assert nets[0]["channel"] == "36"
        assert nets[1]["network_type"] == "Infrastructure"


class TestCorewlan:
    def test_success(self, monkeypatch):
        payload = json.dumps(
            [
                {
                    "ssid": "",
                    "bssid": "aa",
                    "band": "5 GHz",
                    "channel": 36,
                    "rssi": -40,
                    "security": "WPA3",
                }
            ]
        )
        monkeypatch.setattr(
            scan.subprocess, "run", _run_stub(payload, returncode=0)
        )
        nets = scan._run_corewlan_scan()
        assert nets[0]["ssid"] == "(hidden)"

    def test_launch_error(self, monkeypatch):
        monkeypatch.setattr(
            scan.subprocess, "run", _run_stub(raises=OSError("x"))
        )
        assert scan._run_corewlan_scan() == []

    def test_nonzero(self, monkeypatch):
        monkeypatch.setattr(
            scan.subprocess, "run", _run_stub("", returncode=1)
        )
        assert scan._run_corewlan_scan() == []

    def test_bad_json(self, monkeypatch):
        monkeypatch.setattr(scan.subprocess, "run", _run_stub("not json"))
        assert scan._run_corewlan_scan() == []

    def test_error_payload(self, monkeypatch):
        monkeypatch.setattr(
            scan.subprocess, "run", _run_stub(json.dumps({"error": "no wifi"}))
        )
        assert scan._run_corewlan_scan() == []


class TestAirportBinary:
    def test_found(self, monkeypatch):
        monkeypatch.setattr(scan.os.path, "exists", lambda p: True)
        assert scan._find_airport_binary()

    def test_which(self, monkeypatch):
        monkeypatch.setattr(scan.os.path, "exists", lambda p: False)
        monkeypatch.setattr(
            scan.subprocess, "run", _run_stub("/usr/bin/airport\n")
        )
        assert scan._find_airport_binary() == "/usr/bin/airport"

    def test_error(self, monkeypatch):
        monkeypatch.setattr(scan.os.path, "exists", lambda p: False)
        monkeypatch.setattr(
            scan.subprocess, "run", _run_stub(raises=OSError("x"))
        )
        assert scan._find_airport_binary() == ""


class TestWifiScan:
    def test_corewlan_first(self, monkeypatch):
        monkeypatch.setattr(
            scan, "_run_corewlan_scan", lambda: [{"ssid": "x"}]
        )
        assert scan._run_wifi_scan() == [{"ssid": "x"}]

    def test_airport_fallback(self, monkeypatch):
        monkeypatch.setattr(scan, "_run_corewlan_scan", lambda: [])
        monkeypatch.setattr(
            scan, "_find_airport_binary", lambda: "/bin/airport"
        )
        monkeypatch.setattr(
            scan, "_parse_airport_scan", lambda out: [{"ssid": "y"}]
        )
        monkeypatch.setattr(scan.subprocess, "run", _run_stub("data"))
        assert scan._run_wifi_scan() == [{"ssid": "y"}]

    def test_airport_error_then_sysprof(self, monkeypatch):
        monkeypatch.setattr(scan, "_run_corewlan_scan", lambda: [])
        monkeypatch.setattr(
            scan, "_find_airport_binary", lambda: "/bin/airport"
        )
        monkeypatch.setattr(scan, "_parse_airport_scan", lambda out: [])
        monkeypatch.setattr(
            scan, "_parse_sysprof_wifi", lambda out: [{"ssid": "z"}]
        )
        monkeypatch.setattr(scan.os.path, "exists", lambda p: True)
        monkeypatch.setattr(scan.subprocess, "run", _run_stub("data"))
        assert scan._run_wifi_scan() == [{"ssid": "z"}]

    def test_no_sysprof(self, monkeypatch):
        monkeypatch.setattr(scan, "_run_corewlan_scan", lambda: [])
        monkeypatch.setattr(scan, "_find_airport_binary", lambda: "")
        monkeypatch.setattr(scan.os.path, "exists", lambda p: False)
        assert scan._run_wifi_scan() == []

    def test_sysprof_error(self, monkeypatch):
        monkeypatch.setattr(scan, "_run_corewlan_scan", lambda: [])
        monkeypatch.setattr(scan, "_find_airport_binary", lambda: "")
        monkeypatch.setattr(scan.os.path, "exists", lambda p: True)
        monkeypatch.setattr(
            scan.subprocess, "run", _run_stub(raises=OSError("x"))
        )
        assert scan._run_wifi_scan() == []


class TestBtClassic:
    def test_no_sysprof(self, monkeypatch):
        monkeypatch.setattr(scan.os.path, "exists", lambda p: False)
        assert scan._scan_bt_classic() == []

    def test_parse(self, monkeypatch):
        out = (
            "Connected:\n"
            "        Headset:\n"
            "          Address: AA-BB-CC-DD-EE-FF\n"
            "          RSSI: -50\n"
            "          Major Type: Audio\n"
        )
        monkeypatch.setattr(scan.os.path, "exists", lambda p: True)
        monkeypatch.setattr(scan.subprocess, "run", _run_stub(out))
        peers = scan._scan_bt_classic()
        assert peers[0]["address"] == "aa:bb:cc:dd:ee:ff"
        assert peers[0]["major_type"] == "Audio"

    def test_bad_address(self, monkeypatch):
        out = "\n".join(
            [
                "Connected:",
                "        Peer:",
                "          Address: AA:BB:CC",
            ]
        )
        monkeypatch.setattr(scan.os.path, "exists", lambda p: True)
        monkeypatch.setattr(scan.subprocess, "run", _run_stub(out))
        assert scan._scan_bt_classic()[0]["address"] == "AA:BB:CC"

    def test_error(self, monkeypatch):
        monkeypatch.setattr(scan.os.path, "exists", lambda p: True)
        monkeypatch.setattr(
            scan.subprocess, "run", _run_stub(raises=OSError("x"))
        )
        assert scan._scan_bt_classic() == []


class TestMdns:
    def test_missing(self, monkeypatch):
        monkeypatch.setattr(scan.os.path, "exists", lambda p: False)
        assert scan._scan_mdns_services() == []

    def test_timeout_stdout(self, monkeypatch):
        def stub(*a, **k):
            raise subprocess.TimeoutExpired(
                "cmd", 4, output="Add _x._y.local.\n"
            )

        monkeypatch.setattr(scan.os.path, "exists", lambda p: True)
        monkeypatch.setattr(scan.subprocess, "run", stub)
        services = scan._scan_mdns_services()
        assert services

    def test_os_error(self, monkeypatch):
        monkeypatch.setattr(scan.os.path, "exists", lambda p: True)
        monkeypatch.setattr(
            scan.subprocess, "run", _run_stub(raises=OSError("x"))
        )
        assert scan._scan_mdns_services() == []

    def test_parse(self, monkeypatch):
        out = "12:00 Add _airplay._tcp.local. _airplay._tcp.local.\nignored\n"
        monkeypatch.setattr(scan.os.path, "exists", lambda p: True)
        monkeypatch.setattr(scan.subprocess, "run", _run_stub(out))
        assert scan._scan_mdns_services() == ["_airplay._tcp.local."]


class TestProbePort:
    def test_open(self, monkeypatch):
        _patch_conn(monkeypatch, _Sock())
        assert scan._probe_port("1.1.1.1", 80) == 80

    def test_closed(self, monkeypatch):
        def boom(*a, **k):
            raise OSError("refused")

        monkeypatch.setattr(scan, "socket", _SockMod(conn=boom))
        assert scan._probe_port("1.1.1.1", 80) == 0


class TestNetgearProbe:
    def test_plain(self, monkeypatch):
        _patch_conn(
            monkeypatch, _Sock([b"Firmware=V1.0.5.128 Model=R6700v3", b""])
        )
        tag = scan._netgear_firmware_probe("1.1.1.1", 80)
        assert "R6700v3" in tag

    def test_tls(self, monkeypatch):
        sock = _Sock([b"Firmware=V1 Model=R", b""])
        monkeypatch.setattr(
            scan, "socket", _SockMod(conn=lambda *a, **k: sock)
        )

        class FakeCtx:
            def set_ciphers(self, value):
                raise scan.ssl.SSLError("bad")

            def wrap_socket(self, raw, server_hostname=None):
                return sock

        monkeypatch.setattr(
            scan.ssl, "_create_unverified_context", lambda: FakeCtx()
        )
        assert "R" in scan._netgear_firmware_probe("1.1.1.1", 443, tls=True)

    def test_error(self, monkeypatch):
        def boom(*a, **k):
            raise OSError("x")

        monkeypatch.setattr(scan, "socket", _SockMod(conn=boom))
        assert scan._netgear_firmware_probe("1.1.1.1", 80) == ""

    def test_recv_error(self, monkeypatch):
        _patch_conn(monkeypatch, _Sock(raise_recv=True))
        assert scan._netgear_firmware_probe("1.1.1.1", 80) == ""


class TestRfbProbe:
    def test_not_rfb(self, monkeypatch):
        _patch_conn(monkeypatch, _Sock([b"HTTP/1.0"]))
        assert scan._probe_rfb_vendor("1.1.1.1") == ""

    def test_apple(self, monkeypatch):
        _patch_conn(monkeypatch, _Sock([b"RFB 003.889\n", bytes([1, 30])]))
        assert scan._probe_rfb_vendor("1.1.1.1") == "Apple Screen Sharing"

    def test_generic(self, monkeypatch):
        _patch_conn(monkeypatch, _Sock([b"RFB 003.008\n", bytes([1, 2])]))
        assert scan._probe_rfb_vendor("1.1.1.1").startswith("RFB security")

    def test_empty(self, monkeypatch):
        _patch_conn(monkeypatch, _Sock([b"RFB 003.008\n", b""]))
        assert scan._probe_rfb_vendor("1.1.1.1") == "RFB"

    def test_error(self, monkeypatch):
        def boom(*a, **k):
            raise OSError("x")

        monkeypatch.setattr(scan, "socket", _SockMod(conn=boom))
        assert scan._probe_rfb_vendor("1.1.1.1") == ""


class TestGrabBanner:
    def test_http(self, monkeypatch):
        _patch_conn(monkeypatch, _Sock([b"HTTP/1.0 200 OK"]))
        assert "HTTP" in scan._grab_banner("1.1.1.1", 80)

    def test_tls(self, monkeypatch):
        _patch_conn(monkeypatch, _Sock([b"\x16\x03"]))
        assert scan._grab_banner("1.1.1.1", 443) is not None

    def test_ssh(self, monkeypatch):
        _patch_conn(monkeypatch, _Sock([b"SSH-2.0-OpenSSH"]))
        assert "SSH" in scan._grab_banner("1.1.1.1", 22)

    def test_mqtt(self, monkeypatch):
        _patch_conn(monkeypatch, _Sock([b"MQTT"]))
        assert scan._grab_banner("1.1.1.1", 1883) == "MQTT"

    def test_netgear_tag(self, monkeypatch):
        _patch_conn(monkeypatch, _Sock([b"NETGEAR httpd"]))
        monkeypatch.setattr(
            scan,
            "_netgear_firmware_probe",
            lambda ip, port: "NETGEAR R firmware 1.0.5",
        )
        assert "1.0.5" in scan._grab_banner("1.1.1.1", 80)

    def test_connect_error(self, monkeypatch):
        def boom(*a, **k):
            raise OSError("x")

        monkeypatch.setattr(scan, "socket", _SockMod(conn=boom))
        assert scan._grab_banner("1.1.1.1", 80) == ""

    def test_recv_error(self, monkeypatch):
        _patch_conn(monkeypatch, _Sock(raise_recv=True))
        assert scan._grab_banner("1.1.1.1", 80) == ""


class TestDnsProbe:
    def _response(self, txt=b"dnsmasq-2.93"):
        name = b"\x07version\x04bind\x00"
        header = struct.pack("!HHHHHH", 0xAAAA, 0x8180, 1, 1, 0, 0)
        question = name + struct.pack("!HH", 16, 3)
        rdata = bytes([len(txt)]) + txt
        answer = (
            b"\xc0\x0c" + struct.pack("!HHIH", 16, 3, 0, len(rdata)) + rdata
        )
        return header + question + answer

    def test_success(self, monkeypatch):
        udp = _UDP(self._response())
        monkeypatch.setattr(scan, "socket", _SockMod(sock=lambda *a: udp))
        assert scan._probe_dns_version("1.1.1.1") == "dnsmasq-2.93"

    def test_timeout(self, monkeypatch):
        monkeypatch.setattr(
            scan, "socket", _SockMod(sock=lambda *a: _UDP(None))
        )
        assert scan._probe_dns_version("1.1.1.1") == ""

    def test_short(self, monkeypatch):
        monkeypatch.setattr(
            scan, "socket", _SockMod(sock=lambda *a: _UDP(b"short"))
        )
        assert scan._probe_dns_version("1.1.1.1") == ""

    def test_bad_flags(self, monkeypatch):
        data = bytearray(self._response())
        data[2:4] = b"\x00\x00"
        monkeypatch.setattr(
            scan, "socket", _SockMod(sock=lambda *a: _UDP(bytes(data)))
        )
        assert scan._probe_dns_version("1.1.1.1") == ""

    def test_no_answers(self, monkeypatch):
        header = struct.pack("!HHHHHH", 0xAAAA, 0x8180, 1, 0, 0, 0)
        name = b"\x07version\x04bind\x00" + struct.pack("!HH", 16, 3)
        monkeypatch.setattr(
            scan, "socket", _SockMod(sock=lambda *a: _UDP(header + name))
        )
        assert scan._probe_dns_version("1.1.1.1") == ""


class TestScanHostPorts:
    def test_empty_ip(self):
        assert scan._scan_host_ports("") == []

    def test_custom_ports(self, monkeypatch):
        monkeypatch.setattr(
            scan, "_probe_port", lambda ip, p: p if p in (80, 81) else 0
        )
        monkeypatch.setattr(scan, "_grab_banner", lambda ip, p: "b")
        monkeypatch.setattr(
            scan, "_netgear_firmware_probe", lambda *a, **k: ""
        )
        monkeypatch.setattr(scan, "_probe_rfb_vendor", lambda ip: "")
        result = scan._scan_host_ports("1.1.1.1", "80-81")
        assert [r["port"] for r in result] == [80, 81]

    def test_default_ports_and_tags(self, monkeypatch):
        monkeypatch.setattr(
            scan, "_probe_port", lambda ip, p: 443 if p == 443 else 0
        )
        monkeypatch.setattr(scan, "_grab_banner", lambda ip, p: "")
        monkeypatch.setattr(
            scan,
            "_netgear_firmware_probe",
            lambda ip, p, tls=False: "NETGEAR R firmware 1.0.5",
        )
        monkeypatch.setattr(scan, "_probe_rfb_vendor", lambda ip: "")
        result = scan._scan_host_ports("1.1.1.1")
        assert "1.0.5" in result[0]["banner"]

    def test_rfb_tag(self, monkeypatch):
        monkeypatch.setattr(
            scan, "_probe_port", lambda ip, p: 5900 if p == 5900 else 0
        )
        monkeypatch.setattr(scan, "_grab_banner", lambda ip, p: "RFB")
        monkeypatch.setattr(
            scan, "_netgear_firmware_probe", lambda *a, **k: ""
        )
        monkeypatch.setattr(
            scan, "_probe_rfb_vendor", lambda ip: "Apple Screen Sharing"
        )
        result = scan._scan_host_ports("1.1.1.1")
        assert "Apple" in result[0]["banner"]


class TestAuditHosts:
    def test_audit_host(self, monkeypatch):
        monkeypatch.setattr(
            scan, "_scan_host_ports", lambda ip, p: [{"port": 80}]
        )
        monkeypatch.setattr(scan, "_auto_vendor_lookup", lambda *a: None)
        monkeypatch.setattr(
            "iiatool.cve._assess_vulnerabilities", lambda i: None
        )
        monkeypatch.setattr(
            "iiatool.network._flow_matches", lambda f, ip: True
        )
        intel = scan._audit_host_intel(
            {"ip": "1.1.1.1", "mac": "aa", "name": "h"}, [{"src": "1.1.1.1"}]
        )
        assert intel["open_ports"]

    def test_audit_wifi(self, monkeypatch):
        monkeypatch.setattr(scan, "_auto_vendor_lookup", lambda *a: None)
        monkeypatch.setattr(
            "iiatool.cve._assess_wifi_security", lambda i, n: None
        )
        intel = scan._audit_wifi_network(
            {
                "bssid": "aa",
                "ssid": "x",
                "band": "5 GHz",
                "channel": 36,
                "rssi": -40,
                "security": "WPA3",
            }
        )
        assert intel["device_type"] == "wifi"

    def test_audit_bt(self, monkeypatch):
        monkeypatch.setattr(scan, "_auto_vendor_lookup", lambda *a: None)
        monkeypatch.setattr(
            "iiatool.cve._assess_bt_security", lambda i, p: None
        )
        intel = scan._audit_bt_classic_peer({"address": "aa", "name": "p"})
        assert intel["device_type"] == "bluetooth_classic"


class TestScanEdges:
    def test_sysprof_edges(self):
        out = "\n".join(
            [
                "garbage",
                "          Current Network Information:",
                "            MyNet:",
                "              12345",
                "              Channel: 6",
            ]
        )
        nets = scan._parse_sysprof_wifi(out)
        assert nets[0]["ssid"] == "MyNet"

    def test_airport_run_error(self, monkeypatch):
        monkeypatch.setattr(scan, "_run_corewlan_scan", lambda: [])
        monkeypatch.setattr(
            scan, "_find_airport_binary", lambda: "/bin/airport"
        )
        monkeypatch.setattr(scan, "_parse_sysprof_wifi", lambda out: [])
        monkeypatch.setattr(scan.os.path, "exists", lambda p: True)
        monkeypatch.setattr(
            scan.subprocess, "run", _run_stub(raises=OSError("x"))
        )
        assert scan._run_wifi_scan() == []

    def test_bt_blank_before_start(self, monkeypatch):
        out = "\n".join(
            [
                "",
                "Connected:",
                "",
                "        Peer:",
                "          Address: aa:bb:cc:dd:ee:ff",
            ]
        )
        monkeypatch.setattr(scan.os.path, "exists", lambda p: True)
        monkeypatch.setattr(scan.subprocess, "run", _run_stub(out))
        assert scan._scan_bt_classic()[0]["address"] == "aa:bb:cc:dd:ee:ff"

    def test_netgear_no_firmware(self, monkeypatch):
        _patch_conn(monkeypatch, _Sock([b"no firmware here", b""]))
        assert scan._netgear_firmware_probe("1.1.1.1", 80) == ""

    def test_netgear_close_error(self, monkeypatch):
        class BadClose(_Sock):
            def close(self):
                raise OSError("close")

        _patch_conn(monkeypatch, BadClose([b"Firmware=V1 Model=R6700v3", b""]))
        assert "R6700v3" in scan._netgear_firmware_probe("1.1.1.1", 80)

    def test_ports_empty_token(self, monkeypatch):
        monkeypatch.setattr(
            scan, "_probe_port", lambda ip, p: p if p in (80, 81) else 0
        )
        monkeypatch.setattr(scan, "_grab_banner", lambda ip, p: "")
        monkeypatch.setattr(
            scan, "_netgear_firmware_probe", lambda *a, **k: ""
        )
        monkeypatch.setattr(scan, "_probe_rfb_vendor", lambda ip: "")
        result = scan._scan_host_ports("1.1.1.1", ",80,81")
        assert [r["port"] for r in result] == [80, 81]

    def test_netgear_in_banner(self, monkeypatch):
        monkeypatch.setattr(
            scan, "_probe_port", lambda ip, p: 80 if p == 80 else 0
        )
        monkeypatch.setattr(
            scan,
            "_grab_banner",
            lambda ip, p: "NETGEAR R6700v3 firmware 1.0.5",
        )
        monkeypatch.setattr(scan, "_probe_rfb_vendor", lambda ip: "")
        result = scan._scan_host_ports("1.1.1.1")
        assert result[0]["port"] == 80


class TestDnsProbeEdges:
    def _question(self):
        name = b"\x07version\x04bind\x00"
        return (
            struct.pack("!HHHHHH", 1, 0x8180, 1, 1, 0, 0)
            + name
            + struct.pack("!HH", 16, 3)
        )

    def test_truncated_answer(self, monkeypatch):
        monkeypatch.setattr(
            scan, "socket", _SockMod(sock=lambda *a: _UDP(self._question()))
        )
        assert scan._probe_dns_version("1.1.1.1") == ""

    def test_full_name_answer(self, monkeypatch):
        name = b"\x07version\x04bind\x00"
        txt = b"dnsmasq-2.93"
        rdata = bytes([len(txt)]) + txt
        answer = name + struct.pack("!HHIH", 16, 3, 0, len(rdata)) + rdata
        data = struct.pack("!HHHHHH", 1, 0x8180, 1, 1, 0, 0) + name
        data += struct.pack("!HH", 16, 3) + answer
        monkeypatch.setattr(
            scan, "socket", _SockMod(sock=lambda *a: _UDP(data))
        )
        assert scan._probe_dns_version("1.1.1.1") == "dnsmasq-2.93"

    def test_short_answer(self, monkeypatch):
        name = b"\x07version\x04bind\x00"
        data = struct.pack("!HHHHHH", 1, 0x8180, 1, 1, 0, 0) + name
        data += struct.pack("!HH", 16, 3) + b"\xc0\x0c\x00"
        monkeypatch.setattr(
            scan, "socket", _SockMod(sock=lambda *a: _UDP(data))
        )
        assert scan._probe_dns_version("1.1.1.1") == ""

    def test_non_txt_answer(self, monkeypatch):
        name = b"\x07version\x04bind\x00"
        answer = (
            b"\xc0\x0c"
            + struct.pack("!HHIH", 1, 3, 0, 4)
            + b"\x01\x02\x03\x04"
        )
        data = struct.pack("!HHHHHH", 1, 0x8180, 1, 1, 0, 0) + name
        data += struct.pack("!HH", 16, 3) + answer
        monkeypatch.setattr(
            scan, "socket", _SockMod(sock=lambda *a: _UDP(data))
        )
        assert scan._probe_dns_version("1.1.1.1") == ""


class TestSpectrum:
    def test_scan(self, monkeypatch):
        monkeypatch.setattr(scan, "_audit_all_bluetooth", lambda t: ([1], [2]))
        monkeypatch.setattr(scan, "_run_wifi_scan", lambda: [1])
        monkeypatch.setattr(scan, "_scan_bt_classic", lambda: [1])
        monkeypatch.setattr(scan, "_scan_mdns_services", lambda: [1])
        monkeypatch.setattr(scan, "_ping_sweep", lambda: [1])
        spectrum, ble = scan._scan_radio_spectrum(1.0)
        assert spectrum["wifi_networks"] == [1] and ble == [2]


class TestScannerHelpers:
    def test_sysprof_attr_without_record(self):
        scan._sysprof_attr("  Foo: bar", None, {})

    def test_airport_proc_invalid(self, monkeypatch):
        monkeypatch.setattr(
            scan.subprocess, "run", _run_stub("", returncode=1)
        )
        assert scan._airport_proc("/bin/airport") is None

    def test_bt_attr_without_current(self):
        scan._bt_attr("  RSSI: -50", None)

    def test_mdns_token_no_match(self):
        assert scan._mdns_token("Add foo._bar") == ""
