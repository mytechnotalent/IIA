"""Coverage tests for pcap.py using fake scapy layers."""

import json
import types
import urllib.error

import pytest

from iiatool import pcap
from iiatool.utils import _init_intel


class _IP:
    """Sentinel IP layer type."""

    def __init__(self, src="1.1.1.1", dst="2.2.2.2", id=1, ttl=64):
        """Initialize the layer."""
        self.src, self.dst, self.id, self.ttl = src, dst, id, ttl


class _TCP:
    """Sentinel TCP layer type."""

    def __init__(self, seq=0, dport=443, sport=1234, window=100, payload=b""):
        """Initialize the layer."""
        self.seq, self.dport, self.sport = seq, dport, sport
        self.window, self.payload = window, payload


class _DNS:
    """Sentinel DNS layer type."""

    def __init__(self, qr=0, qname=None):
        """Initialize the layer."""
        self.qr = qr
        self.qd = types.SimpleNamespace(qname=qname) if qname else None


class _Pkt:
    """Fake scapy packet."""

    def __init__(self, ip=None, tcp=None, dns=None):
        """Initialize with optional layers."""
        self.ip, self.tcp, self.dns = ip, tcp, dns
        self.layers = set()
        if ip:
            self.layers.add(_IP)
        if tcp:
            self.layers.add(_TCP)
        if dns:
            self.layers.add(_DNS)

    def __getitem__(self, key):
        """Return the requested layer."""
        if key is _IP:
            return self.ip
        if key is _TCP:
            return self.tcp
        if key is _DNS:
            return self.dns
        raise KeyError(key)

    def haslayer(self, key):
        """Report layer presence."""
        return key in self.layers


@pytest.fixture(autouse=True)
def _fake_scapy(monkeypatch):
    """Install a fake scapy module for every test."""
    fake = types.SimpleNamespace(
        IP=_IP, TCP=_TCP, DNS=_DNS, rdpcap=lambda path: []
    )
    monkeypatch.setattr(pcap, "scapy", fake)
    yield


def _client_hello(name: bytes) -> bytes:
    """Build a payload matching the parser's expected offsets."""
    total = 55 + len(name)
    buf = bytearray(total)
    buf[0], buf[1], buf[2] = 0x16, 0x03, 0x01
    buf[6:9] = (total - 9).to_bytes(3, "big")
    buf[43] = 0
    buf[46] = 0
    ext_total = 6 + len(name)
    buf[47:49] = ext_total.to_bytes(2, "big")
    buf[49:51] = (0).to_bytes(2, "big")
    buf[51:53] = (5 + len(name)).to_bytes(2, "big")
    buf[53:55] = len(name).to_bytes(2, "big")
    buf[55: 55 + len(name)] = name
    return bytes(buf)


class TestTls:
    def test_is_tls(self):
        assert pcap._is_tls_app_data(b"\x17\x03\x03\x00\x00")
        assert not pcap._is_tls_app_data(b"\x16\x03\x03")

    def test_sni_short(self):
        assert pcap._tls_handshake_sni(b"") == ""
        assert pcap._tls_handshake_sni(b"\x15\x03") == ""

    def test_sni_valid(self):
        assert (
            pcap._tls_handshake_sni(_client_hello(b"host.example"))
            == "host.example"
        )

    def test_sni_truncated(self):
        payload = bytearray(_client_hello(b"host.example"))
        payload = bytes(payload[:20])
        assert pcap._tls_handshake_sni(payload) == ""

    def _hello_at(self, hs_end):
        buf = bytearray(max(hs_end, 50))
        buf[0], buf[1], buf[2] = 0x16, 0x03, 0x01
        buf[6:9] = (hs_end - 9).to_bytes(3, "big")
        buf[43] = 0
        buf[46] = 0
        return bytes(buf[:hs_end])

    def test_sni_cut_after_session(self):
        assert pcap._tls_handshake_sni(self._hello_at(44)) == ""

    def test_sni_cut_after_cipher(self):
        assert pcap._tls_handshake_sni(self._hello_at(46)) == ""

    def test_sni_cut_after_compression(self):
        assert pcap._tls_handshake_sni(self._hello_at(47)) == ""

    def test_sni_non_name_extension(self):
        payload = bytearray(_client_hello(b"host.example"))
        payload[49:51] = (0x0B).to_bytes(2, "big")
        assert pcap._tls_handshake_sni(bytes(payload)) == ""


class TestHttpMqtt:
    def test_http_short(self):
        assert pcap._extract_http_host(b"GET /") == ""

    def test_http_none(self):
        assert pcap._extract_http_host(b"GET / HTTP/1.1\r\n\r\n") == ""

    def test_http_host(self):
        payload = b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n"
        assert pcap._extract_http_host(payload) == "example.com"

    def test_mqtt_empty(self):
        assert pcap._extract_mqtt_topics(b"") == []

    def test_mqtt_publish(self):
        topic = b"t/1"
        payload = (
            bytes([0x30, len(topic) + 2])
            + len(topic).to_bytes(2, "big")
            + topic
        )
        assert "t/1" in pcap._extract_mqtt_topics(payload)

    def test_mqtt_connect(self):
        proto = b"MQTT"
        cid = b"dev1"
        payload = bytes([0x10, 0x10]) + len(proto).to_bytes(2, "big") + proto
        payload += b"\x04\x02" + len(cid).to_bytes(2, "big") + cid
        assert any(
            t.startswith("client_id:")
            for t in pcap._extract_mqtt_topics(payload)
        )

    def test_mqtt_malformed(self):
        assert pcap._extract_mqtt_topics(b"\x30") == []


class TestTcpMeta:
    def test_src_match(self):
        pkt = _Pkt(ip=_IP("1.1.1.1", "2.2.2.2"), tcp=_TCP())
        key, ep, stack = pcap._extract_tcp_meta(pkt, "1.1.1.1")
        assert ep == ("2.2.2.2", 443) and stack

    def test_dst_match(self):
        pkt = _Pkt(ip=_IP("2.2.2.2", "1.1.1.1"), tcp=_TCP())
        key, ep, stack = pcap._extract_tcp_meta(pkt, "1.1.1.1")
        assert ep == ("2.2.2.2", 1234) and stack is None

    def test_no_match(self):
        pkt = _Pkt(ip=_IP("3.3.3.3", "4.4.4.4"), tcp=_TCP())
        key, ep, stack = pcap._extract_tcp_meta(pkt, "1.1.1.1")
        assert ep is None


class TestState:
    def test_update_dns(self):
        st = {
            "tx_set": set(),
            "endpoints": {},
            "stack": {},
            "tls": False,
            "domains": set(),
            "mqtt_topics": set(),
        }
        pkt = _Pkt(
            ip=_IP("1.1.1.1", "2.2.2.2"),
            tcp=_TCP(payload=b""),
            dns=_DNS(0, "example.com."),
        )
        pcap._update_pcap_state(st, pkt, "1.1.1.1")
        assert "example.com" in st["domains"]

    def test_update_tls_and_http(self):
        st = {
            "tx_set": set(),
            "endpoints": {},
            "stack": {},
            "tls": False,
            "domains": set(),
            "mqtt_topics": set(),
        }
        payload = b"\x17\x03\x03GET / HTTP/1.1\r\nHost: h.example\r\n\r\n"
        pkt = _Pkt(ip=_IP("1.1.1.1", "2.2.2.2"), tcp=_TCP(payload=payload))
        pcap._update_pcap_state(st, pkt, "1.1.1.1")
        assert st["tls"] and "h.example" in st["domains"]

    def test_update_no_endpoint(self):
        st = {
            "tx_set": set(),
            "endpoints": {},
            "stack": {},
            "tls": False,
            "domains": set(),
            "mqtt_topics": set(),
        }
        pkt = _Pkt(ip=_IP("3.3.3.3", "4.4.4.4"), tcp=_TCP(payload=b""))
        pcap._update_pcap_state(st, pkt, "1.1.1.1")
        assert st["endpoints"] == {}

    def test_update_sni(self):
        st = {
            "tx_set": set(),
            "endpoints": {},
            "stack": {},
            "tls": False,
            "domains": set(),
            "mqtt_topics": set(),
        }
        pkt = _Pkt(
            ip=_IP("1.1.1.1", "2.2.2.2"),
            tcp=_TCP(payload=_client_hello(b"sni.example")),
        )
        pcap._update_pcap_state(st, pkt, "1.1.1.1")
        assert "sni.example" in st["domains"]

    def test_collect_dns(self):
        st = {"domains": set()}
        pkt = _Pkt(ip=_IP(), dns=_DNS(0, "a.example."))
        pcap._collect_dns_names(st, pkt)
        assert "a.example" in st["domains"]

    def test_collect_dns_response_ignored(self):
        st = {"domains": set()}
        pkt = _Pkt(ip=_IP(), dns=_DNS(1, "a.example."))
        pcap._collect_dns_names(st, pkt)
        assert not st["domains"]


class TestParseFrames:
    def test_parse(self):
        frames = [
            _Pkt(ip=_IP("1.1.1.1", "2.2.2.2"), tcp=_TCP()),
            _Pkt(ip=_IP("1.1.1.1", "3.3.3.3"), dns=_DNS(0, "x.example.")),
            _Pkt(),
        ]
        u_tx, endpoints, stack, tls, domains, mqtt = pcap._parse_pcap_frames(
            frames, "1.1.1.1"
        )
        assert u_tx >= 1 and "x.example" in domains


class TestCloudEndpoints:
    def test_fetch_ipinfo(self, monkeypatch):
        class Resp:
            def __enter__(self):
                return self

            def __exit__(self, *a):
                return False

            def read(self):
                return json.dumps({"org": "Acme"}).encode()

        monkeypatch.setattr(
            pcap.urllib.request, "urlopen", lambda *a, **k: Resp()
        )
        assert pcap._fetch_ipinfo_dict("1.1.1.1")["org"] == "Acme"

    def test_enrich(self, monkeypatch):
        monkeypatch.setattr(
            pcap, "_fetch_ipinfo_dict", lambda ip: {"org": "Acme", "city": "C"}
        )
        entry = pcap._enrich_endpoint("1.1.1.1")
        assert entry["ip"] == "1.1.1.1"

    def test_process_cache_hit(self):
        intel = _init_intel("", "00:11:22:33:44:55")
        cache = {"1.1.1.1": {"ip": "1.1.1.1", "org": "Acme"}}
        endpoints = {"1.1.1.1": {"ports": {443}, "pkts": 1, "bytes": 2}}
        pcap._process_cloud_endpoints(intel, endpoints, cache)
        assert intel["cloud_c2"][0]["ports"] == [443]

    def test_process_lookup(self, monkeypatch):
        monkeypatch.setattr(
            pcap, "_enrich_endpoint", lambda ip: {"ip": ip, "org": "Acme"}
        )
        intel = _init_intel("", "00:11:22:33:44:55")
        endpoints = {"1.1.1.1": {"ports": {443}, "pkts": 1, "bytes": 2}}
        pcap._process_cloud_endpoints(intel, endpoints)
        assert intel["cloud_c2"]

    def test_process_lookup_error(self, monkeypatch):
        def boom(ip):
            raise urllib.error.URLError("x")

        monkeypatch.setattr(pcap, "_enrich_endpoint", boom)
        intel = _init_intel("", "00:11:22:33:44:55")
        endpoints = {"1.1.1.1": {"ports": {443}, "pkts": 1, "bytes": 2}}
        pcap._process_cloud_endpoints(intel, endpoints)
        assert intel["cloud_c2"] == []


class TestAuditPcap:
    def test_skip(self, monkeypatch):
        monkeypatch.setattr(pcap, "HAS_SCAPY", False)
        intel = _init_intel("", "00:11:22:33:44:55")
        pcap._audit_pcap(intel, "/nope", "1.1.1.1")
        assert intel["pcap_forensics"] == {}

    def test_read_frames(self, monkeypatch):
        monkeypatch.setattr(pcap.scapy, "rdpcap", lambda path: [1, 2])
        assert pcap._read_pcap_frames("x") == [1, 2]

    def test_audit(self, monkeypatch, tmp_path):
        target = tmp_path / "a.pcap"
        target.write_bytes(b"x")
        monkeypatch.setattr(pcap, "HAS_SCAPY", True)
        monkeypatch.setattr(
            pcap,
            "_read_pcap_frames",
            lambda path: [_Pkt(ip=_IP("1.1.1.1", "2.2.2.2"), tcp=_TCP())],
        )
        called = {}
        monkeypatch.setattr(
            pcap,
            "_process_cloud_endpoints",
            lambda intel, endpoints, cache=None: called.setdefault(
                "yes", True
            ),
        )
        intel = _init_intel("", "00:11:22:33:44:55")
        pcap._audit_pcap(intel, str(target), "1.1.1.1")
        assert called["yes"] and intel["pcap_forensics"]["unique_tx"] >= 1

    def test_import_error_sets_flag(self, monkeypatch):
        import importlib
        import sys

        monkeypatch.setitem(sys.modules, "scapy.all", None)
        reloaded = importlib.reload(pcap)
        assert reloaded.HAS_SCAPY is False
        monkeypatch.undo()
        importlib.reload(pcap)

    def test_mqtt_unhandled_type(self):
        assert pcap._extract_mqtt_topics(b"\x90\x00") == []

    def test_mqtt_connect_short(self):
        assert pcap._mqtt_connect(b"\x10\x00") == []
