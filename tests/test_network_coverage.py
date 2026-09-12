"""Coverage tests for network.py using fakes for sockets and subprocess."""

import json
import types

from iiatool import network


class _SockMod:
    """Minimal stand-in for the socket module."""

    AF_INET = 2
    SOCK_DGRAM = 2
    SOCK_STREAM = 1

    def __init__(self, factory):
        """Store the socket factory."""
        self.socket = factory


class _FakeSock:
    """Fake connected socket returning queued chunks."""

    def __init__(self, chunks=(), addr=("192.168.1.50", 0)):
        """Initialize with queued chunks and a fake local address."""
        self.chunks = list(chunks)
        self.addr = addr

    def __enter__(self):
        """Enter the context manager."""
        return self

    def __exit__(self, *args):
        """Exit the context manager."""
        return False

    def settimeout(self, value):
        """Accept a timeout."""
        return None

    def connect(self, addr):
        """Record the connect target."""
        self.target = addr

    def sendall(self, data):
        """Record sent bytes."""
        self.sent = data

    def recv(self, size):
        """Return the next queued chunk or empty bytes."""
        return self.chunks.pop(0) if self.chunks else b""

    def getsockname(self):
        """Return the fake local address."""
        return self.addr

    def close(self):
        """Close the socket."""
        return None


def _run_stub(stdout="", raises=None):
    """Build a subprocess.run replacement."""

    def stub(*args, **kwargs):
        if raises:
            raise raises
        return types.SimpleNamespace(stdout=stdout)

    return stub


class TestArp:
    def test_resolve_mac(self, monkeypatch):
        monkeypatch.setattr(
            network.subprocess, "run", _run_stub("x at AA:BB:CC:DD:EE:FF")
        )
        assert network._resolve_arp_mac("192.168.1.5") == "aa:bb:cc:dd:ee:ff"

    def test_resolve_mac_none(self, monkeypatch):
        monkeypatch.setattr(
            network.subprocess, "run", _run_stub("no mac here")
        )
        assert network._resolve_arp_mac("192.168.1.5") == ""

    def test_arp_all_hosts_filters(self, monkeypatch):
        out = (
            "? (224.0.0.251) at aa:bb:cc:dd:ee:ff on en0\n"
            "? (192.168.1.9) at aa:bb:cc:dd:ee:ff on en0\n"
            "? (192.168.1.9) at ff:ff:ff:ff:ff:ff on en0\n"
            "? (192.168.1.55) at aa:bb:cc:dd:ee:ff on en0\n"
        )
        monkeypatch.setattr(network.subprocess, "run", _run_stub(out))
        hosts = network._arp_all_hosts()
        assert hosts == [
            {"ip": "192.168.1.9", "mac": "aa:bb:cc:dd:ee:ff"},
            {"ip": "192.168.1.55", "mac": "aa:bb:cc:dd:ee:ff"},
        ]

    def test_arp_all_hosts_error(self, monkeypatch):
        monkeypatch.setattr(
            network.subprocess, "run", _run_stub(raises=OSError("x"))
        )
        assert network._arp_all_hosts() == []

    def test_ping_once_ok(self, monkeypatch):
        monkeypatch.setattr(network.subprocess, "run", _run_stub())
        assert network._ping_once("192.168.1.9") == "192.168.1.9"

    def test_ping_once_error(self, monkeypatch):
        monkeypatch.setattr(
            network.subprocess, "run", _run_stub(raises=OSError("x"))
        )
        assert network._ping_once("192.168.1.9") == ""


class TestSockets:
    def test_read_chunk_error(self):
        class Bad:
            def recv(self, size):
                raise OSError("x")

        assert network._read_socket_chunk(Bad()) == b""

    def test_recv_chunks(self):
        sock = _FakeSock(chunks=[b"a", b"b"])
        assert network._recv_socket_chunks(sock) == b"ab"

    def test_query_router_socket(self, monkeypatch):
        sock = _FakeSock(chunks=[b'{"ok":true}'])
        fake = _SockMod(lambda *a, **k: sock)
        monkeypatch.setattr(network, "socket", fake)
        assert network._query_router_socket("192.168.1.1") == '{"ok":true}'

    def test_local_ipv4(self, monkeypatch):
        fake = _SockMod(lambda *a, **k: _FakeSock(addr=("192.168.1.50", 0)))
        monkeypatch.setattr(network, "socket", fake)
        assert network._local_ipv4() == "192.168.1.50"

    def test_local_ipv4_error(self, monkeypatch):
        class BadSock(_FakeSock):
            def connect(self, addr):
                raise OSError("x")

        fake = _SockMod(lambda *a, **k: BadSock())
        monkeypatch.setattr(network, "socket", fake)
        assert network._local_ipv4() == ""


class TestFlows:
    def test_flow_matches(self):
        assert network._flow_matches({"src": "1.1.1.1"}, "1.1.1.1")
        assert network._flow_matches({"dst_addr": "2.2.2.2"}, "2.2.2.2")
        assert not network._flow_matches({}, "3.3.3.3")

    def test_parse_flows_list_msg(self):
        assert network._parse_flows_list({"msg": '[{"src": "a"}]'}) == [
            {"src": "a"}
        ]

    def test_parse_flows_list_msg_bad(self):
        assert network._parse_flows_list({"msg": "[broken"}) == []

    def test_parse_flows_list_flows(self):
        assert network._parse_flows_list({"flows": [1]}) == [1]

    def test_parse_flows_list_non_dict(self):
        assert network._parse_flows_list("x") == []

    def test_filter_flows(self):
        raw = json.dumps({"flows": [{"src": "1.1.1.1"}, {"src": "9.9.9.9"}]})
        assert network._filter_flows("1.1.1.1", raw) == [{"src": "1.1.1.1"}]

    def test_filter_flows_bad_json(self):
        assert network._filter_flows("1.1.1.1", "{bad") == []

    def test_record_router_flows(self, monkeypatch):
        monkeypatch.setattr(
            network, "_query_router_socket", lambda ip, cmd="get_flows": "{}"
        )
        intel = {"network_flows": []}
        network._record_router_flows(intel, "1.1.1.1", "192.168.1.1")
        assert intel["network_flows"] == []

    def test_record_router_flows_error(self, monkeypatch):
        def boom(ip, cmd="get_flows"):
            raise OSError("refused")

        monkeypatch.setattr(network, "_query_router_socket", boom)
        intel = {"network_flows": []}
        network._record_router_flows(intel, "1.1.1.1", "192.168.1.1")

    def test_audit_network(self, monkeypatch):
        monkeypatch.setattr(
            network, "_resolve_arp_mac", lambda ip: "aa:bb:cc:dd:ee:ff"
        )
        monkeypatch.setattr(network, "_record_router_flows", lambda *a: None)
        intel = {"target": {"mac": ""}}
        network._audit_network(intel, "1.1.1.1", "192.168.1.1")
        assert intel["target"]["mac"] == "aa:bb:cc:dd:ee:ff"

    def test_audit_network_has_mac(self, monkeypatch):
        monkeypatch.setattr(network, "_record_router_flows", lambda *a: None)
        intel = {"target": {"mac": "existing"}}
        network._audit_network(intel, "1.1.1.1", "192.168.1.1")
        assert intel["target"]["mac"] == "existing"


class TestRouterCommands:
    def test_fetch_json_cmd(self, monkeypatch):
        monkeypatch.setattr(
            network, "_query_router_socket", lambda ip, cmd: '{"a": 1}'
        )
        assert network._fetch_router_json_cmd("ip", "get_flows") == {"a": 1}

    def test_fetch_json_cmd_error(self, monkeypatch):
        def boom(ip, cmd):
            raise OSError("x")

        monkeypatch.setattr(network, "_query_router_socket", boom)
        assert network._fetch_router_json_cmd("ip", "get_flows") == {}

    def test_fetch_flows_all(self, monkeypatch):
        monkeypatch.setattr(
            network,
            "_fetch_router_json_cmd",
            lambda ip, cmd: {"flows": [{"src": "a"}]},
        )
        assert network._fetch_router_flows_all("ip") == [{"src": "a"}]

    def test_fetch_flows_all_empty(self, monkeypatch):
        monkeypatch.setattr(
            network, "_fetch_router_json_cmd", lambda ip, cmd: {}
        )
        assert network._fetch_router_flows_all("ip") == []

    def test_fetch_router_aux(self, monkeypatch):
        responses = {
            "get_wifi_scan": {"networks": [{"ssid": "x"}]},
            "get_clients": {"leases": [{"ip": "1.1.1.1"}]},
        }
        monkeypatch.setattr(
            network, "_fetch_router_json_cmd", lambda ip, cmd: responses[cmd]
        )
        aps, clients = network._fetch_router_aux("ip")
        assert aps == [{"ssid": "x"}]
        assert clients == [{"ip": "1.1.1.1"}]

    def test_fetch_router_aux_alt_keys(self, monkeypatch):
        responses = {
            "get_wifi_scan": {"scan": [{"ssid": "y"}]},
            "get_clients": {"clients": [{"ip": "2.2.2.2"}]},
        }
        monkeypatch.setattr(
            network, "_fetch_router_json_cmd", lambda ip, cmd: responses[cmd]
        )
        aps, clients = network._fetch_router_aux("ip")
        assert aps and clients


class TestPingSweep:
    def test_sweep_with_local(self, monkeypatch):
        monkeypatch.setattr(network, "_local_ipv4", lambda: "192.168.1.50")
        monkeypatch.setattr(network, "_ping_once", lambda ip: ip)
        monkeypatch.setattr(
            network, "_arp_all_hosts", lambda: [{"ip": "x", "mac": "y"}]
        )
        assert network._ping_sweep() == [{"ip": "x", "mac": "y"}]

    def test_sweep_without_local(self, monkeypatch):
        monkeypatch.setattr(network, "_local_ipv4", lambda: "")
        monkeypatch.setattr(network, "_arp_all_hosts", lambda: [])
        assert network._ping_sweep() == []
