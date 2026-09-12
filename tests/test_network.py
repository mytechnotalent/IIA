"""Tests for the network audit phase."""

import json

from iiatool import network


class TestFlowMatches:
    def test_src_match(self):
        assert network._flow_matches(
            {"src": "10.0.0.5", "dst": "8.8.8.8"}, "10.0.0.5"
        )

    def test_dst_match_alt_keys(self):
        assert network._flow_matches(
            {"src_addr": "8.8.8.8", "dst_addr": "10.0.0.5"}, "10.0.0.5"
        )

    def test_no_match(self):
        assert not network._flow_matches(
            {"src": "8.8.8.8", "dst": "9.9.9.9"}, "10.0.0.5"
        )


class TestParseFlowsList:
    def test_msg_string_list(self):
        obj = {"msg": '[{"src": "10.0.0.5", "dst": "8.8.8.8"}]'}
        flows = network._parse_flows_list(obj)
        assert flows[0]["dst"] == "8.8.8.8"

    def test_msg_invalid_json(self):
        assert network._parse_flows_list({"msg": "[oops"}) == []

    def test_flows_key(self):
        obj = {"flows": [{"src": "10.0.0.5"}]}
        assert network._parse_flows_list(obj) == [{"src": "10.0.0.5"}]

    def test_foreign_object(self):
        assert network._parse_flows_list({"other": 1}) == []


class TestFilterFlows:
    def test_filters_by_target(self):
        raw = json.dumps(
            {
                "flows": [
                    {"src": "10.0.0.5", "dst": "8.8.8.8"},
                    {"src": "10.0.0.9", "dst": "8.8.8.8"},
                ]
            }
        )
        result = network._filter_flows("10.0.0.5", raw)
        assert len(result) == 1
        assert result[0]["src"] == "10.0.0.5"

    def test_unparseable_returns_empty(self):
        assert network._filter_flows("10.0.0.5", "not json") == []


class TestArpResolve:
    def test_mac_extracted(self, monkeypatch):
        class FakeProc:
            stdout = "10.0.0.5 at 00:11:22:33:44:55 on en0 ifscope [ethernet]"

        monkeypatch.setattr(
            network.subprocess, "run", lambda *a, **k: FakeProc()
        )
        assert network._resolve_arp_mac("10.0.0.5") == "00:11:22:33:44:55"

    def test_no_match_returns_empty(self, monkeypatch):
        class FakeProc:
            stdout = "no entries"

        monkeypatch.setattr(
            network.subprocess, "run", lambda *a, **k: FakeProc()
        )
        assert network._resolve_arp_mac("10.0.0.5") == ""


class TestSocketChunks:
    class _FakeSocket:
        def __init__(self, payload):
            self._data = payload

        def recv(self, _n):
            if not self._data:
                raise OSError("timeout")
            chunk = self._data[:8]
            self._data = self._data[8:]
            return chunk

    def test_read_socket_chunk_normal(self):
        sock = self._FakeSocket(b"1234567890123")
        assert network._read_socket_chunk(sock) == b"12345678"

    def test_recv_accumulates(self):
        sock = self._FakeSocket(b"hello world")
        assert network._recv_socket_chunks(sock) == b"hello world"


class TestArpAllHosts:
    def test_filters_multicast_and_incomplete(self, monkeypatch):
        class FakeProc:
            stdout = (
                "? (224.0.0.251) at 00:11:22:33:44:55 ...\n"
                "? (10.0.0.5) at 00:11:22:33:44:55 on en0 ...\n"
                "? (10.0.0.7) at <incomplete> on en0 ...\n"
                "? (255.255.255.255) at ff:ff:ff:ff:ff:ff ...\n"
            )

        monkeypatch.setattr(
            network.subprocess, "run", lambda *a, **k: FakeProc()
        )
        hosts = network._arp_all_hosts()
        assert len(hosts) == 1
        assert hosts[0] == {"ip": "10.0.0.5", "mac": "00:11:22:33:44:55"}
