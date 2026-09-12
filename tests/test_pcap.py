"""Tests for the PCAP forensics phase."""

import struct

import pytest

from iiatool import pcap

pytestmark = pytest.mark.skipif(
    not pcap.HAS_SCAPY, reason="scapy not installed"
)


class TestIsTlsAppData:
    def test_detects_tls12_app_data(self):
        assert pcap._is_tls_app_data(b"\x17\x03\x03\x00\x01\xff")

    def test_rejects_short_payload(self):
        assert not pcap._is_tls_app_data(b"\x17\x03")

    def test_rejects_handshake(self):
        assert not pcap._is_tls_app_data(b"\x16\x03\x01\x00\x00")


class TestExtractHttpHost:
    def test_host_header(self):
        payload = b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n"
        assert pcap._extract_http_host(payload) == "example.com"

    def test_lowercase_host(self):
        payload = b"GET / HTTP/1.1\r\nhost: c2.bad.net\r\n\r\n"
        assert pcap._extract_http_host(payload) == "c2.bad.net"

    def test_too_short(self):
        assert pcap._extract_http_host(b"short") == ""

    def test_no_host(self):
        assert pcap._extract_http_host(b"POST /x HTTP/1.1\r\n\r\n") == ""


class TestExtractMqttTopics:
    def _publish(self, topic):
        topic_bytes = topic.encode("utf-8")
        body = struct.pack("!H", len(topic_bytes)) + topic_bytes
        remaining = len(body)
        header = bytes(
            [0x30, 0x80 & remaining if remaining >= 128 else remaining]
        )
        if remaining >= 128:
            header = bytes([0x30, remaining])
        return header + body

    def test_publish_topic(self):
        payload = self._publish("devices/oven/status")
        assert "devices/oven/status" in pcap._extract_mqtt_topics(payload)

    def test_connect_client_id(self):
        payload = (
            bytes([0x10, 0x0F]) + b"\x00\x04MQTT\x04" + b"\x00\x06" + b"client"
        )
        topics = pcap._extract_mqtt_topics(payload)
        assert "client_id:client" in topics

    def test_empty_payload(self):
        assert pcap._extract_mqtt_topics(b"") == []


class TestTlsHandshakeSni:
    def _client_hello(self, server_name):
        version = b"\x03\x03"
        random = b"\x00" * 32
        session = b"\x00"
        cipher_field = b"\x00\x02"
        compression = b"\x01\x00"
        name_len = len(server_name)
        extension = (
            struct.pack("!HH", 0, 2 + name_len)
            + struct.pack("!H", name_len)
            + server_name
        )
        extensions = struct.pack("!H", len(extension)) + extension
        body = (
            version
            + random
            + session
            + cipher_field
            + compression
            + extensions
        )
        handshake = bytes([0x01]) + struct.pack("!I", len(body))[1:] + body
        record_len = len(handshake)
        return (
            bytes([0x16, 0x03, 0x01])
            + struct.pack("!H", record_len)
            + handshake
        )

    def test_extracts_sni(self):
        client_hello = self._client_hello(b"device.cloud.example")
        assert pcap._tls_handshake_sni(client_hello) == "device.cloud.example"

    def test_garbage_no_crash(self):
        assert pcap._tls_handshake_sni(b"\x16\x03\xff\x00\x00") == ""
        assert pcap._tls_handshake_sni(b"") == ""


class TestEnrichEndpoint:
    def test_builds_c2_record(self, monkeypatch):
        monkeypatch.setattr(
            pcap,
            "_fetch_ipinfo_dict",
            lambda ip: {
                "loc": "1.2,3.4",
                "org": "AS13335 Cloudflare",
                "asn": "AS13335",
                "hostname": "c2.example",
                "city": "SF",
                "region": "CA",
                "country": "US",
                "anycast": True,
            },
        )
        c2 = pcap._enrich_endpoint("1.2.3.4")
        assert c2["ip"] == "1.2.3.4"
        assert c2["org"] == "AS13335 Cloudflare"
        assert c2["anycast"] is True

    def test_cloud_endpoint_merge_with_cache(self, monkeypatch):
        def fake_fetch(ip):
            return {
                "ip": ip,
                "org": "Acme",
                "loc": "",
                "asn": "",
                "hostname": "",
                "city": "",
                "region": "",
                "country": "",
                "anycast": None,
            }

        monkeypatch.setattr(pcap, "_enrich_endpoint", fake_fetch)
        intel = {}
        endpoints = {
            "1.2.3.4": {"ports": {443, 8443}, "pkts": 5, "bytes": 100}
        }
        pcap._process_cloud_endpoints(intel, endpoints)
        entry = intel["cloud_c2"][0]
        assert entry["ports"] == [443, 8443]
        assert entry["pkts"] == 5
