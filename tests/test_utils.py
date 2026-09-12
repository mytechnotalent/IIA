"""Tests for shared utilities."""

import json
import os

from iiatool import utils


class TestCleanMac:
    def test_strips_colons(self):
        assert utils._clean_mac("00:11:22:33:44:55") == "001122334455"

    def test_strips_hyphens(self):
        assert utils._clean_mac("0c-2a-69-27-42-0c") == "0C2A6927420C"

    def test_upcases_input(self):
        assert utils._clean_mac("00:11:22:33:44:55") == "001122334455"


class TestIntelContainer:
    def test_base_intel_dict_shape(self):
        intel = utils._base_intel_dict("10.0.0.1", "00:11:22:33:44:55")
        assert intel["target"] == {
            "ip": "10.0.0.1",
            "mac": "00:11:22:33:44:55",
        }
        assert intel["regulatory"] == {}
        assert "timestamp" in intel

    def test_init_intel_initializes_all_keys(self):
        intel = utils._init_intel("10.0.0.1", "00:11:22:33:44:55")
        for key in (
            "vendor_oui",
            "ble_telemetry",
            "pcap_forensics",
            "cloud_c2",
        ):
            assert intel[key] == {}
        for key in ("network_flows", "blue_team_risk_assessment"):
            assert intel[key] == []
        assert intel["regulatory"] == {}
        assert intel["target"]["ip"] == "10.0.0.1"
        assert intel["blue_team_risk_assessment"] == []


class TestWriteFile:
    def test_writes_file_and_mkdirs(self, tmp_path):
        target = tmp_path / "nested" / "out.json"
        utils._write_file(str(target), '{"a": 1}')
        assert target.exists()
        assert json.loads(target.read_text()) == {"a": 1}

    def test_existing_directory_ok(self, tmp_path):
        target = tmp_path / "out.txt"
        utils._write_file(str(target), "hi")
        assert target.read_text() == "hi"

    def test_file_in_cwd(self, tmp_path, monkeypatch):
        monkeypatch.chdir(tmp_path)
        utils._write_file("plain.txt", "x")
        assert os.path.exists("plain.txt")
