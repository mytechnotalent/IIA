"""Coverage tests for __main__.py CLI orchestration."""

import sys
import types

from iiatool import __main__ as cli


def _args(**over):
    """Build a default CLI namespace."""
    base = {
        "target_ip": "",
        "target_mac": "",
        "router_ip": "192.168.1.1",
        "ble": "tovala",
        "ble_timeout": 1.0,
        "pcap": "x.pcap",
        "json": "r.json",
        "report": "r.md",
        "all": False,
        "info": "info.json",
        "no_scan_ports": False,
        "ports": "",
        "fcc_id": "",
        "firmware": "",
        "extract_dir": "",
        "carve_dir": "",
        "broad": False,
        "cve_mirror": "",
        "sbom_out": "",
    }
    base.update(over)
    return types.SimpleNamespace(**base)


def _quiet(monkeypatch):
    """Silence logging helpers."""
    monkeypatch.setattr(cli, "_log", lambda *a: None)
    monkeypatch.setattr(cli, "_found", lambda *a: None)


class TestParsers:
    def test_net_args(self):
        assert cli._parser_net_args()

    def test_file_args(self):
        assert cli._parser_file_args()

    def test_arguments(self):
        assert cli._parser_arguments()

    def test_build(self):
        parser = cli._build_arg_parser()
        opts = vars(parser.parse_args(["--firmware", "x"]))
        assert opts["firmware"] == "x"


class TestAuditSteps:
    def test_full(self, monkeypatch):
        _quiet(monkeypatch)
        calls = {}
        monkeypatch.setattr(cli, "_audit_network", lambda *a: None)
        monkeypatch.setattr(cli, "_audit_vendor_regulatory", lambda *a: None)
        monkeypatch.setattr(
            cli, "_maybe_fcc_resolve", lambda *a: calls.setdefault("fcc", True)
        )
        monkeypatch.setattr(
            cli, "_scan_host_ports", lambda ip, ports: [{"port": 80}]
        )
        monkeypatch.setattr(cli, "_assess_vulnerabilities", lambda i: None)
        monkeypatch.setattr(cli, "_audit_bluetooth", lambda *a: None)
        monkeypatch.setattr(cli, "_audit_pcap", lambda *a: None)
        monkeypatch.setattr(
            cli, "_export_reports", lambda *a: calls.setdefault("export", True)
        )
        intel = {
            "target": {"mac": "00:11:22:33:44:55", "name": "x"},
            "open_ports": [],
        }
        cli._run_audit_steps(intel, _args(fcc_id="VPYLB1MDIMP004"))
        assert calls["fcc"] and calls["export"]
        assert intel["open_ports"] == [{"port": 80}]

    def test_no_scan(self, monkeypatch):
        _quiet(monkeypatch)
        monkeypatch.setattr(cli, "_audit_network", lambda *a: None)
        monkeypatch.setattr(cli, "_audit_vendor_regulatory", lambda *a: None)
        monkeypatch.setattr(cli, "_audit_bluetooth", lambda *a: None)
        monkeypatch.setattr(cli, "_audit_pcap", lambda *a: None)
        monkeypatch.setattr(cli, "_export_reports", lambda *a: None)
        intel = {"target": {"mac": "m", "name": "x"}}
        cli._run_audit_steps(intel, _args(no_scan_ports=True))
        assert "open_ports" not in intel


class TestAllAudit:
    def _patch(self, monkeypatch):
        _quiet(monkeypatch)
        spectrum = {
            "wifi_networks": [{"bssid": "aa"}],
            "local_hosts": [{"ip": "1.1.1.1", "mac": "aa"}],
            "bt_classic": [{"address": "bb"}],
        }
        monkeypatch.setattr(
            cli,
            "_scan_radio_spectrum",
            lambda t: (spectrum, [{"target": {"name": ""}}]),
        )
        monkeypatch.setattr(
            cli, "_fetch_router_flows_all", lambda ip: [{"f": 1}]
        )
        monkeypatch.setattr(
            cli,
            "_fetch_router_aux",
            lambda ip: (
                [{"bssid": "bb"}, {"bssid": "aa"}],
                [
                    {"ip": "2.2.2.2", "mac": "cc"},
                    {"ip": "1.1.1.1", "mac": "aa"},
                ],
            ),
        )
        monkeypatch.setattr(
            cli, "_audit_wifi_network", lambda n: {"target": {}}
        )
        monkeypatch.setattr(
            cli, "_audit_host_intel", lambda h, f, p: {"target": {"name": ""}}
        )
        monkeypatch.setattr(
            cli, "_audit_bt_classic_peer", lambda p: {"target": {}}
        )
        monkeypatch.setattr(
            cli,
            "_maybe_fcc_resolve",
            lambda *a: a[0].setdefault("fcc_id_override", "X"),
        )
        monkeypatch.setattr(cli, "_write_file", lambda *a: None)
        monkeypatch.setattr(cli, "_format_giant_markdown", lambda g: "md")
        return spectrum

    def test_all(self, monkeypatch):
        spectrum = self._patch(monkeypatch)
        assert cli._run_all_audit(_args(fcc_id="VPYLB1MDIMP004")) == 0
        assert spectrum["router_ap_scan"] == 2
        assert spectrum["router_client_count"] == 2

    def test_all_no_info(self, monkeypatch):
        self._patch(monkeypatch)
        assert cli._run_all_audit(_args(info="", json="", report="")) == 0


class TestFirmware:
    def test_read_bytes(self, tmp_path):
        target = tmp_path / "a.bin"
        target.write_bytes(b"hi")
        assert cli._read_bytes(str(target)) == b"hi"
        assert cli._read_bytes("/nonexistent") == b""

    def test_write_sbom(self, tmp_path, monkeypatch):
        _quiet(monkeypatch)
        cli._write_sbom({"components": []}, str(tmp_path / "sbom"))
        assert (tmp_path / "sbom" / "sbom.cdx.json").exists()

    def test_run_firmware_audit(self, tmp_path, monkeypatch):
        _quiet(monkeypatch)
        target = tmp_path / "fw.bin"
        target.write_bytes(b"x")
        calls = {}
        monkeypatch.setattr(cli, "scan_file", lambda p, b: {"findings": []})
        monkeypatch.setattr(cli, "entropy_pass", lambda d: {})
        monkeypatch.setattr(cli, "detect_upx", lambda d: {})
        monkeypatch.setattr(
            cli, "extract_tree", lambda p, o: calls.setdefault("extract", True)
        )
        monkeypatch.setattr(
            cli,
            "carve_findings",
            lambda d, f, o: calls.setdefault("carve", True),
        )
        monkeypatch.setattr(cli, "_run_static_passes", lambda doc, a: None)
        monkeypatch.setattr(
            cli,
            "_export_firmware_reports",
            lambda *a: calls.setdefault("export", True),
        )
        code = cli._run_firmware_audit(
            _args(
                firmware=str(target),
                extract_dir=str(tmp_path / "e"),
                carve_dir=str(tmp_path / "c"),
            )
        )
        assert (
            code == 0
            and calls["extract"]
            and calls["carve"]
            and calls["export"]
        )

    def test_run_static_passes(self, monkeypatch):
        _quiet(monkeypatch)
        monkeypatch.setattr(cli, "scan_secrets", lambda t: {"count": 1})
        monkeypatch.setattr(
            cli, "build_sbom", lambda t: {"count": 2, "components": []}
        )
        monkeypatch.setattr(cli, "scan_licenses", lambda t: {"findings": [1]})
        monkeypatch.setattr(cli, "load_mirror", lambda p: {})
        monkeypatch.setattr(cli, "join_cves", lambda c, m: {"findings": []})
        written = {}
        monkeypatch.setattr(
            cli, "_write_sbom", lambda s, o: written.setdefault("done", True)
        )
        doc = {}
        cli._run_static_passes(doc, _args(cve_mirror="m.json", sbom_out="out"))
        assert doc["secrets"]["count"] == 1 and written["done"]


class TestMain:
    def test_main_firmware(self, monkeypatch):
        _quiet(monkeypatch)
        monkeypatch.setattr(cli.sys, "argv", ["iiatool", "--firmware", "x"])
        monkeypatch.setattr(cli, "_run_firmware_audit", lambda a: 7)
        assert cli.main() == 7

    def test_main_all(self, monkeypatch):
        _quiet(monkeypatch)
        monkeypatch.setattr(cli.sys, "argv", ["iiatool", "--all"])
        monkeypatch.setattr(cli, "_run_all_audit", lambda a: 3)
        assert cli.main() == 3

    def test_main_single(self, monkeypatch):
        _quiet(monkeypatch)
        monkeypatch.setattr(
            cli.sys, "argv", ["iiatool", "--target-ip", "1.1.1.1"]
        )
        monkeypatch.setattr(cli, "_init_intel", lambda ip, mac: {"target": {}})
        monkeypatch.setattr(cli, "_run_audit_steps", lambda i, a: None)
        assert cli.main() == 0

    def test_module_entry(self, monkeypatch):
        import runpy

        import iiatool.ble as ble_mod
        import iiatool.cve as cve_mod
        import iiatool.network as net_mod
        import iiatool.pcap as pcap_mod
        import iiatool.report as report_mod
        import iiatool.scan as scan_mod
        import iiatool.vendor as vendor_mod

        monkeypatch.setattr(net_mod, "_audit_network", lambda *a: None)
        monkeypatch.setattr(
            vendor_mod, "_audit_vendor_regulatory", lambda *a: None
        )
        monkeypatch.setattr(scan_mod, "_scan_host_ports", lambda ip, ports: [])
        monkeypatch.setattr(cve_mod, "_assess_vulnerabilities", lambda i: None)
        monkeypatch.setattr(ble_mod, "_audit_bluetooth", lambda *a: None)
        monkeypatch.setattr(pcap_mod, "_audit_pcap", lambda *a: None)
        monkeypatch.setattr(report_mod, "_export_reports", lambda *a: None)
        monkeypatch.setattr(sys, "argv", ["iiatool", "--target-ip", "1.1.1.1"])
        try:
            runpy.run_module("iiatool", run_name="__main__")
        except SystemExit as exc:
            assert exc.code == 0


class TestMergeHelpers:
    def test_merge_aps_empty(self):
        spectrum = {"wifi_networks": []}
        cli._merge_aps(spectrum, [])
        assert spectrum["wifi_networks"] == []

    def test_merge_clients_empty(self):
        spectrum = {"local_hosts": []}
        cli._merge_clients(spectrum, [])
        assert spectrum["local_hosts"] == []
