"""Tests for the command-line entry point."""

from iiatool import __main__ as cli


class TestArgParser:
    def test_parser_builds(self):
        parser = cli._build_arg_parser()
        args = parser.parse_args(["--all", "--no-scan-ports"])
        assert args.all is True
        assert args.no_scan_ports is True

    def test_ble_timeout_is_float(self):
        args = cli._build_arg_parser().parse_args([])
        assert isinstance(args.ble_timeout, float)

    def test_default_ports_empty(self):
        args = cli._build_arg_parser().parse_args([])
        assert args.ports == ""

    def test_fcc_id_default_empty(self):
        args = cli._build_arg_parser().parse_args([])
        assert args.fcc_id == ""


class TestParserConfigs:
    def test_net_args_include_target_ip(self):
        opts = dict((o, d) for o, d, _ in cli._parser_net_args())
        assert opts["--target-ip"] == ""
        assert opts["--target-mac"] == ""
        assert opts["--router-ip"] == "192.168.1.1"

    def test_file_args_include_report(self):
        opts = dict((o, d) for o, d, _ in cli._parser_file_args())
        assert opts["--report"].endswith(".md")
        assert "reports" in opts["--report"]

    def test_all_argument_configs_combined(self):
        combos = cli._parser_arguments()
        opts = [o for o, _, _ in combos]
        assert len(opts) == len(set(opts))
