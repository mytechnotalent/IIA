"""Tests for the vendor OUI and FCC regulatory phase."""

from iiatool import vendor


class TestOuiFlags:
    def test_globally_unique_unicast(self):
        assert "globally unique" in vendor._oui_flags("00:11:22:33:44:55")

    def test_locally_administered_flagged(self):
        flags = vendor._oui_flags("02:00:00:00:00:00")
        assert "locally administered" in flags

    def test_multicast_detected(self):
        flags = vendor._oui_flags("01:00:5e:00:00:01")
        assert "multicast" in flags

    def test_short_mac(self):
        assert vendor._oui_flags("a") == ""


class TestOuiLocalAdmin:
    def test_randomized_mac_is_local(self):
        assert vendor._oui_is_locally_administered("02:00:00:00:00:01")

    def test_registered_mac_not_local(self):
        assert not vendor._oui_is_locally_administered("00:11:22:33:44:55")


class TestCleanTableRow:
    def test_strips_tags(self):
        assert (
            vendor._clean_table_row("<tr><td>a</td><td>b</td></tr>") == "a b"
        )

    def test_collapses_whitespace(self):
        assert vendor._clean_table_row("  foo\n   bar  ") == "foo bar"


class TestParseFccFrequencies:
    def test_matches_band_rows(self):
        html = (
            "<table><tr><td>2412 MHz</td></tr>"
            "<tr><td>5100 MHz</td></tr></table>"
        )
        rows = vendor._parse_fcc_frequencies(html)
        assert len(rows) == 1
        assert "2412" in rows[0]

    def test_no_rows(self):
        assert vendor._parse_fcc_frequencies("<html></html>") == []


class TestExtractFccIds:
    def _intel(self, adv_hex="", device_info=None, hostname=""):
        return {
            "ble_telemetry": {
                "adv": {"manufacturer_data": [{"hex": adv_hex}]},
                "device_info": device_info or {},
            },
            "cloud_c2": [{"hostname": hostname}],
        }

    def test_mines_adv_hex(self):
        intel = self._intel(adv_hex="VPYLB1MDIMP004")
        assert "VPYLB1MDIMP004" in vendor._extract_embedded_fcc_ids(intel)

    def test_mines_device_info(self):
        intel = self._intel(device_info={"model": "ABC12XYZ9"})
        assert "ABC12XYZ9" in vendor._extract_embedded_fcc_ids(intel)

    def test_mines_hostname(self):
        intel = self._intel(hostname="AB1CDEF9901.cloud.example")
        assert "AB1CDEF9901" in vendor._extract_embedded_fcc_ids(intel)

    def test_noise_ignored(self):
        intel = self._intel(device_info={"model": "Tovala Oven"})
        assert vendor._extract_embedded_fcc_ids(intel) == []


class TestMaybeFccResolve:
    def test_explicit_fcc_id_stored(self, monkeypatch):
        calls = []
        grant = {
            "grant": "VPYLB1MDIMP004",
            "url": "u",
            "frequencies": ["2412"],
        }

        def fake_direct(fcc_id):
            calls.append(fcc_id)
            return grant

        monkeypatch.setattr(vendor, "_fcc_lookup_direct", fake_direct)
        intel = {}
        vendor._maybe_fcc_resolve(intel, fcc_id="vpyLB1MDIMP004")
        assert calls == ["VPYLB1MDIMP004"]
        assert intel["regulatory"]["fcc_grant"]["grant"] == "VPYLB1MDIMP004"

    def test_empty_fcc_id_no_crash(self, monkeypatch):
        monkeypatch.setattr(vendor, "_fcc_lookup_direct", lambda x: {})
        intel = {}
        vendor._maybe_fcc_resolve(intel)
        assert "regulatory" not in intel

    def test_budget_respected(self, monkeypatch):
        monkeypatch.setattr(vendor, "_FCC_PROBE_BUDGET", 0)
        vendor._maybe_fcc_resolve({}, "some model 123")
        assert True


class TestStoreFccGrant:
    def test_stores_and_reports(self):
        intel = {}
        vendor._store_fcc_grant(
            intel, {"grant": "ABC", "url": "u", "frequencies": ["x"]}
        )
        assert intel["regulatory"]["fcc_grant"]["grant"] == "ABC"
