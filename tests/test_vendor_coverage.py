"""Coverage tests for vendor.py OUI and FCC resolution."""

import json
import urllib.error

import pytest

from iiatool import vendor
from iiatool.utils import _init_intel

FCC_HTML = "<tr><td>2412 - 2462 MHz</td></tr><tr><td>nothing</td></tr>"


class _Resp:
    """Fake urlopen response."""

    def __init__(self, payload):
        """Store bytes or text."""
        self.payload = payload

    def __enter__(self):
        """Enter context."""
        return self

    def __exit__(self, *args):
        """Exit context."""
        return False

    def read(self):
        """Return payload as bytes."""
        if isinstance(self.payload, bytes):
            return self.payload
        return self.payload.encode()


@pytest.fixture(autouse=True)
def _reset_budget():
    """Reset the FCC probe budget before each test."""
    vendor._FCC_PROBE_BUDGET = 12
    yield


class TestOuiFlags:
    def test_empty(self):
        assert vendor._oui_flags("") == ""

    def test_unicast_global(self):
        assert vendor._oui_flags("00:11:22:33:44:55") == (
            "unicast, globally unique (IEEE-registered)"
        )

    def test_multicast_local(self):
        result = vendor._oui_flags("03:00:00:00:00:00")
        assert "multicast" in result and "locally" in result

    def test_local_len(self):
        assert vendor._oui_is_locally_administered("") is False

    def test_local_true(self):
        assert vendor._oui_is_locally_administered("02:00:00:00:00:00") is True


class TestOuiFetch:
    def test_fetch(self, monkeypatch):
        monkeypatch.setattr(
            vendor.urllib.request,
            "urlopen",
            lambda *a, **k: _Resp(json.dumps({"company": "Acme"})),
        )
        assert (
            vendor._fetch_oui_vendor("00:11:22:33:44:55")["company"] == "Acme"
        )


class TestFccParse:
    def test_clean_row(self):
        assert vendor._clean_table_row("<td>a   b</td>") == "a b"

    def test_parse_frequencies(self):
        rows = vendor._parse_fcc_frequencies(FCC_HTML)
        assert rows and "2412" in rows[0]


class TestFccSearch:
    def test_success(self, monkeypatch):
        html = '<a href="/VPYLB1MDIMP004">x</a>'
        responses = [_Resp(html), _Resp(FCC_HTML)]
        monkeypatch.setattr(
            vendor.urllib.request, "urlopen", lambda *a, **k: responses.pop(0)
        )
        grant = vendor._fcc_search("module")
        assert grant["grant"] == "VPYLB1MDIMP004"
        assert grant["frequencies"]

    def test_no_grants(self, monkeypatch):
        monkeypatch.setattr(
            vendor.urllib.request,
            "urlopen",
            lambda *a, **k: _Resp("<a href='/short'>x</a>"),
        )
        assert vendor._fcc_search("module") == {}

    def test_frequency_error(self, monkeypatch):
        html = '<a href="/VPYLB1MDIMP004">x</a>'

        def urlopen(req, timeout=0):
            if FCC_HTML.encode() and "VPYLB1MDIMP004" in str(req.full_url):
                raise urllib.error.URLError("x")
            return _Resp(html)

        monkeypatch.setattr(vendor.urllib.request, "urlopen", urlopen)
        grant = vendor._fcc_search("module")
        assert grant["frequencies"] == []


class TestFccDirect:
    def test_invalid(self):
        assert vendor._fcc_lookup_direct("abc") == {}

    def test_valid(self, monkeypatch):
        monkeypatch.setattr(
            vendor.urllib.request, "urlopen", lambda *a, **k: _Resp(FCC_HTML)
        )
        grant = vendor._fcc_lookup_direct("VPYLB1MDIMP004")
        assert grant["frequencies"]

    def test_error(self, monkeypatch):
        def boom(*a, **k):
            raise urllib.error.URLError("x")

        monkeypatch.setattr(vendor.urllib.request, "urlopen", boom)
        assert vendor._fcc_lookup_direct("VPYLB1MDIMP004")["frequencies"] == []


class TestExtractIds:
    def test_extract(self):
        intel = _init_intel("", "00:11:22:33:44:55")
        intel["ble_telemetry"] = {
            "adv": {
                "manufacturer_data": [{"hex": "VPYLB1MDIMP004", "ascii": ""}]
            },
            "device_info": {"model": "VPYLB1MDIMP004"},
        }
        intel["cloud_c2"] = [{"hostname": ""}]
        assert "VPYLB1MDIMP004" in vendor._extract_embedded_fcc_ids(intel)


class TestMaybeResolve:
    def test_explicit_id(self, monkeypatch):
        monkeypatch.setattr(
            vendor,
            "_fcc_lookup_direct",
            lambda i: {"grant": i, "url": "u", "frequencies": ["2412"]},
        )
        intel = _init_intel("", "00:11:22:33:44:55")
        vendor._maybe_fcc_resolve(intel, fcc_id="VPYLB1MDIMP004")
        assert intel["regulatory"]["fcc_grant"]

    def test_embedded_token(self, monkeypatch):
        monkeypatch.setattr(
            vendor,
            "_fcc_lookup_direct",
            lambda i: {"grant": i, "url": "u", "frequencies": ["2412"]},
        )
        intel = _init_intel("", "00:11:22:33:44:55")
        intel["ble_telemetry"] = {
            "adv": {"manufacturer_data": [{"hex": "VPYLB1MDIMP004"}]}
        }
        vendor._maybe_fcc_resolve(intel)
        assert intel["regulatory"]["fcc_grant"]

    def test_query_search(self, monkeypatch):
        monkeypatch.setattr(
            vendor,
            "_fcc_search",
            lambda q: {"grant": "X", "url": "u", "frequencies": ["2412"]},
        )
        intel = _init_intel("", "00:11:22:33:44:55")
        vendor._maybe_fcc_resolve(intel, query="model 123")
        assert intel["regulatory"]["fcc_grant"]

    def test_query_too_short(self):
        intel = _init_intel("", "00:11:22:33:44:55")
        vendor._maybe_fcc_resolve(intel, query="ab")
        assert "fcc_grant" not in intel["regulatory"]

    def test_budget_exhausted(self):
        vendor._FCC_PROBE_BUDGET = 0
        intel = _init_intel("", "00:11:22:33:44:55")
        vendor._maybe_fcc_resolve(intel, query="model 123")
        assert "fcc_grant" not in intel["regulatory"]

    def test_embedded_budget_break(self, monkeypatch):
        vendor._FCC_PROBE_BUDGET = 1
        monkeypatch.setattr(vendor, "_fcc_lookup_direct", lambda i: {})
        intel = _init_intel("", "00:11:22:33:44:55")
        intel["ble_telemetry"] = {
            "adv": {
                "manufacturer_data": [{"hex": "VPYLB1MDIMP004 VPYLB1MDIMP005"}]
            }
        }
        vendor._maybe_fcc_resolve(intel)
        assert "fcc_grant" not in intel["regulatory"]

    def test_search_url_error(self, monkeypatch):
        def boom(q):
            raise urllib.error.URLError("x")

        monkeypatch.setattr(vendor, "_fcc_search", boom)
        intel = _init_intel("", "00:11:22:33:44:55")
        vendor._maybe_fcc_resolve(intel, query="model 123")


class TestFccGrantInfo:
    def test_fetch_grant(self, monkeypatch):
        monkeypatch.setattr(
            vendor.urllib.request, "urlopen", lambda *a, **k: _Resp(FCC_HTML)
        )
        assert vendor._fetch_fcc_grant("VPYLB1MDIMP004")

    def test_query_grant_info(self, monkeypatch):
        monkeypatch.setattr(
            vendor, "_fetch_fcc_grant", lambda i: ["row1", "row2"]
        )
        intel = _init_intel("", "00:11:22:33:44:55")
        vendor._query_fcc_grant_info(intel)
        assert intel["regulatory"]["fcc_grant"] == ["row1", "row2"]

    def test_query_grant_error(self, monkeypatch):
        def boom(i):
            raise urllib.error.URLError("x")

        monkeypatch.setattr(vendor, "_fetch_fcc_grant", boom)
        intel = _init_intel("", "00:11:22:33:44:55")
        vendor._query_fcc_grant_info(intel)

    def test_assign_imp(self, monkeypatch):
        monkeypatch.setattr(
            vendor, "_query_fcc_grant_info", lambda intel: None
        )
        intel = _init_intel("", "00:11:22:33:44:55")
        vendor._assign_imp_regulatory(intel)
        assert "imp004m" in intel["regulatory"]["platform"]


class TestStoreVendor:
    def test_unknown_vendor(self, monkeypatch):
        monkeypatch.setattr(vendor, "_found", lambda m: None)
        intel = _init_intel("", "02:00:00:00:00:00")
        vendor._store_vendor_info(
            intel, "02:00:00:00:00:00", {"company": "Private"}
        )
        assert "Locally administered" in intel["vendor_oui"]["company"]

    def test_imp_vendor(self, monkeypatch):
        monkeypatch.setattr(
            vendor, "_assign_imp_regulatory", lambda intel: None
        )
        monkeypatch.setattr(vendor, "_found", lambda m: None)
        intel = _init_intel("", "00:11:22:33:44:55")
        vendor._store_vendor_info(
            intel, "00:11:22:33:44:55", {"company": "Electric Imp"}
        )
        assert "regulatory" in intel


class TestAuditVendor:
    def test_audit(self, monkeypatch):
        monkeypatch.setattr(
            vendor, "_fetch_oui_vendor", lambda mac: {"company": "Acme"}
        )
        intel = _init_intel("", "00:11:22:33:44:55")
        vendor._audit_vendor_regulatory(intel, "00:11:22:33:44:55")
        assert intel["vendor_oui"]["company"] == "Acme"

    def test_audit_error(self, monkeypatch):
        def boom(mac):
            raise urllib.error.URLError("x")

        monkeypatch.setattr(vendor, "_fetch_oui_vendor", boom)
        intel = _init_intel("", "00:11:22:33:44:55")
        vendor._audit_vendor_regulatory(intel, "00:11:22:33:44:55")


class TestAutoVendor:
    def test_oui_success(self, monkeypatch):
        monkeypatch.setattr(
            vendor, "_fetch_oui_vendor", lambda mac: {"company": "Acme"}
        )
        monkeypatch.setattr(vendor, "_maybe_fcc_resolve", lambda *a, **k: None)
        intel = _init_intel("", "00:11:22:33:44:55")
        vendor._auto_vendor_lookup(intel, "00:11:22:33:44:55")
        assert intel["vendor_oui"]["source"] == "IEEE OUI registry"

    def test_oui_error_then_gatt(self, monkeypatch):
        def boom(mac):
            raise urllib.error.URLError("offline")

        monkeypatch.setattr(vendor, "_fetch_oui_vendor", boom)
        monkeypatch.setattr(vendor, "_maybe_fcc_resolve", lambda *a, **k: None)
        intel = _init_intel("", "00:11:22:33:44:55")
        intel["ble_telemetry"] = {"device_info": {"manufacturer": "Globex"}}
        vendor._auto_vendor_lookup(intel, "00:11:22:33:44:55")
        assert intel["vendor_oui"]["company"] == "Globex"

    def test_adv_company(self, monkeypatch):
        monkeypatch.setattr(
            vendor, "_fetch_oui_vendor", lambda mac: {"company": ""}
        )
        monkeypatch.setattr(vendor, "_maybe_fcc_resolve", lambda *a, **k: None)
        intel = _init_intel("", "00:11:22:33:44:55")
        intel["ble_telemetry"] = {
            "adv": {"manufacturer_data": [{"company": "Initech"}]}
        }
        vendor._auto_vendor_lookup(intel, "00:11:22:33:44:55")
        assert intel["vendor_oui"]["company"] == "Initech"

    def test_non_mac(self, monkeypatch):
        monkeypatch.setattr(vendor, "_maybe_fcc_resolve", lambda *a, **k: None)
        intel = _init_intel("", "")
        intel["target"]["name"] = "peer"
        vendor._auto_vendor_lookup(intel, "")
        assert intel["vendor_oui"]["company"].startswith("Non-MAC")

    def test_local_mac(self, monkeypatch):
        monkeypatch.setattr(
            vendor, "_fetch_oui_vendor", lambda mac: {"company": ""}
        )
        monkeypatch.setattr(vendor, "_maybe_fcc_resolve", lambda *a, **k: None)
        intel = _init_intel("", "02:00:00:00:00:00")
        vendor._auto_vendor_lookup(intel, "02:00:00:00:00:00")
        assert "Locally administered" in intel["vendor_oui"]["company"]

    def test_unregistered_mac(self, monkeypatch):
        monkeypatch.setattr(
            vendor, "_fetch_oui_vendor", lambda mac: {"company": ""}
        )
        monkeypatch.setattr(vendor, "_maybe_fcc_resolve", lambda *a, **k: None)
        intel = _init_intel("", "00:11:22:33:44:55")
        vendor._auto_vendor_lookup(intel, "00:11:22:33:44:55")
        assert (
            intel["vendor_oui"]["company"]
            == "No registered OUI (unassigned prefix)"
        )

    def test_fcc_trigger(self, monkeypatch):
        monkeypatch.setattr(
            vendor, "_fetch_oui_vendor", lambda mac: {"company": "Acme"}
        )
        called = {}
        monkeypatch.setattr(
            vendor,
            "_maybe_fcc_resolve",
            lambda intel, q="", fcc_id="": called.setdefault("q", q),
        )
        intel = _init_intel("", "00:11:22:33:44:55")
        intel["ble_telemetry"] = {"device_info": {"model": "M1"}}
        vendor._auto_vendor_lookup(intel, "00:11:22:33:44:55")
        assert called["q"] == "M1"

    def test_valid_grant_short(self):
        assert vendor._valid_grant("abc", None) is False
