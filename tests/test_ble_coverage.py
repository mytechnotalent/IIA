"""Coverage tests for ble.py using fake GATT objects."""

import asyncio

from iiatool import ble


def _run(coro):
    """Run an async coroutine."""
    return asyncio.run(coro)


class _Char:
    """Fake GATT characteristic."""

    def __init__(self, uuid, properties=("read",), descriptors=()):
        """Initialize the characteristic."""
        self.uuid = uuid
        self.properties = list(properties)
        self.descriptors = list(descriptors)


class _Desc:
    """Fake GATT descriptor."""

    def __init__(self, uuid="d1", handle=1):
        """Initialize the descriptor."""
        self.uuid = uuid
        self.handle = handle


class _Srv:
    """Fake GATT service."""

    def __init__(self, uuid="s1", chars=()):
        """Initialize the service."""
        self.uuid = uuid
        self.characteristics = list(chars)


class _Client:
    """Fake BleakClient with read behavior."""

    def __init__(
        self,
        services=(),
        read_value=b"hi",
        desc_value=b"ok",
        fail_read=False,
        fail_desc=False,
    ):
        """Initialize the client."""
        self.services = list(services)
        self.read_value = read_value
        self.desc_value = desc_value
        self.fail_read = fail_read
        self.fail_desc = fail_desc

    async def read_gatt_char(self, uuid):
        """Return or raise for a characteristic read."""
        if self.fail_read:
            raise RuntimeError("read failed")
        return self.read_value

    async def read_gatt_descriptor(self, handle):
        """Return or raise for a descriptor read."""
        if self.fail_desc:
            raise RuntimeError("desc failed")
        return self.desc_value


class _Adv:
    """Fake AdvertisementData."""

    def __init__(self):
        """Populate advertisement fields."""
        self.rssi = -40
        self.tx_power = -4
        self.appearance = 1
        self.connectable = True
        self.is_anonymous = False
        self.active = True
        self.service_uuids = ["abcd"]
        self.manufacturer_data = {76: b"\x01\x02"}
        self.service_data = {"abcd": b"\x03"}


class _Dev:
    """Fake BLE device."""

    def __init__(self, name="Tovala", address="aa:bb:cc:dd:ee:ff"):
        """Initialize the device."""
        self.name = name
        self.address = address


class TestNameMatching:
    def test_pattern(self):
        assert ble._match_ble_name("MyTovala", "tovala")

    def test_default_keywords(self):
        assert ble._match_ble_name("Smart Oven", "")

    def test_no_match(self):
        assert not ble._match_ble_name("zzz", "qqq")

    def test_find_target(self):
        dev, adv = _Dev(), _Adv()
        found = ble._find_ble_target({"a": (dev, adv)}, "tovala")
        assert found[0] is dev

    def test_find_target_none(self):
        assert ble._find_ble_target({}, "x") == (None, None)


class TestDecode:
    def test_decode_utf8(self):
        assert ble._decode_gatt_bytes(b"abc") == "abc"

    def test_decode_binary(self):
        assert ble._decode_gatt_bytes(b"\xff\xfe").startswith("b'")

    def test_try_read_ok(self):
        hx, asc, err = _run(ble._try_read_char(_Client(), "u"))
        assert hx == b"hi".hex() and err is None

    def test_try_read_error(self):
        hx, asc, err = _run(ble._try_read_char(_Client(fail_read=True), "u"))
        assert err and not hx

    def test_read_one_char(self):
        char = _Char("u", ("read",), [_Desc()])
        info = _run(ble._read_one_char(_Client(), char))
        assert info["hex"] and info["descriptors"]["d1"]["hex"]

    def test_read_one_char_desc_error(self):
        char = _Char("u", ("read",), [_Desc()])
        info = _run(ble._read_one_char(_Client(fail_desc=True), char))
        assert "err" in info["descriptors"]["d1"]

    def test_read_one_char_no_read(self):
        char = _Char("u", (), ())
        info = _run(ble._read_one_char(_Client(), char))
        assert "hex" not in info

    def test_dump_service(self):
        srv = _Srv("s1", [_Char("c1")])
        dump = _run(ble._dump_service_chars(_Client(), srv))
        assert "c1" in dump

    def test_dump_services(self):
        srv = _Srv("s1", [_Char("c1")])
        dump = _run(ble._dump_gatt_services(_Client(services=[srv])))
        assert "s1" in dump


class TestDeviceInfo:
    def test_char_ascii(self):
        assert ble._char_ascii({"u": {"ascii": "x"}}, "u") == "x"

    def test_extract_device_info(self):
        dump = {ble.SRV_DEV_INFO: {"chars": {ble.CHR_MODEL: {"ascii": "M"}}}}
        assert ble._extract_device_info(dump)["model"] == "M"

    def test_manufacturer_bytes(self):
        records = ble._decode_manufacturer_data({76: b"\x01"})
        assert records[0]["company"] == ble.MANUFACTURER_IDS.get(76, "Unknown")

    def test_manufacturer_bytearray(self):
        records = ble._decode_manufacturer_data({76: bytearray(b"\x01")})
        assert records[0]["hex"] == "01"

    def test_manufacturer_other(self):
        records = ble._decode_manufacturer_data({76: "str"})
        assert records[0]["hex"] == "str"

    def test_format_adv_value(self):
        assert ble._format_adv_value(b"a")["hex"] == "61"
        assert ble._format_adv_value(bytearray(b"a"))["hex"] == "61"
        assert ble._format_adv_value(5) == 5

    def test_adv_payload(self):
        payload = ble._adv_payload(_Adv(), "n")
        assert payload["manufacturer_data"] and payload["service_uuids"]


class TestLeakage:
    def test_extract_survey_no_locked(self):
        assert ble._extract_survey_lines("ssid") == []

    def test_extract_survey(self):
        assert ble._extract_survey_lines("locked\nSSID1\nSSID2") == [
            "SSID1",
            "SSID2",
        ]

    def test_check_ssid_leakage(self):
        dump = {"s": {"chars": {"c": {"ascii": "locked\nSSID1"}}}}
        assert ble._check_ssid_leakage(dump) == ["SSID1"]

    def test_record_leakage_risk(self):
        from iiatool.utils import _init_intel

        intel = _init_intel("", "aa:bb:cc:dd:ee:ff")
        ble._record_leakage_risk(intel, ["SSID1"])
        assert intel["blue_team_risk_assessment"][0]["severity"] == "MEDIUM"


class TestStoreResults:
    def test_store(self, monkeypatch):
        from iiatool.utils import _init_intel

        monkeypatch.setattr(ble, "_auto_vendor_lookup", lambda *a: None)
        intel = _init_intel("", "aa:bb:cc:dd:ee:ff")
        dump = {
            ble.SRV_DEV_INFO: {"chars": {ble.CHR_MODEL: {"ascii": "M"}}},
            "s": {"chars": {"c": {"ascii": "locked\nSSID1"}}},
        }
        _run(ble._store_ble_results(intel, dump))
        assert any(
            r["severity"] == "MEDIUM"
            for r in intel["blue_team_risk_assessment"]
        )


class TestConnect:
    def test_connect_target(self, monkeypatch):
        from iiatool.utils import _init_intel

        called = {}

        async def fake(intel, dev):
            called["yes"] = True

        monkeypatch.setattr(ble, "_interrogate_ble_target", fake)
        intel = _init_intel("", "aa:bb:cc:dd:ee:ff")
        _run(ble._connect_target(intel, _Dev(), _Adv()))
        assert called["yes"]

    def test_connect_target_error(self, monkeypatch):
        from iiatool.utils import _init_intel

        async def boom(intel, dev):
            raise RuntimeError("x")

        monkeypatch.setattr(ble, "_interrogate_ble_target", boom)
        intel = _init_intel("", "aa:bb:cc:dd:ee:ff")
        _run(ble._connect_target(intel, _Dev(), _Adv()))


class TestInterrogate:
    def test_interrogate(self, monkeypatch):
        from iiatool.utils import _init_intel

        class FakeBleak:
            def __init__(self, address, timeout=0):
                self.services = [_Srv("s1", [_Char("c1")])]

            async def __aenter__(self):
                return self

            async def __aexit__(self, *a):
                return False

            async def read_gatt_char(self, uuid):
                return b"hi"

        monkeypatch.setattr(ble.bleak, "BleakClient", FakeBleak)
        monkeypatch.setattr(ble, "_auto_vendor_lookup", lambda *a: None)
        intel = _init_intel("", "aa:bb:cc:dd:ee:ff")
        _run(ble._interrogate_ble_target(intel, _Dev()))
        assert intel["ble_telemetry"]["gatt"]


class TestPipelines:
    def test_scan_pipeline_found(self, monkeypatch):
        from iiatool.utils import _init_intel

        async def discover(timeout=0, return_adv=True):
            return {"a": (_Dev(), _Adv())}

        monkeypatch.setattr(ble.bleak.BleakScanner, "discover", discover)
        called = {}

        async def connect(intel, dev, adv):
            called["yes"] = True

        monkeypatch.setattr(ble, "_connect_target", connect)
        intel = _init_intel("", "aa:bb:cc:dd:ee:ff")
        _run(ble._scan_ble_pipeline(intel, "tovala", 1.0))
        assert called["yes"]

    def test_scan_pipeline_not_found(self, monkeypatch):
        from iiatool.utils import _init_intel

        async def discover(timeout=0, return_adv=True):
            return {}

        monkeypatch.setattr(ble.bleak.BleakScanner, "discover", discover)
        intel = _init_intel("", "aa:bb:cc:dd:ee:ff")
        _run(ble._scan_ble_pipeline(intel, "x", 1.0))

    def test_audit_bluetooth_no_bleak(self, monkeypatch):
        from iiatool.utils import _init_intel

        monkeypatch.setattr(ble, "HAS_BLEAK", False)
        ble._audit_bluetooth(_init_intel("", "aa:bb:cc:dd:ee:ff"), "x", 1.0)

    def test_audit_bluetooth(self, monkeypatch):
        from iiatool.utils import _init_intel

        monkeypatch.setattr(ble, "HAS_BLEAK", True)
        monkeypatch.setattr(ble.asyncio, "run", lambda coro: coro.close())
        ble._audit_bluetooth(_init_intel("", "aa:bb:cc:dd:ee:ff"), "x", 1.0)

    def test_audit_all_async(self, monkeypatch):
        async def discover(timeout=0, return_adv=True):
            return {"a": (_Dev(), _Adv())}

        monkeypatch.setattr(ble.bleak.BleakScanner, "discover", discover)
        called = {}

        async def connect(intel, dev, adv):
            called["yes"] = True

        monkeypatch.setattr(ble, "_connect_target", connect)
        inventory, audits = _run(ble._audit_all_ble_async(1.0))
        assert inventory and audits and called["yes"]

    def test_audit_all_async_connect_error(self, monkeypatch):
        async def discover(timeout=0, return_adv=True):
            return {"a": (_Dev(), _Adv())}

        monkeypatch.setattr(ble.bleak.BleakScanner, "discover", discover)

        async def boom(intel, dev, adv):
            raise RuntimeError("x")

        monkeypatch.setattr(ble, "_connect_target", boom)
        inventory, audits = _run(ble._audit_all_ble_async(1.0))
        assert audits

    def test_audit_all_async_error(self, monkeypatch):
        async def discover(timeout=0, return_adv=True):
            raise RuntimeError("x")

        monkeypatch.setattr(ble.bleak.BleakScanner, "discover", discover)
        assert _run(ble._audit_all_ble_async(1.0)) == ([], [])

    def test_audit_all_no_bleak(self, monkeypatch):
        monkeypatch.setattr(ble, "HAS_BLEAK", False)
        assert ble._audit_all_bluetooth(1.0) == ([], [])

    def test_audit_all(self, monkeypatch):
        monkeypatch.setattr(ble, "HAS_BLEAK", True)
        captured = {}

        def fake_run(coro):
            coro.close()
            captured["ran"] = True
            return ([], [])

        monkeypatch.setattr(ble.asyncio, "run", fake_run)
        ble._audit_all_bluetooth(1.0)
        assert captured["ran"]

    def test_import_error_sets_flag(self, monkeypatch):
        import importlib
        import sys

        monkeypatch.setitem(sys.modules, "bleak", None)
        reloaded = importlib.reload(ble)
        assert reloaded.HAS_BLEAK is False
        monkeypatch.undo()
        importlib.reload(ble)
        assert ble.HAS_BLEAK is True
