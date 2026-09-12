"""Tests for the Bluetooth LE audit phase."""

from iiatool import ble
from iiatool.constants import CHR_MODEL, CHR_FIRMWARE, SRV_DEV_INFO


class TestDecodeGattBytes:
    def test_utf8_decode(self):
        assert ble._decode_gatt_bytes(b"Tovala") == "Tovala"

    def test_non_utf8_repr(self):
        value = ble._decode_gatt_bytes(b"\xff\xfe\x00")
        assert value.startswith("b'")


class TestCharAscii:
    def test_returns_ascii_value(self):
        chars = {"x": {"ascii": "Tovala"}}
        assert ble._char_ascii(chars, "x") == "Tovala"

    def test_missing_uuid(self):
        assert ble._char_ascii({}, "nope") is None


class TestExtractDeviceInfo:
    def _dump(self, model="Tovala", fw="1.2.3"):
        chars = {CHR_MODEL: {"ascii": model}, CHR_FIRMWARE: {"ascii": fw}}
        return {SRV_DEV_INFO: {"name": "", "chars": chars}}

    def test_extracts_model_and_firmware(self):
        info = ble._extract_device_info(self._dump())
        assert info["model"] == "Tovala"
        assert info["firmware"] == "1.2.3"

    def test_empty_dump_is_safe(self):
        info = ble._extract_device_info({})
        assert info["model"] is None


class TestDecodeManufacturerData:
    def test_apple_company_lookup(self):
        records = ble._decode_manufacturer_data({0x004C: b"\x02\x15"})
        assert records[0]["company"] == "Apple, Inc."
        assert records[0]["company_id"] == "0x004C"
        assert records[0]["hex"] == "0215"

    def test_unknown_company(self):
        records = ble._decode_manufacturer_data({0x9999: b"\x01"})
        assert records[0]["company"] == "Unknown"

    def test_none_safe(self):
        assert ble._decode_manufacturer_data(None) == []


class TestFormatAdvValue:
    def test_bytes_hex_and_ascii(self):
        assert ble._format_adv_value(b"hi") == {"hex": "6869", "ascii": "hi"}

    def test_passthrough_scalar(self):
        assert ble._format_adv_value(42) == 42


class TestSurveyLeakage:
    def test_extract_survey_skips_locked(self):
        assert ble._extract_survey_lines("locked") == []
        assert ble._extract_survey_lines("SSID1\nlocked") == ["SSID1"]

    def test_check_ssid_leakage_finds_ssids(self):
        dump = {
            "srv": {"chars": {"ch": {"ascii": "MyWifi\nlocked"}}},
        }
        assert ble._check_ssid_leakage(dump) == ["MyWifi"]

    def test_no_leakage(self):
        assert (
            ble._check_ssid_leakage({"srv": {"chars": {"ch": {"ascii": "x"}}}})
            == []
        )


class TestMatchBleName:
    def test_pattern_substring(self):
        assert ble._match_ble_name("Tovala Oven", "tovala")

    def test_no_pattern_includes_default_keywords(self):
        assert ble._match_ble_name("ElectricImp", "")

    def test_no_pattern_miss(self):
        assert not ble._match_ble_name("Apple Watch", "")
