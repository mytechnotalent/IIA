"""Tests for the constants knowledge base."""

import re

import iiatool.constants as C


class TestHardcodedDefaults:
    def test_no_device_specific_ip_default(self):
        assert C.DEFAULT_IP == ""

    def test_no_device_specific_mac_default(self):
        assert C.DEFAULT_MAC == ""

    def test_router_default_is_generic_gateway(self):
        assert C.DEFAULT_ROUTER == "192.168.1.1"

    def test_no_embedded_fcc_url_constant(self):
        assert not hasattr(C, "FCC_ID_URL")


class TestPortKnowledgeBase:
    def test_c2_agent_port_special_cased(self):
        assert C.COMMON_PORTS[4200] == "c2-agent"

    def test_common_ports_cover_default_list(self):
        for port in C.PORT_SCAN_DEFAULT:
            assert port in C.COMMON_PORTS

    def test_service_kb_covers_common_exposed_services(self):
        for port in (22, 23, 80, 443, 1883, 445, 9100):
            assert port in C.COMMON_PORTS


class TestCveKnowledgeBase:
    def test_netgear_current_baseline(self):
        assert C.NETGEAR_CURRENT_BASELINE == "1.0.5."

    def test_netgear_old_cves_nonempty(self):
        assert len(C.NETGEAR_OLD_CVES) >= 4

    def test_dnsmasq_old_cves_ordered_by_age(self):
        assert C.DNSMASQ_CVE_OLD[0][0] == "CVE-2020-25681"
        assert C.DNSMASQ_CVE_OLD[-1][0] == "CVE-2023-28450"

    def test_banner_product_regex_flags(self):
        assert C.CVE_BANNER_PRODUCT_RE.flags & re.IGNORECASE

    def test_wifi_open_security_set(self):
        assert "Open" in C.WIFI_OPEN_SECURITY


class TestFccRegex:
    def test_grantee_code_matches(self):
        assert C.FCC_TOKEN_RE.fullmatch("VPYLB1MDIMP004")

    def test_grantee_code_requires_leading_letters(self):
        assert not C.FCC_TOKEN_RE.fullmatch("1234ABCD")


class TestGattTables:
    def test_device_info_service_known(self):
        assert C.GATT_SERVICE_NAMES[C.SRV_DEV_INFO] == "Device Information"

    def test_model_char_known(self):
        assert C.GATT_CHAR_NAMES[C.CHR_MODEL] == "Model Number"

    def test_client_char_config_descriptor_known(self):
        assert C.GATT_DESCRIPTOR_NAMES["00002902-0000-1000-8000-00805f9b34fb"]

    def test_apple_manufacturer_id(self):
        assert C.MANUFACTURER_IDS[0x004C] == "Apple, Inc."
