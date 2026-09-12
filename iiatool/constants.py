"""Constants and knowledge bases for the IoT Intel Audit tool."""

import re

DEFAULT_IP = ""
DEFAULT_MAC = ""
DEFAULT_ROUTER = "192.168.1.1"
MAC_API_URL = "https://api.maclookup.app/v2/macs/"
IPINFO_URL = "https://ipinfo.io/"
SRV_DEV_INFO = "0000180a-0000-1000-8000-00805f9b34fb"
CHR_MODEL = "00002a24-0000-1000-8000-00805f9b34fb"
CHR_FIRMWARE = "00002a26-0000-1000-8000-00805f9b34fb"
CHR_DEVICE_ID = "00002a25-0000-1000-8000-00805f9b34fb"

PORT_SCAN_DEFAULT = [
    21,
    22,
    23,
    25,
    53,
    80,
    111,
    123,
    139,
    443,
    445,
    515,
    1883,
    1900,
    2121,
    3306,
    5353,
    5000,
    5432,
    5900,
    6379,
    6667,
    7000,
    8000,
    8080,
    8443,
    8883,
    8888,
    9100,
    9306,
    49152,
    25565,
    4200,
    5555,
]

COMMON_PORTS = {
    21: "ftp",
    22: "ssh",
    23: "telnet",
    25: "smtp",
    53: "dns",
    80: "http",
    111: "rpcbind",
    123: "ntp",
    139: "netbios-ssn",
    443: "https",
    445: "smb",
    515: "printer",
    1883: "mqtt",
    1900: "ssdp/upnp",
    3306: "mysql",
    5000: "upnp/airport",
    5353: "mdns",
    5432: "postgresql",
    5900: "vnc",
    6379: "redis",
    6667: "irc",
    7000: "airplay",
    8000: "http-alt",
    8080: "http-proxy",
    8443: "https-alt",
    8883: "mqtt-tls",
    8888: "http-alt",
    9100: "printer-jetdirect",
    49152: "ephemeral-iot",
    25565: "minecraft",
    2121: "ftp-fxp",
    9306: "mysql-client",
    4200: "c2-agent",
    5555: "soap-upnp",
}

CVE_NVD_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
CVE_KEYWORD_BUDGET = 5
CVE_RATE_LIMIT_S = 6.0

SERVICE_VULN_KB = {
    21: {
        "risks": [
            "FTP transmits credentials in the clear — disable if cloud "
            "tethering is sufficient",
        ],
        "cves": [
            (
                "CVE-1999-0497",
                0.0,
                "Anonymous FTP under heavy traffic conditions",
            ),
        ],
    },
    22: {
        "risks": [
            "SSH exposes an interactive remote shell — restrict to the "
            "management VLAN",
        ],
        "cves": [
            (
                "CVE-2018-15473",
                5.3,
                "OpenSSH username enumeration via auth timing difference",
            ),
            (
                "CVE-2021-41617",
                7.0,
                "OpenSSH privilege escalation via AuthorizedKeysCommand and "
                "AuthorizedKeysCommandUser",
            ),
            (
                "CVE-2023-48795",
                5.9,
                "OpenSSH Terrapin prefix truncation in SSH transport protocol",
            ),
        ],
    },
    23: {
        "risks": [
            "Telnet exposes unencrypted root shells — replace with SSH "
            "even on trusted LANs",
        ],
        "cves": [
            (
                "CVE-2020-10177",
                10.0,
                "MikroTik Winbox/Core unauth admin via crafted session",
            ),
        ],
    },
    25: {
        "risks": [
            "SMTP on an IoT device suggests outbound mail relay; verify "
            "spoofing protections",
        ],
        "cves": [
            ("CVE-2020-14928", 5.0, "Exim ACL memory safety issue (DoS)"),
        ],
    },
    53: {
        "risks": [
            "Open DNS may cache-poison or proxy; keep recursion LAN-bound",
        ],
        "cves": [],
    },
    80: {
        "risks": [
            "Plaintext HTTP admin console — check for default credentials and "
            "CSRF",
        ],
        "cves": [],
    },
    111: {
        "risks": [
            "rpcbind may expose NFS exports to LAN — verify export list is "
            "restrictive",
        ],
        "cves": [
            (
                "CVE-2017-8779",
                7.5,
                "rpcbind enabled port map allows crafted requests DoS",
            ),
        ],
    },
    123: {
        "risks": [
            "Exposed NTP may be abused for amplification DDoS — restrict to "
            "internal records",
        ],
        "cves": [
            ("CVE-2015-7855", 7.5, "NTP decodenetnum stack buffer overflow"),
        ],
    },
    139: {
        "risks": [
            "NetBIOS SMB shares on IoT devices frequently carry default "
            "filesystem access",
        ],
        "cves": [
            (
                "CVE-2017-7494",
                7.0,
                "Samba remote code execution via crafted, authenticated "
                "command (SambaCry)",
            ),
        ],
    },
    443: {
        "risks": [
            "HTTPS service on IoT often uses self-signed certs — check for "
            "weak TLS",
        ],
        "cves": [],
    },
    445: {
        "risks": [
            "SMB exposed — legacy protocol with multiple remote code "
            "execution vectors",
        ],
        "cves": [
            (
                "CVE-2017-0144",
                8.8,
                "SMBv1 EternalBlue RCE enabling wormable lateral movement",
            ),
        ],
    },
    515: {
        "risks": [
            "LPD print service — verify no unauthenticated queue manipulation",
        ],
        "cves": [
            ("CVE-2002-1184", 5.0, "LPD remote denial of service"),
        ],
    },
    1883: {
        "risks": [
            "MQTT without TLS exposes device telemetry and often allows "
            "unauthenticated publish",
        ],
        "cves": [
            (
                "CVE-2017-7650",
                9.0,
                "Mosquitto MQTT remote code execution (pre-1.4.15)",
            ),
        ],
    },
    1900: {
        "risks": [
            "SSDP/UPnP discovery service has a long history of reflection and "
            "RCE",
        ],
        "cves": [
            (
                "CVE-2020-12695",
                8.8,
                "UPnP CallStranger SSDP/HTTP/UPnP HTTP header injection",
            ),
        ],
    },
    2121: {
        "risks": [
            "FTP-FXP allows data proxying between arbitrary endpoints — "
            "disable if unused",
        ],
        "cves": [
            (
                "CVE-1999-0497",
                0.0,
                "Anonymous FTP under heavy traffic conditions",
            ),
        ],
    },
    3306: {
        "risks": [
            "Exposed MySQL often has default or weak credentials on consumer "
            "firmware",
        ],
        "cves": [
            (
                "CVE-2021-2022",
                6.5,
                "MySQL Server 8.0 mysqld InnoDB unspecified DoS",
            ),
        ],
    },
    5000: {
        "risks": [
            "UPnP/SSDP http-alt interface enables port-forwarding "
            "manipulation",
        ],
        "cves": [
            (
                "CVE-2020-12695",
                8.8,
                "UPnP CallStranger SSDP/HTTP/UPnP HTTP header injection",
            ),
        ],
    },
    5353: {
        "risks": [
            "mDNS responder reachable means zeroconf enumeration possible",
        ],
        "cves": [
            ("CVE-2017-6519", 7.5, "Avahi mDNS reflective loop vulnerability"),
        ],
    },
    5432: {
        "risks": [
            "PostgreSQL exposed to LAN without TLS allows credential sniffing",
        ],
        "cves": [
            (
                "CVE-2021-23214",
                9.9,
                "PostgreSQL libpq server trust bypass for authentication",
            ),
        ],
    },
    5900: {
        "risks": [
            "VNC/RFB is exposed — confirm authentication; a bare RFB "
            "banner is not proof of RealVNC",
        ],
        "cves": [],
    },
    6379: {
        "risks": [
            "Redis bound beyond loopback leads to unauthenticated remote code "
            "execution",
        ],
        "cves": [
            ("CVE-2021-32761", 8.8, "Redis Lua sandbox escape leading to RCE"),
        ],
    },
    6667: {
        "risks": [
            "IRC bots on IoT devices indicate a C2 channel — investigate",
        ],
        "cves": [
            ("CVE-2005-0381", 5.0, "IRC daemon DoS via crafted message"),
        ],
    },
    7000: {
        "risks": [
            "AirPlay/AirPort interface — verifies no unauthorized audio "
            "streaming",
        ],
        "cves": [
            ("CVE-2016-5883", 7.5, "AirPlay Daemon arbitrary code execution"),
        ],
    },
    8000: {
        "risks": [
            "http-alt often hosts developer or admin live views",
        ],
        "cves": [],
    },
    8080: {
        "risks": [
            "http-proxy frequently exposes unauthenticated admin panels",
        ],
        "cves": [],
    },
    8443: {
        "risks": [
            "https-alt service — verify TLS and inspect cert authenticity",
        ],
        "cves": [],
    },
    8883: {
        "risks": [
            "MQTT over TLS exposed — verify broker authentication on the "
            "trusted network",
        ],
        "cves": [
            (
                "CVE-2017-7650",
                9.0,
                "Mosquitto MQTT remote code execution (pre-1.4.15)",
            ),
        ],
    },
    8888: {
        "risks": [
            "http-alt port 8888 often carries a proxy management console",
        ],
        "cves": [],
    },
    9100: {
        "risks": [
            "PJL printer daemon — verify no unauthenticated queue commands",
        ],
        "cves": [
            ("CVE-2002-1184", 5.0, "LPD remote denial of service"),
        ],
    },
    9306: {
        "risks": [
            "Exposed MySQL client service on IoT — verify MySQL-style auth",
        ],
        "cves": [
            (
                "CVE-2021-2022",
                6.5,
                "MySQL Server 8.0 mysqld InnoDB unspecified DoS",
            ),
        ],
    },
    49152: {
        "risks": [
            "Ephemeral port in use — usually DIAL/discovery or NAT traversal",
        ],
        "cves": [],
    },
    25565: {
        "risks": [
            "Minecraft server listener exposed on LAN — verifies player "
            "authorities",
        ],
        "cves": [
            (
                "CVE-2021-38525",
                7.5,
                "Minecraft Java Edition crafted network packet DoS",
            ),
        ],
    },
    4200: {
        "risks": [
            "C2 agent listener confirmed — validate TLS-only transport and "
            "token auth",
        ],
        "cves": [],
    },
    5555: {
        "risks": [
            "SOAP/UPnP alternate port frequently used for NETGEAR config "
            "extraction",
        ],
        "cves": [
            (
                "CVE-2022-27641",
                8.8,
                "NETGEAR R6700v3 unauthenticated integer overflow in NetUSB",
            ),
            (
                "CVE-2022-27642",
                8.8,
                "NETGEAR R6700v3 httpd auth bypass enabling root code "
                "execution",
            ),
        ],
    },
}

CVE_BANNER_PRODUCT_RE = re.compile(
    r"(dropbear|openssh|nginx|mosquitto|vsftpd|proftpd|pure[- ]?ftpd|lwip|"
    r"lighttpd|apache[ /]|realvnc|samba|sshd|bftpd|cherokee|thttpd|boa|"
    r"mongoose|tinyxml|rabbitmq|postgresql|mariadb)",
    re.IGNORECASE,
)

WIFI_OPEN_SECURITY = {"Open", "WEP", "WPA Personal"}

NETGEAR_CURRENT_BASELINE = "1.0.5."
NETGEAR_OLD_CVES = [
    (
        "CVE-2022-27641",
        8.8,
        "NETGEAR R6700v3 unauthenticated integer overflow in NetUSB "
        "leading to root code execution",
    ),
    (
        "CVE-2022-27642",
        8.8,
        "NETGEAR R6700v3 httpd auth bypass (incorrect string match) enabling "
        "root code execution",
    ),
    ("CVE-2022-27646", 8.8, "NETGEAR R6700v3 unauthenticated code execution"),
    (
        "CVE-2022-48196",
        7.4,
        "NETGEAR R6700v3 pre-1.0.4.122 unauthenticated buffer overflow",
    ),
]

APACHE_KB_CVES = [
    ("CVE-2021-41773", 9.8, "Apache httpd path traversal + RCE (2.4.49)"),
    (
        "CVE-2021-42013",
        9.8,
        "Apache httpd path traversal + RCE (2.4.49/2.4.50)",
    ),
]

REALVNC_KB_CVES = [
    (
        "CVE-2006-2369",
        10.0,
        "VNC 4 authentication bypass in RealVNC 4.1 pre-1.1.1",
    ),
]

DNSMASQ_CVE_OLD = [
    (
        "CVE-2020-25681",
        8.8,
        "dnsmasq <2.83 heap overflow via DNSSEC RRSIG parsing",
    ),
    (
        "CVE-2021-3448",
        6.5,
        "dnsmasq <2.86 NULL pointer dereference via crafted DNS query",
    ),
    (
        "CVE-2021-45949",
        7.5,
        "dnsmasq <2.87 heap overflow via crafted DNS response",
    ),
    (
        "CVE-2023-28450",
        7.4,
        "dnsmasq <2.90 DNS rebinding allows CORS and SSRF bypass",
    ),
]

BIND_KB_CVES = [
    (
        "CVE-2021-25220",
        7.2,
        "BIND AXFR-denied records still copied, leaking private zone data",
    ),
    (
        "CVE-2020-8616",
        6.5,
        "BIND assertion failure on a malformed answer (DoS)",
    ),
]

HAPROXY_KB_CVES = [
    (
        "CVE-2021-40346",
        9.8,
        "HAProxy HTTP request smuggling enabling cache and ACL bypass",
    ),
]

MANUFACTURER_IDS = {
    0x004C: "Apple, Inc.",
    0x0006: "Microsoft",
    0x0059: "Nordic Semiconductor",
    0x0112: "Nordic Semiconductor",
    0x0118: "Espressif Inc.",
    0x00E0: "Google LLC",
    0x0075: "Samsung Electronics",
    0x0089: "Samsung Electronics",
    0x001D: "Fitbit LLC",
    0x000A: "Bluegiga",
    0x000D: "Texas Instruments",
    0x0008: "Broadcom",
    0x0012: "Qualcomm",
    0x0066: "Jawbone",
    0x0040: "Nike Inc.",
    0x0016: "Dell",
    0x0007: "Apple (legacy)",
    0x0049: "No Company",
    0x0054: "Huawei",
    0x00E1: "Sony",
    0x00D2: "Amazon",
    0x0499: "Xiaomi",
    0x0136: "Arduino SA",
    0x0119: "Mi (Xiaomi)",
    0x00B0: "Hittite Microwave",
    0x0300: "Garmin",
    0x01FE: "Logitech",
    0x0140: "Tile",
    0x00CA: "Ubiquiti Networks",
    0x00DC: "Lego",
    0x0070: "TP-Link",
    0x00FA: "TP-Link",
    0x011A: "Tuya",
    0x0DA8: "Tuya",
}

GATT_SERVICE_NAMES = {
    "00001800-0000-1000-8000-00805f9b34fb": "Generic Access",
    "00001801-0000-1000-8000-00805f9b34fb": "Generic Attribute",
    "00001802-0000-1000-8000-00805f9b34fb": "Immediate Alert",
    "00001803-0000-1000-8000-00805f9b34fb": "Link Loss",
    "00001804-0000-1000-8000-00805f9b34fb": "Tx Power",
    "00001805-0000-1000-8000-00805f9b34fb": "Current Time",
    "00001806-0000-1000-8000-00805f9b34fb": "Location and Navigation",
    "00001807-0000-1000-8000-00805f9b34fb": "IP Support",
    "00001808-0000-1000-8000-00805f9b34fb": "Phone Alert Status",
    "00001809-0000-1000-8000-00805f9b34fb": "Health Thermometer",
    "0000180a-0000-1000-8000-00805f9b34fb": "Device Information",
    "0000180b-0000-1000-8000-00805f9b34fb": "Network Availability",
    "0000180c-0000-1000-8000-00805f9b34fb": "Watchdog",
    "0000180d-0000-1000-8000-00805f9b34fb": "Heart Rate",
    "0000180e-0000-1000-8000-00805f9b34fb": "Link Loss",
    "0000180f-0000-1000-8000-00805f9b34fb": "Battery Service",
    "00001810-0000-1000-8000-00805f9b34fb": "Blood Pressure",
    "00001811-0000-1000-8000-00805f9b34fb": "Alert Notification",
    "00001812-0000-1000-8000-00805f9b34fb": "Human Interface Device",
    "00001813-0000-1000-8000-00805f9b34fb": "Scan Parameters",
    "00001814-0000-1000-8000-00805f9b34fb": "Running Speed and Cadence",
    "00001815-0000-1000-8000-00805f9b34fb": "Body Composition",
    "00001816-0000-1000-8000-00805f9b34fb": "Weight Scale",
    "00001818-0000-1000-8000-00805f9b34fb": "Cycling Power",
    "00001819-0000-1000-8000-00805f9b34fb": "Location and Navigation",
    "0000181c-0000-1000-8000-00805f9b34fb": "User Data",
    "0000181e-0000-1000-8000-00805f9b34fb": "Alert Notification",
    "0000181f-0000-1000-8000-00805f9b34fb": "Automation IO",
    "00001820-0000-1000-8000-00805f9b34fb": "Basic Notification",
    "00001821-0000-1000-8000-00805f9b34fb": "Object Transfer",
    "00001826-0000-1000-8000-00805f9b34fb": "Fitness Machine",
    "00001827-0000-1000-8000-00805f9b34fb": "Mesh Provisioning",
    "0000182a-0000-1000-8000-00805f9b34fb": "Mesh Proxy",
    "0000fee0-0000-1000-8000-00805f9b34fb": "Vendor (see char names)",
    "0000fee7-0000-1000-8000-00805f9b34fb": "Vendor (TI/BLE CC254x)",
    "0000fe95-0000-1000-8000-00805f9b34fb": "Xiaomi IoT vendor",
    "0000ff00-0000-1000-8000-00805f9b34fb": "Custom UART/serial (HM-10)",
    "0000fff0-0000-1000-8000-00805f9b34fb": "Custom vendor service",
}

GATT_CHAR_NAMES = {
    "00002a00-0000-1000-8000-00805f9b34fb": "Device Name",
    "00002a01-0000-1000-8000-00805f9b34fb": "Appearance",
    "00002a02-0000-1000-8000-00805f9b34fb": "Peripheral Privacy Flag",
    "00002a03-0000-1000-8000-00805f9b34fb": "Reconnection Address",
    "00002a04-0000-1000-8000-00805f9b34fb": "Preferred Connection Parameters",
    "00002a05-0000-1000-8000-00805f9b34fb": "Service Changed",
    "00002a19-0000-1000-8000-00805f9b34fb": "Battery Level",
    "00002a21-0000-1000-8000-00805f9b34fb": "Measurement Interval",
    "00002a23-0000-1000-8000-00805f9b34fb": "System ID",
    "00002a24-0000-1000-8000-00805f9b34fb": "Model Number",
    "00002a25-0000-1000-8000-00805f9b34fb": "Serial Number",
    "00002a26-0000-1000-8000-00805f9b34fb": "Firmware Revision",
    "00002a27-0000-1000-8000-00805f9b34fb": "Hardware Revision",
    "00002a28-0000-1000-8000-00805f9b34fb": "Software Revision",
    "00002a29-0000-1000-8000-00805f9b34fb": "Manufacturer Name",
    "00002a2a-0000-1000-8000-00805f9b34fb": "IEEE 11073 Cert Data List",
    "00002a2b-0000-1000-8000-00805f9b34fb": "Current Time",
    "00002a2c-0000-1000-8000-00805f9b34fb": "Magnetic Declination",
    "00002a50-0000-1000-8000-00805f9b34fb": "PnP ID",
    "00002a51-0000-1000-8000-00805f9b34fb": "Glucose Feature",
    "00002a55-0000-1000-8000-00805f9b34fb": "Sport Summary Period",
    "00002a56-0000-1000-8000-00805f9b34fb": "Date Time",
    "00002a58-0000-1000-8000-00805f9b34fb": "Battery Level State",
    "00002a6e-0000-1000-8000-00805f9b34fb": "Temperature",
    "00002a7b-0000-1000-8000-00805f9b34fb": "HTN Health Thermometer",
    "00002a9f-0000-1000-8000-00805f9b34fb": "BCS Control",
    "00002aa0-0000-1000-8000-00805f9b34fb": "BMI Feature",
    "00002ab3-0000-1000-8000-00805f9b34fb": "HID Information",
    "00002ac0-0000-1000-8000-00805f9b34fb": "UDP Socket",
    "00002afe-0000-1000-8000-00805f9b34fb": "Middleware",
    "0000ff01-0000-1000-8000-00805f9b34fb": "Custom Serial TX/RX",
}  # opaque vendor UUIDs are passed through with no name lookup

GATT_DESCRIPTOR_NAMES = {
    "00002902-0000-1000-8000-00805f9b34fb":
        "Client Characteristic Configuration",
    "00002901-0000-1000-8000-00805f9b34fb":
        "Characteristic User Description",
    "00002903-0000-1000-8000-00805f9b34fb":
        "Server Characteristic Configuration",
    "00002904-0000-1000-8000-00805f9b34fb":
        "Characteristic Presentation Format",
    "00002905-0000-1000-8000-00805f9b34fb": "Characteristic Aggregate Format",
}

FCC_SEARCH_URL = "https://fccid.io/search.php"
FCC_GRANT_URL = "https://fccid.io/{}"
FCC_TOKEN_RE = re.compile(r"\b([A-Z]{2,5}[0-9][A-Z0-9]{4,})\b")

AIRPORT_PATHS = [
    "/System/Library/PrivateFrameworks/Apple80211.framework/"
    "Versions/Current/Resources/airport",
    "/usr/sbin/airport",
]
BT_SYSTEM_PROFILER = "/usr/sbin/system_profiler"
DNS_SD = "/usr/bin/dns-sd"

CORE_WLAN_SWIFT = r"""
import Foundation
import CoreWLAN

func _bandLabel(_ c: CWChannel?) -> String {
    guard let c = c else { return "" }
    switch c.channelBand {
    case .band2GHz: return "2.4 GHz"
    case .band5GHz: return "5 GHz"
    case .band6GHz: return "6 GHz"
    default: return ""
    }
}

func _securityLabel(_ n: CWNetwork) -> String {
    if n.supportsSecurity(.wpa3Personal) { return "WPA3 Personal" }
    if n.supportsSecurity(.personal) { return "WPA2/WPA3 Personal" }
    if n.supportsSecurity(.wpa3Enterprise) { return "WPA3 Enterprise" }
    if n.supportsSecurity(.wpa2Enterprise) { return "WPA2 Enterprise" }
    if n.supportsSecurity(.wpaEnterprise) { return "WPA Enterprise" }
    if n.supportsSecurity(.wpa2Personal) { return "WPA2 Personal" }
    if n.supportsSecurity(.wpaPersonalMixed) { return "WPA/WPA2 Personal" }
    if n.supportsSecurity(.wpaPersonal) { return "WPA Personal" }
    if n.supportsSecurity(.WEP) { return "WEP" }
    return "Open"
}

let _client = CWWiFiClient.shared()
guard let _iface = _client.interface() else {
    print("{\"error\": \"no wifi interface\"}")
    exit(1)
}
do {
    let _results = try _iface.scanForNetworks(
        withName: nil, includeHidden: true)
    var _arr: [[String: Any]] = []
    for _n in _results.sorted(by: { $0.rssiValue > $1.rssiValue }) {
        var _d: [String: Any] = [:]
        _d["ssid"] = _n.ssid ?? ""
        _d["bssid"] = _n.bssid ?? ""
        _d["rssi"] = _n.rssiValue
        if let _ch = _n.wlanChannel {
            _d["channel"] = _ch.channelNumber
            _d["band"] = _bandLabel(_ch)
        } else {
            _d["channel"] = -1
            _d["band"] = ""
        }
        _d["security"] = _securityLabel(_n)
        _arr.append(_d)
    }
    let _data = try JSONSerialization.data(
        withJSONObject: _arr, options: [.sortedKeys])
    print(String(data: _data, encoding: .utf8) ?? "[]")
} catch {
    print("{\"error\": \"\(error)\"}")
    exit(1)
}
"""
