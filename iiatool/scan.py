"""Wi-Fi scanning, port scanning, mDNS, and Bluetooth Classic discovery."""

import concurrent.futures
import json
import os
import re
import socket
import ssl
import string
import struct
import subprocess

from .ble import _audit_all_bluetooth
from .constants import (
    AIRPORT_PATHS,
    BT_SYSTEM_PROFILER,
    COMMON_PORTS,
    CORE_WLAN_SWIFT,
    DNS_SD,
    PORT_SCAN_DEFAULT,
)
from .utils import _found, _init_intel, _log, _warn
from .vendor import _auto_vendor_lookup

from .network import _ping_sweep


_BAND_LABELS = {"2GHz": "2.4 GHz", "5GHz": "5 GHz", "6GHz": "6 GHz"}


def _channel_band(channel: str) -> str:
    """
    Classify Wi-Fi channel number into frequency band.

    Parameters
    ----------
    channel : str
        Raw channel field from airport scan output.

    Returns
    -------
    str
        Human-readable band label.
    """
    match = re.match(r"\s*(\d+)", channel)
    number = int(match.group(1)) if match else 0
    if number == 0:
        return "unknown"
    if number <= 14:
        return "2.4 GHz"
    return "5 GHz"


def _parse_airport_scan(rows: str) -> list:
    """
    Parse legacy airport -s scan output into network records.

    Parameters
    ----------
    rows : str
        Raw airport -s stdout.

    Returns
    -------
    list
        Network dictionaries.
    """
    networks = []
    mac_re = re.compile(r"(?:[0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}")
    for line in rows.splitlines()[1:]:
        tokens = line.split()
        idx = next(
            (i for i, tok in enumerate(tokens) if mac_re.match(tok)), None
        )
        if idx is not None:
            networks.append(_airport_record(tokens, idx))
    return networks


def _token(tokens: list, idx: int, default):
    """
    Return a token by index, or a default when out of range.

    Parameters
    ----------
    tokens : list
        Token list.
    idx : int
        Token index.
    default : object
        Fallback value.

    Returns
    -------
    object
        Token or default.
    """
    return tokens[idx] if len(tokens) > idx else default


def _add_token(network: dict, tokens: list, idx: int, key: str) -> None:
    """
    Add an optional token to a network record.

    Parameters
    ----------
    network : dict
        Network record.
    tokens : list
        Token list.
    idx : int
        Token index.
    key : str
        Record key.

    Returns
    -------
    None
    """
    if len(tokens) > idx:
        network[key] = tokens[idx]


def _airport_security(tokens: list, idx: int) -> str:
    """
    Join the trailing security tokens of an airport line.

    Parameters
    ----------
    tokens : list
        Token list.
    idx : int
        MAC index.

    Returns
    -------
    str
        Security string.
    """
    return " ".join(tokens[idx + 5:]) if len(tokens) > idx + 5 else "N/A"


def _airport_record(tokens: list, idx: int) -> dict:
    """
    Build an airport scan record from one line's tokens.

    Parameters
    ----------
    tokens : list
        Token list.
    idx : int
        MAC index.

    Returns
    -------
    dict
        Network record.
    """
    network = {"ssid": " ".join(tokens[:idx]), "bssid": tokens[idx].upper()}
    network["rssi"] = _token(tokens, idx + 1, "N/A")
    network["channel"] = _token(tokens, idx + 2, "")
    network["band"] = _channel_band(network["channel"])
    _add_token(network, tokens, idx + 3, "ht")
    _add_token(network, tokens, idx + 4, "cc")
    network["security"] = _airport_security(tokens, idx)
    return network


def _sysprof_band_map(out: str) -> dict:
    """
    Extract channel-to-band mapping from supported-channel list.

    Parameters
    ----------
    out : str
        Raw system_profiler SPAirPortDataType output.

    Returns
    -------
    dict
        Channel number mapped to band label.
    """
    band_map = {}
    for channel, band in re.findall(r"(\d+) \((2GHz|5GHz|6GHz)\)", out):
        label = {"2GHz": "2.4 GHz", "5GHz": "5 GHz", "6GHz": "6 GHz"}[band]
        band_map[int(channel)] = label
    return band_map


def _parse_sysprof_wifi(out: str) -> list:
    """
    Parse system_profiler Wi-Fi output for visible networks.

    Parameters
    ----------
    out : str
        Raw SPAirPortDataType output.

    Returns
    -------
    list
        Network dictionaries with band and channel data.
    """
    band_map = _sysprof_band_map(out)
    state = {"networks": [], "record": None, "current": False, "inside": False}
    for line in out.splitlines():
        _sysprof_line(line, state, band_map)
    _sysprof_flush(state)
    return state["networks"]


def _sysprof_indented(line: str) -> bool:
    """
    Report whether a line is an indented, non-empty field line.

    Parameters
    ----------
    line : str
        Input line.

    Returns
    -------
    bool
        True when the line is an indented field.
    """
    return line.startswith(" ") and bool(line.strip())


def _sysprof_marker(line: str, state: dict) -> bool:
    """
    Update section state when a section marker is seen.

    Parameters
    ----------
    line : str
        Input line.
    state : dict
        Mutable parser state.

    Returns
    -------
    bool
        True when the line was a section marker.
    """
    if "Current Network Information:" in line:
        state["inside"] = True
        return True
    if "Other Local Wi-Fi Networks:" in line:
        state["inside"] = False
        return True
    return False


def _sysprof_new_net(state: dict, ssid: str) -> None:
    """
    Start a new network record, flushing the previous one.

    Parameters
    ----------
    state : dict
        Mutable parser state.
    ssid : str
        Network SSID.

    Returns
    -------
    None
    """
    if state["record"]:
        state["record"]["current"] = state["current"]
        state["networks"].append(state["record"])
    state["record"] = {
        "ssid": ssid,
        "bssid": "",
        "rssi": "",
        "channel": "",
        "band": "",
        "phy": "",
        "security": "N/A",
    }
    state["current"] = state["inside"]


def _sysprof_flush(state: dict) -> None:
    """
    Flush the final open network record.

    Parameters
    ----------
    state : dict
        Mutable parser state.

    Returns
    -------
    None
    """
    if state["record"]:
        state["record"]["current"] = state["current"]
        state["networks"].append(state["record"])
        state["record"] = None


def _set_rssi(record: dict, value: str) -> None:
    """
    Record the signal strength of a network.

    Parameters
    ----------
    record : dict
        Network record.
    value : str
        Signal / Noise field.

    Returns
    -------
    None
    """
    signal = re.match(r"(-\d+)", value)
    record["rssi"] = signal.group(1) if signal else ""


def _set_channel(record: dict, value: str, band_map: dict) -> None:
    """
    Record the channel and band of a network.

    Parameters
    ----------
    record : dict
        Network record.
    value : str
        Channel field.
    band_map : dict
        Channel-to-band fallback map.

    Returns
    -------
    None
    """
    chan = re.match(r"(\d+)\s*\((\dGHz)", value)
    if chan:
        record["channel"] = chan.group(1)
        record["band"] = _BAND_LABELS.get(chan.group(2), chan.group(2))
        return
    num = re.match(r"(\d+)", value)
    record["channel"] = num.group(1) if num else value
    record["band"] = band_map.get(int(record["channel"]), "")


def _sysprof_set(record: dict, key: str, value: str, band_map: dict) -> None:
    """
    Apply one parsed attribute to a network record.

    Parameters
    ----------
    record : dict
        Network record.
    key : str
        Attribute name.
    value : str
        Attribute value.
    band_map : dict
        Channel-to-band fallback map.

    Returns
    -------
    None
    """
    if key == "Channel":
        _set_channel(record, value, band_map)
    elif key == "PHY Mode":
        record["phy"] = value
    elif key in ("Security", "Network Type"):
        record[key.lower().replace(" ", "_")] = value
    elif key == "Signal / Noise":
        _set_rssi(record, value)


def _sysprof_attr(line: str, record: dict, band_map: dict) -> None:
    """
    Parse an attribute line into a network record.

    Parameters
    ----------
    line : str
        Attribute line.
    record : dict
        Network record.
    band_map : dict
        Channel-to-band fallback map.

    Returns
    -------
    None
    """
    if not record:
        return
    attr = re.match(r"^\s+([A-Za-z /']+):\s*(.*)$", line)
    if attr:
        _sysprof_set(record, attr.group(1).strip(), attr.group(2).strip(),
                     band_map)


def _sysprof_line(line: str, state: dict, band_map: dict) -> None:
    """
    Process one system_profiler Wi-Fi output line.

    Parameters
    ----------
    line : str
        Input line.
    state : dict
        Mutable parser state.
    band_map : dict
        Channel-to-band fallback map.

    Returns
    -------
    None
    """
    if _sysprof_marker(line, state):
        return
    if not _sysprof_indented(line):
        return
    name = re.match(r"^\s{10,12}([^:]+?):\s*$", line)
    if name:
        _sysprof_new_net(state, name.group(1).strip())
    else:
        _sysprof_attr(line, state["record"], band_map)


def _run_corewlan_scan() -> list:
    """
    Enumerate Wi-Fi networks via Apple CoreWLAN (no root, unredacted).

    Runs a tiny Swift script against the CoreWLAN framework. Every visible
    SSID is returned in full, including hidden networks (empty SSIDs) and
    6 GHz channels — no macOS privacy redaction, and no sudo required.

    Parameters
    ----------
    None

    Returns
    -------
    list
        Network dictionaries with ssid/bssid/band/channel/rssi/security.
    """
    proc = _corewlan_proc()
    if proc is None:
        return []
    payload = _corewlan_payload(proc)
    if payload is None:
        return []
    return _corewlan_finish([_corewlan_record(n) for n in payload])


def _corewlan_finish(networks: list) -> list:
    """
    Log and return the CoreWLAN network records.

    Parameters
    ----------
    networks : list
        Network records.

    Returns
    -------
    list
        The same network records.
    """
    if networks:
        _found(
            f"CoreWLAN scan: {len(networks)} networks unredacted "
            f"(no sudo required)"
        )
    return networks


def _corewlan_proc():
    """
    Run the CoreWLAN Swift scan, or None on launch failure.

    Parameters
    ----------
    None

    Returns
    -------
    subprocess.CompletedProcess or None
        Scan process.
    """
    try:
        return subprocess.run(
            ["swift", "-e", CORE_WLAN_SWIFT],
            capture_output=True,
            text=True,
            timeout=20,
        )
    except (OSError, subprocess.SubprocessError) as err:
        _warn(f"CoreWLAN scan failed to launch: {err}")
        return None


def _corewlan_json(text: str):
    """
    Parse CoreWLAN JSON output, or None on failure.

    Parameters
    ----------
    text : str
        JSON text.

    Returns
    -------
    object or None
        Parsed payload.
    """
    try:
        return json.loads(text)
    except json.JSONDecodeError:
        return None


def _corewlan_payload(proc):
    """
    Validate and parse the CoreWLAN scan process output.

    Parameters
    ----------
    proc : subprocess.CompletedProcess
        Scan process.

    Returns
    -------
    object or None
        Parsed payload.
    """
    if proc.returncode != 0 or not proc.stdout.strip():
        return None
    payload = _corewlan_json(proc.stdout)
    if isinstance(payload, dict) and payload.get("error"):
        _warn(f"CoreWLAN scan unavailable: {payload['error']}")
        return None
    return payload


def _corewlan_record(n: dict) -> dict:
    """
    Build a Wi-Fi network record from a CoreWLAN entry.

    Parameters
    ----------
    n : dict
        CoreWLAN network entry.

    Returns
    -------
    dict
        Network record.
    """
    ssid = n.get("ssid", "")
    return {
        "ssid": ssid if ssid else "(hidden)",
        "bssid": n.get("bssid", ""),
        "band": n.get("band", ""),
        "channel": n.get("channel", -1),
        "rssi": n.get("rssi", ""),
        "security": n.get("security", ""),
        "source": "corewlan",
    }


def _find_airport_binary() -> str:
    """
    Locate the macOS airport scan utility.

    Parameters
    ----------
    None

    Returns
    -------
    str
        Absolute binary path or empty string.
    """
    for path in AIRPORT_PATHS:
        if os.path.exists(path):
            return path
    try:
        return subprocess.run(
            ["which", "airport"], capture_output=True, text=True
        ).stdout.strip()
    except OSError:
        return ""


def _run_wifi_scan() -> list:
    """
    Enumerate every visible Wi-Fi network on all bands.

    Uses Apple CoreWLAN via Swift first — returns every SSID **unredacted**
    (including hidden networks), across 2.4/5/6 GHz, with no sudo required.
    Falls back to the legacy airport -s scan, then to system_profiler
    (whose other-network SSIDs macOS may redact).

    Parameters
    ----------
    None

    Returns
    -------
    list
        Network dictionaries.
    """
    corewlan = _run_corewlan_scan()
    if corewlan:
        return corewlan
    airport = _airport_networks()
    if airport:
        return airport
    return _sysprof_networks()


def _airport_proc(binary: str):
    """
    Run the airport scan, or None on failure or empty output.

    Parameters
    ----------
    binary : str
        Airport binary path.

    Returns
    -------
    subprocess.CompletedProcess or None
        Scan process.
    """
    try:
        result = subprocess.run(
            [binary, "-s"], capture_output=True, text=True, timeout=20
        )
    except (OSError, subprocess.SubprocessError) as err:
        _warn(f"airport scan failed: {err}")
        return None
    if result and result.returncode == 0 and result.stdout.strip():
        return result
    return None


def _airport_parsed(binary: str) -> list:
    """
    Parse airport scan output into network records.

    Parameters
    ----------
    binary : str
        Airport binary path.

    Returns
    -------
    list
        Network records.
    """
    result = _airport_proc(binary)
    if result is None:
        return []
    return _parse_airport_scan(result.stdout)


def _airport_networks() -> list:
    """
    Enumerate networks via the legacy airport utility.

    Parameters
    ----------
    None

    Returns
    -------
    list
        Network records.
    """
    binary = _find_airport_binary()
    if not binary:
        return []
    parsed = _airport_parsed(binary)
    if parsed:
        return parsed
    _warn("airport scan yielded no networks; falling back to system_profiler")
    return []


def _sysprof_out():
    """
    Run the system_profiler SPAirPortDataType scan, or None on failure.

    Parameters
    ----------
    None

    Returns
    -------
    str or None
        Raw output.
    """
    try:
        return subprocess.run(
            [BT_SYSTEM_PROFILER, "SPAirPortDataType"],
            capture_output=True,
            text=True,
            timeout=30,
        ).stdout
    except (OSError, subprocess.SubprocessError) as err:
        _warn(f"Wi-Fi discovery failed: {err}")
        return None


def _sysprof_finish(networks: list) -> list:
    """
    Warn about redaction when system_profiler returned networks.

    Parameters
    ----------
    networks : list
        Network records.

    Returns
    -------
    list
        The same network records.
    """
    if networks:
        _warn(
            "system_profiler may redact other-network SSIDs "
            "(`swift -e` CoreWLAN or router agent needed for full AP list)"
        )
    return networks


def _sysprof_networks() -> list:
    """
    Enumerate networks via system_profiler as a last resort.

    Parameters
    ----------
    None

    Returns
    -------
    list
        Network records.
    """
    if not os.path.exists(BT_SYSTEM_PROFILER):
        _warn("No Wi-Fi scan utility available on this Mac")
        return []
    out = _sysprof_out()
    if out is None:
        return []
    return _sysprof_finish(_parse_sysprof_wifi(out))


def _scan_bt_classic() -> list:
    """
    Inventory Bluetooth Classic peers visible to the radio.

    Parameters
    ----------
    None

    Returns
    -------
    list
        Peer dictionaries with name, address, and device type.
    """
    if not os.path.exists(BT_SYSTEM_PROFILER):
        _warn("system_profiler unavailable; Bluetooth Classic scan skipped")
        return []
    out = _bt_out()
    if out is None:
        return []
    return _bt_devices(out)


def _bt_out():
    """
    Run the system_profiler SPBluetoothDataType scan.

    Parameters
    ----------
    None

    Returns
    -------
    str or None
        Raw output.
    """
    try:
        return subprocess.run(
            [BT_SYSTEM_PROFILER, "SPBluetoothDataType"],
            capture_output=True,
            text=True,
            timeout=30,
        ).stdout
    except (OSError, subprocess.SubprocessError) as err:
        _warn(f"Bluetooth Classic scan skipped: {err}")
        return None


def _bt_new_device(state: dict, name: str) -> None:
    """
    Start a new Bluetooth Classic peer record.

    Parameters
    ----------
    state : dict
        Mutable parser state.
    name : str
        Peer name.

    Returns
    -------
    None
    """
    state["current"] = {"name": name, "address": "", "rssi": ""}
    state["devices"].append(state["current"])


def _bt_address(line: str, current: dict) -> None:
    """
    Record a peer address when present.

    Parameters
    ----------
    line : str
        Input line.
    current : dict
        Current peer record.

    Returns
    -------
    None
    """
    match = re.match(r"^\s+Address:\s*([0-9A-Fa-f: -]+)$", line)
    if not match:
        return
    raw = match.group(1).strip().replace("-", ":").lower()
    if re.match(r"(?:[0-9a-f]{2}:){5}[0-9a-f]{2}$", raw):
        current["address"] = raw
    else:
        current["address"] = match.group(1).strip()


def _bt_rssi(line: str, current: dict) -> None:
    """
    Record a peer RSSI when present.

    Parameters
    ----------
    line : str
        Input line.
    current : dict
        Current peer record.

    Returns
    -------
    None
    """
    match = re.match(r"^\s+RSSI:\s*(-?\d+)\s*$", line)
    if match:
        current["rssi"] = match.group(1)


def _bt_type(line: str, current: dict) -> None:
    """
    Record a peer device type when present.

    Parameters
    ----------
    line : str
        Input line.
    current : dict
        Current peer record.

    Returns
    -------
    None
    """
    match = re.match(r"^\s+(Major Type|Minor Type):\s*(.*)$", line)
    if match:
        key = match.group(1).lower().replace(" ", "_")
        current[key] = match.group(2).strip()


def _bt_attr(line: str, current: dict) -> None:
    """
    Apply address, RSSI, and type fields to a peer record.

    Parameters
    ----------
    line : str
        Input line.
    current : dict or None
        Current peer record.

    Returns
    -------
    None
    """
    if not current:
        return
    _bt_address(line, current)
    _bt_rssi(line, current)
    _bt_type(line, current)


def _bt_skip(line: str, state: dict) -> bool:
    """
    Update peer-scan state and report whether the line is structural.

    Parameters
    ----------
    line : str
        Input line.
    state : dict
        Mutable parser state.

    Returns
    -------
    bool
        True when the line should not be parsed as a peer field.
    """
    if "Connected:" in line or "Not Connected:" in line:
        state["started"] = True
        return True
    return not state["started"] or not line.strip()


def _bt_line(line: str, state: dict) -> None:
    """
    Process one Bluetooth Classic scan line.

    Parameters
    ----------
    line : str
        Input line.
    state : dict
        Mutable parser state.

    Returns
    -------
    None
    """
    if _bt_skip(line, state):
        return
    name = re.match(r"^ {8,12}([^:]+?):\s*$", line)
    if name:
        _bt_new_device(state, name.group(1).strip())
    else:
        _bt_attr(line, state["current"])


def _bt_devices(out: str) -> list:
    """
    Parse Bluetooth Classic peers from system_profiler output.

    Parameters
    ----------
    out : str
        Raw output.

    Returns
    -------
    list
        Peer records.
    """
    state = {"devices": [], "current": None, "started": False}
    for line in out.splitlines():
        _bt_line(line.rstrip(), state)
    return state["devices"]


def _scan_mdns_services() -> list:
    """
    Enumerate visible mDNS/Bonjour service types via dns-sd.

    Parameters
    ----------
    None

    Returns
    -------
    list
        Sorted unique service type strings.
    """
    if not os.path.exists(DNS_SD):
        _warn("dns-sd unavailable; mDNS discovery skipped")
        return []
    out = _mdns_out()
    if out is None:
        return []
    return _mdns_services(out)


def _mdns_out():
    """
    Run the dns-sd browse command and return its output.

    Parameters
    ----------
    None

    Returns
    -------
    str or None
        Raw output, or None when unavailable.
    """
    try:
        return (
            subprocess.run(
                [DNS_SD, "-B", "_services._dns-sd._udp.local"],
                capture_output=True,
                text=True,
                timeout=4,
            ).stdout
            or ""
        )
    except subprocess.TimeoutExpired as err:
        return err.stdout or ""
    except (OSError, subprocess.SubprocessError):
        return None


def _mdns_token(line: str) -> str:
    """
    Extract an mDNS service type token from a browse line.

    Parameters
    ----------
    line : str
        Input line.

    Returns
    -------
    str
        Service type or empty string.
    """
    if "Add" not in line or "._" not in line:
        return ""
    for token in line.split():
        if token.startswith("_") and "._" in token and ".local." in token:
            return token
    return ""


def _mdns_services(out: str) -> list:
    """
    Collect unique mDNS service types from browse output.

    Parameters
    ----------
    out : str
        Raw browse output.

    Returns
    -------
    list
        Sorted service types.
    """
    services = []
    for line in out.splitlines():
        token = _mdns_token(line)
        if token:
            services.append(token)
    return sorted(set(services))


def _probe_port(ip: str, port: int) -> int:
    """
    Test whether a remote TCP port accepts connections.

    Parameters
    ----------
    ip : str
        Target host.
    port : int
        Destination port.

    Returns
    -------
    int
        Port when open, or 0.
    """
    try:
        with socket.create_connection((ip, port), timeout=0.6):
            return port
    except OSError:
        return 0


def _netgear_firmware_probe(ip: str, port: int, tls: bool = False) -> str:
    """
    Query the unauthenticated /currentsetting.htm endpoint NETGEAR httpd
    exposes.

    Returns a banner tag like "NETGEAR R6700v3 firmware 1.0.5.128_10.0.104", or
    an empty string when the server is not a NETGEAR device. The probe works
    over both plain HTTP (80/5555) and HTTPS (443/8443) — NETGEAR httpd serves
    the same endpoint on both, so the TLS console is identified too.

    Parameters
    ----------
    ip : str
        Target host.
    port : int
        TCP port.
    tls : bool
        Wrap the connection in TLS (HTTPS) before sending the request.

    Returns
    -------
    str
        Firmware-derived banner tag or empty.
    """
    request = _netgear_request(ip)
    for _ in range(3):
        tag = _netgear_attempt(ip, port, tls, request)
        if tag:
            return tag
    return ""


def _netgear_request(ip: str) -> bytes:
    """
    Build the /currentsetting.htm request for a host.

    Parameters
    ----------
    ip : str
        Target host.

    Returns
    -------
    bytes
        HTTP request.
    """
    return (
        b"GET /currentsetting.htm HTTP/1.1\r\nHost: "
        + ip.encode()
        + b"\r\nConnection: close\r\n\r\n"
    )


def _recv_or_none(sock) -> bytes:
    """
    Receive from a socket, returning empty bytes on error.

    Parameters
    ----------
    sock : object
        Connected socket.

    Returns
    -------
    bytes
        Received bytes.
    """
    try:
        return sock.recv(1024)
    except OSError:
        return b""


def _netgear_read(sock) -> str:
    """
    Read a NETGEAR response until Firmware is seen or the body ends.

    Parameters
    ----------
    sock : object
        Connected socket.

    Returns
    -------
    str
        Decoded response text.
    """
    return _netgear_body(sock).decode("utf-8", "ignore")


def _netgear_complete(chunks: list) -> bool:
    """
    Report whether the accumulated response contains a firmware line.

    Parameters
    ----------
    chunks : list
        Received byte chunks.

    Returns
    -------
    bool
        True when the Firmware field is present.
    """
    return b"Firmware=" in b"".join(chunks)


def _need_more(chunks: list) -> bool:
    """
    Report whether the NETGEAR response needs another read.

    Parameters
    ----------
    chunks : list
        Received byte chunks.

    Returns
    -------
    bool
        True when more bytes should be read.
    """
    if not chunks:
        return True
    return len(b"".join(chunks)) < 4096 and not _netgear_complete(chunks)


def _netgear_body(sock) -> bytes:
    """
    Read the NETGEAR response body until complete or capped.

    Parameters
    ----------
    sock : object
        Connected socket.

    Returns
    -------
    bytes
        Accumulated response bytes.
    """
    chunks = []
    while _need_more(chunks):
        chunk = _recv_or_none(sock)
        if not chunk:
            break
        chunks.append(chunk)
    return b"".join(chunks)


def _netgear_tag(text: str) -> str:
    """
    Extract a firmware banner tag from a NETGEAR response.

    Parameters
    ----------
    text : str
        Response text.

    Returns
    -------
    str
        Banner tag or empty string.
    """
    fw = re.search(r"Firmware=([\w._]+)", text)
    if not fw:
        return ""
    model = re.search(r"Model=([\w]+)", text)
    return "NETGEAR {} firmware {}".format(
        model.group(1) if model else "router", fw.group(1)
    )


def _close_sock(sock) -> None:
    """
    Close a socket, ignoring errors.

    Parameters
    ----------
    sock : object or None
        Socket to close.

    Returns
    -------
    None
    """
    if sock is None:
        return
    try:
        sock.close()
    except OSError:
        pass


def _tls_wrap(raw, ip):
    """
    Wrap a socket in a legacy-compatible unverified TLS session.

    Parameters
    ----------
    raw : object
        Connected plain socket.
    ip : str
        Target host used for SNI.

    Returns
    -------
    object
        TLS-wrapped socket.
    """
    ctx = ssl._create_unverified_context()
    try:
        ctx.set_ciphers("DEFAULT@SECLEVEL=1")
    except ssl.SSLError:
        pass
    return ctx.wrap_socket(raw, server_hostname=ip)


def _netgear_open(ip: str, port: int, tls: bool):
    """
    Open a plain or TLS connection for the NETGEAR probe.

    Parameters
    ----------
    ip : str
        Target host.
    port : int
        Target port.
    tls : bool
        Whether to wrap the socket in TLS.

    Returns
    -------
    object
        Connected socket.
    """
    raw = socket.create_connection((ip, port), timeout=2.0)
    if not tls:
        return raw
    return _tls_wrap(raw, ip)


def _netgear_probe(sock, request: bytes) -> str:
    """
    Send the request and parse a firmware tag from the response.

    Parameters
    ----------
    sock : object
        Connected socket.
    request : bytes
        HTTP request.

    Returns
    -------
    str
        Banner tag or empty string.
    """
    sock.settimeout(2.0)
    sock.sendall(request)
    return _netgear_tag(_netgear_read(sock))


def _netgear_attempt(ip: str, port: int, tls: bool, request: bytes) -> str:
    """
    Perform one NETGEAR probe attempt, tolerating errors.

    Parameters
    ----------
    ip : str
        Target host.
    port : int
        Target port.
    tls : bool
        Whether to use TLS.
    request : bytes
        HTTP request.

    Returns
    -------
    str
        Banner tag or empty string.
    """
    sock = None
    try:
        sock = _netgear_open(ip, port, tls)
        return _netgear_probe(sock, request)
    except OSError:
        return ""
    finally:
        _close_sock(sock)


def _probe_rfb_vendor(ip: str, port: int = 5900) -> str:
    """
    Fingerprint an RFB/VNC server from its security-type handshake.

    Apple Screen Sharing advertises security type 30; a bare ``RFB`` banner
    alone cannot distinguish it from RealVNC, so RealVNC must never be
    asserted from the banner without this confirmation.

    Parameters
    ----------
    ip : str
        Target host.
    port : int
        RFB port (default 5900).

    Returns
    -------
    str
        Vendor tag such as ``Apple Screen Sharing`` or a generic RFB label.
    """
    data = _rfb_greeting(ip, port)
    if data is None:
        return ""
    return _rfb_vendor(data)


def _rfb_handshake(sock):
    """
    Exchange the RFB security-type handshake.

    Parameters
    ----------
    sock : object
        Connected socket.

    Returns
    -------
    bytes or None
        Security-type data, or None when not RFB.
    """
    greeting = sock.recv(32)
    if b"RFB" not in greeting:
        return None
    sock.sendall(greeting.split(b"\n")[0] + b"\n")
    return sock.recv(64)


def _rfb_greeting(ip: str, port: int):
    """
    Connect and read the RFB greeting and security types.

    Parameters
    ----------
    ip : str
        Target host.
    port : int
        RFB port.

    Returns
    -------
    bytes or None
        Security-type data, or None on failure.
    """
    try:
        with socket.create_connection((ip, port), timeout=1.5) as sock:
            return _rfb_handshake(sock)
    except OSError:
        return None


def _rfb_vendor(data) -> str:
    """
    Derive an RFB vendor label from security-type data.

    Parameters
    ----------
    data : bytes
        Security-type data.

    Returns
    -------
    str
        Vendor label.
    """
    if not data or data[0] >= 100:
        return "RFB"
    types = set(data[1: 1 + data[0]])
    if 30 in types:
        return "Apple Screen Sharing"
    return "RFB security types {}".format(sorted(types))


def _grab_banner(ip: str, port: int) -> str:
    """
    Extract a service banner from open ports.

    Parameters
    ----------
    ip : str
        Target host.
    port : int
        Open destination port.

    Returns
    -------
    str
        Truncated banner text or empty string.
    """
    try:
        with socket.create_connection((ip, port), timeout=1.0) as sock:
            _banner_probe(sock, port)
            try:
                return _banner_finish(ip, port, _banner_text(sock.recv(512)))
            except OSError:
                return ""
    except OSError:
        return ""


def _banner_probe(sock, port: int) -> None:
    """
    Send a protocol-appropriate probe for a port.

    Parameters
    ----------
    sock : object
        Connected socket.
    port : int
        Open destination port.

    Returns
    -------
    None
    """
    if port in (80, 8000, 8080, 8888, 5555):
        sock.sendall(b"HEAD / HTTP/1.0\r\n\r\n")
    elif port in (443, 8443):
        sock.sendall(b"\x16\x03\x01\x00\x02\x01\x00")
    elif port == 22:
        sock.sendall(b"\r\n")
    elif port in (1883, 8883):
        sock.sendall(
            bytes([0x10, 0x0E, 0x00, 0x04])
            + b"MQTT"
            + bytes([0x04, 0x02, 0x00, 0x00])
        )


def _banner_text(data: bytes) -> str:
    """
    Normalize raw banner bytes into printable text.

    Parameters
    ----------
    data : bytes
        Raw banner bytes.

    Returns
    -------
    str
        Cleaned banner text.
    """
    text = "".join(
        ch if ch in string.printable and ch not in "\r\n\t" else " "
        for ch in data.decode("utf-8", "ignore")
    )
    return re.sub(r"\s+", " ", text).strip()[:200]


def _banner_finish(ip: str, port: int, banner: str) -> str:
    """
    Append a NETGEAR firmware tag to a banner when relevant.

    Parameters
    ----------
    ip : str
        Target host.
    port : int
        Open destination port.
    banner : str
        Banner text.

    Returns
    -------
    str
        Banner text, possibly with a firmware tag.
    """
    if banner and "netgear" in banner.lower() and port in (80, 5555):
        tag = _netgear_firmware_probe(ip, port)
        if tag:
            banner = banner[:120] + " | " + tag
    return banner


def _probe_dns_version(ip: str, timeout: float = 3.0) -> str:
    """
    Identify a DNS server by querying its CHAOS-class TXT version.bind.

    Standard, non-intrusive fingerprint (RFC 1035 CHAOS class). dnsmasq
    answers with something like ``dnsmasq-2.93``; BIND answers with its
    version or refuses. Returns an empty string when the query fails.

    Parameters
    ----------
    ip : str
        DNS server address.
    timeout : float
        Socket timeout in seconds.

    Returns
    -------
    str
        Server software identity (e.g. 'dnsmasq-2.93' or 'bind'), or ''.
    """
    data = _dns_exchange(ip, _dns_query(), timeout)
    if data is None:
        return ""
    return _dns_parse(data)


def _dns_query() -> bytes:
    """
    Build a CHAOS-class TXT version.bind query.

    Parameters
    ----------
    None

    Returns
    -------
    bytes
        Encoded DNS query.
    """
    query = struct.pack("!HHHHHH", 0xAAAA, 0x0100, 1, 0, 0, 0)
    query += b"\x07version\x04bind\x00"
    query += struct.pack("!HH", 16, 3)
    return query


def _dns_recv(sock, ip: str, query: bytes):
    """
    Send a DNS query over UDP and read the response.

    Parameters
    ----------
    sock : object
        UDP socket.
    ip : str
        DNS server address.
    query : bytes
        Encoded query.

    Returns
    -------
    bytes or None
        Response bytes, or None on failure.
    """
    try:
        sock.sendto(query, (ip, 53))
        data, _ = sock.recvfrom(1024)
        return data
    except OSError:
        return None


def _dns_exchange(ip: str, query: bytes, timeout: float):
    """
    Perform one UDP DNS exchange.

    Parameters
    ----------
    ip : str
        DNS server address.
    query : bytes
        Encoded query.
    timeout : float
        Socket timeout.

    Returns
    -------
    bytes or None
        Response bytes, or None on failure.
    """
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(timeout)
    try:
        return _dns_recv(sock, ip, query)
    finally:
        sock.close()


def _dns_skip_question(data: bytes) -> int:
    """
    Skip the DNS question section.

    Parameters
    ----------
    data : bytes
        DNS response.

    Returns
    -------
    int
        Offset of the first answer.
    """
    offset = 12
    while offset < len(data) and data[offset] != 0x00:
        offset += data[offset] + 1
    return offset + 5


def _dns_skip_name(data: bytes, offset: int):
    """
    Skip a possibly-compressed DNS name.

    Parameters
    ----------
    data : bytes
        DNS response.
    offset : int
        Name offset.

    Returns
    -------
    int or None
        Next offset, or None when out of bounds.
    """
    if offset + 2 > len(data):
        return None
    if data[offset] & 0xC0 == 0xC0:
        return offset + 2
    while offset < len(data) and data[offset] != 0x00:
        offset += data[offset] + 1
    return offset + 1


def _dns_txt(txt: bytes) -> str:
    """
    Decode a DNS TXT record value.

    Parameters
    ----------
    txt : bytes
        TXT record data.

    Returns
    -------
    str
        Decoded text.
    """
    pos = 0
    parts = []
    while pos < len(txt):
        length = txt[pos]
        pos += 1
        parts.append(txt[pos: pos + length].decode("ascii", "ignore"))
        pos += length
    return "".join(parts).strip()


def _dns_answer(data: bytes, offset: int):
    """
    Parse one DNS answer record.

    Parameters
    ----------
    data : bytes
        DNS response.
    offset : int
        Answer offset.

    Returns
    -------
    tuple
        (TXT text or None, next offset).
    """
    offset = _dns_skip_name(data, offset)
    if offset is None or offset + 10 > len(data):
        return None, len(data)
    rtype, rclass, _ttl, rdlen = struct.unpack(
        "!HHIH", data[offset: offset + 10]
    )
    offset += 10
    if rtype == 16 and rclass == 3 and offset + rdlen <= len(data):
        return _dns_txt(data[offset: offset + rdlen]), offset + rdlen
    return None, offset + rdlen


def _dns_answers(data: bytes, offset: int, ancount: int) -> str:
    """
    Scan DNS answers for a TXT version string.

    Parameters
    ----------
    data : bytes
        DNS response.
    offset : int
        First answer offset.
    ancount : int
        Answer count.

    Returns
    -------
    str
        Version text or empty string.
    """
    for _ in range(ancount):
        result, offset = _dns_answer(data, offset)
        if result is not None:
            return result
    return ""


def _dns_parse(data: bytes) -> str:
    """
    Parse a DNS response for a CHAOS TXT version string.

    Parameters
    ----------
    data : bytes
        DNS response.

    Returns
    -------
    str
        Version text or empty string.
    """
    if len(data) < 12 or data[2:4] != b"\x81\x80":
        return ""
    ancount = struct.unpack("!H", data[6:8])[0]
    return _dns_answers(data, _dns_skip_question(data), ancount)


def _scan_host_ports(ip: str, ports: str = "") -> list:
    """
    Actively scan target host for open TCP ports and banners.

    Parameters
    ----------
    ip : str
        Target IPv4 address.
    ports : str
        Optional custom port list ("22,80,443" or "8000-9000").

    Returns
    -------
    list
        Open-port records with service guesses and banners.
    """
    if not ip:
        return []
    results = _port_records(ip, _port_list(ports))
    netgear_tag = _netgear_scan_tag(ip, results)
    if netgear_tag:
        _tag_netgear(results, netgear_tag)
    _tag_rfb(ip, results)
    return results


def _port_list(ports: str) -> list:
    """
    Expand a custom port specification into a list.

    Parameters
    ----------
    ports : str
        Custom port list or empty for the default set.

    Returns
    -------
    list
        Port numbers.
    """
    if not ports:
        return PORT_SCAN_DEFAULT
    port_list = []
    for token in re.split(r"[, ]+", ports.strip()):
        port_list.extend(_port_token(token))
    return port_list


def _port_token(token: str) -> list:
    """
    Expand a single custom-port token into a list.

    Parameters
    ----------
    token : str
        Port or range token.

    Returns
    -------
    list
        Port numbers.
    """
    if not token:
        return []
    if "-" in token:
        start, end = token.split("-", 1)
        return list(range(int(start), int(end) + 1))
    return [int(token)]


def _port_record(ip: str, pnum: int) -> dict:
    """
    Build an open-port record with a service guess and banner.

    Parameters
    ----------
    ip : str
        Target host.
    pnum : int
        Open port.

    Returns
    -------
    dict
        Open-port record.
    """
    return {
        "port": pnum,
        "host": ip,
        "service": COMMON_PORTS.get(pnum, "?"),
        "banner": _grab_banner(ip, pnum),
    }


def _port_records(ip: str, port_list: list) -> list:
    """
    Probe a list of ports in parallel and build records for open ones.

    Parameters
    ----------
    ip : str
        Target host.
    port_list : list
        Ports to probe.

    Returns
    -------
    list
        Open-port records.
    """
    with concurrent.futures.ThreadPoolExecutor(max_workers=48) as pool:
        futures = [pool.submit(_probe_port, ip, p) for p in port_list]
        open_port_nums = [
            f.result()
            for f in concurrent.futures.as_completed(futures)
            if f.result()
        ]
    return [_port_record(ip, pnum) for pnum in sorted(open_port_nums)]


def _banner_netgear(results: list) -> str:
    """
    Find a NETGEAR firmware tag already present in a banner.

    Parameters
    ----------
    results : list
        Open-port records.

    Returns
    -------
    str
        Banner tag or empty string.
    """
    for rec in results:
        match = re.search(
            r"NETGEAR\s+\S+\s+firmware\s+[\w._]+", rec.get("banner", "")
        )
        if match:
            return match.group(0)
    return ""


def _probe_netgear(ip: str, results: list) -> str:
    """
    Probe HTTP(S) ports for a NETGEAR firmware tag.

    Parameters
    ----------
    ip : str
        Target host.
    results : list
        Open-port records.

    Returns
    -------
    str
        Banner tag or empty string.
    """
    for rec in results:
        pnum = rec["port"]
        if pnum in (80, 443, 5555, 8080, 8443, 8888):
            tag = _netgear_firmware_probe(ip, pnum, tls=(pnum in (443, 8443)))
            if tag:
                return tag
    return ""


def _netgear_scan_tag(ip: str, results: list) -> str:
    """
    Resolve a NETGEAR firmware tag from banners or a direct probe.

    Parameters
    ----------
    ip : str
        Target host.
    results : list
        Open-port records.

    Returns
    -------
    str
        Banner tag or empty string.
    """
    tag = _banner_netgear(results)
    if tag:
        return tag
    return _probe_netgear(ip, results)


def _tag_netgear(results: list, tag: str) -> None:
    """
    Append a NETGEAR firmware tag to relevant HTTP(S) banners.

    Parameters
    ----------
    results : list
        Open-port records.
    tag : str
        Firmware tag.

    Returns
    -------
    None
    """
    for rec in results:
        if "netgear" in str(rec.get("banner", "")).lower():
            continue
        if rec["port"] in (80, 443, 8443, 5555):
            rec["banner"] = (str(rec["banner"]) + " | " + tag).strip("| ")


def _tag_record(rec: dict, vendor: str) -> None:
    """
    Append a vendor tag to one record's banner when present.

    Parameters
    ----------
    rec : dict
        Open-port record.
    vendor : str
        Vendor label.

    Returns
    -------
    None
    """
    if vendor:
        rec["banner"] = (str(rec.get("banner", "")) + " | " + vendor).strip(
            "| "
        )


def _tag_rfb(ip: str, results: list) -> None:
    """
    Tag any RFB/VNC port with its fingerprinted vendor.

    Parameters
    ----------
    ip : str
        Target host.
    results : list
        Open-port records.

    Returns
    -------
    None
    """
    for rec in results:
        if rec["port"] == 5900:
            _tag_record(rec, _probe_rfb_vendor(ip))


def _audit_host_intel(host: dict, flows_all: list, ports: str = "") -> dict:
    """
    Audit one local host address.

    Parameters
    ----------
    host : dict
        Host IP/MAC metadata.
    flows_all : list
        Router flow records for correlation.

    Returns
    -------
    dict
        Per-device intelligence record.
    """
    from .cve import _assess_vulnerabilities

    ip = host.get("ip", "")
    intel = _host_intel(host, flows_all)
    _log(
        "HOST",
        f"Auditing host: {ip} ({intel['target']['mac']}) — "
        f"{len(intel['network_flows'])} flows",
    )
    _scan_ports_step(intel, ip, ports)
    _assess_vulnerabilities(intel)
    _auto_vendor_lookup(intel, intel["target"]["mac"])
    return intel


def _host_intel(host: dict, flows_all: list) -> dict:
    """
    Build the base intelligence record for a local host.

    Parameters
    ----------
    host : dict
        Host IP/MAC metadata.
    flows_all : list
        Router flow records.

    Returns
    -------
    dict
        Intelligence container.
    """
    from .network import _flow_matches

    ip = host.get("ip", "")
    mac = host.get("mac", "")
    intel = _init_intel(ip, mac)
    intel["device_type"] = "host"
    intel["target"]["name"] = host.get("name", "")
    intel["network_flows"] = [f for f in flows_all if _flow_matches(f, ip)]
    return intel


def _scan_ports_step(intel: dict, ip: str, ports: str) -> None:
    """
    Scan a host's ports and record them on the intelligence container.

    Parameters
    ----------
    intel : dict
        Intelligence container.
    ip : str
        Target host.
    ports : str
        Optional custom port list.

    Returns
    -------
    None
    """
    intel["open_ports"] = _scan_host_ports(ip, ports)
    if intel["open_ports"]:
        _found(f"Open ports: {[p['port'] for p in intel['open_ports']]}")


def _audit_wifi_network(network: dict) -> dict:
    """
    Audit one discovered Wi-Fi network (BSSID).

    Parameters
    ----------
    network : dict
        Discovered Wi-Fi network metadata.

    Returns
    -------
    dict
        Per-device intelligence record.
    """
    from .cve import _assess_wifi_security

    bssid = network.get("bssid", "")
    intel = _wifi_intel(network, bssid)
    _log("WIFI", f"Auditing network: {intel['target']['name']} ({bssid})")
    _auto_vendor_lookup(intel, bssid)
    _assess_wifi_security(intel, network)
    return intel


def _wifi_intel(network: dict, bssid: str) -> dict:
    """
    Build the base intelligence record for a Wi-Fi network.

    Parameters
    ----------
    network : dict
        Discovered Wi-Fi network metadata.
    bssid : str
        Network BSSID.

    Returns
    -------
    dict
        Intelligence container.
    """
    intel = _init_intel("", bssid)
    intel["device_type"] = "wifi"
    intel["target"]["name"] = network.get("ssid", "")
    intel["wifi"] = {
        "band": network.get("band", ""),
        "channel": network.get("channel", ""),
        "rssi": network.get("rssi", ""),
        "security": network.get("security", ""),
    }
    return intel


def _audit_bt_classic_peer(peer: dict) -> dict:
    """
    Audit one Bluetooth Classic peer.

    Parameters
    ----------
    peer : dict
        Discovered classic peer metadata.

    Returns
    -------
    dict
        Per-device intelligence record.
    """
    from .cve import _assess_bt_security

    address = peer.get("address", "")
    intel = _bt_intel(peer, address)
    _log("BT-CLASSIC", f"Auditing peer: {intel['target']['name']} ({address})")
    _auto_vendor_lookup(intel, address)
    _assess_bt_security(intel, peer)
    return intel


def _bt_intel(peer: dict, address: str) -> dict:
    """
    Build the base intelligence record for a Bluetooth Classic peer.

    Parameters
    ----------
    peer : dict
        Discovered classic peer metadata.
    address : str
        Peer address.

    Returns
    -------
    dict
        Intelligence container.
    """
    intel = _init_intel("", address)
    intel["device_type"] = "bluetooth_classic"
    intel["target"]["name"] = peer.get("name", "")
    intel["bluetooth_classic"] = {
        "major_type": peer.get("major_type", ""),
        "minor_type": peer.get("minor_type", ""),
    }
    return intel


def _scan_radio_spectrum(ble_timeout: float) -> tuple:
    """
    Sweep the visible radio spectrum for all signals.

    Parameters
    ----------
    ble_timeout : float
        BLE scan window in seconds.

    Returns
    -------
    tuple
        Wi-Fi, Bluetooth Classic, mDNS, and host inventories plus BLE data.
    """
    _log(
        "SPECTRUM",
        "Sweeping visible radio spectrum: Wi-Fi, BLE, BT Classic, mDNS...",
    )
    ble_inventory, ble_audits = _audit_all_bluetooth(ble_timeout)
    spectrum = {
        "wifi_networks": _run_wifi_scan(),
        "ble_devices": ble_inventory,
        "bt_classic": _scan_bt_classic(),
        "mdns_services": _scan_mdns_services(),
        "local_hosts": _ping_sweep(),
        "observability_notes": [
            "2.4 GHz: Wi-Fi, Bluetooth/BLE, Zigbee/Z-Wave overlap "
            "(only Wi-Fi and Bluetooth are directly observable)",
            "5 GHz: Wi-Fi (unredacted via CoreWLAN)",
            "6 GHz: Wi-Fi 6E APs appear in the scan when present",
            "Sub-GHz / cellular / satellite / other radio: requires "
            "external SDR hardware, not observable on this Mac",
            "Wi-Fi SSIDs are read via Apple CoreWLAN (swift, no sudo, "
            "no macOS redaction)",
        ],
    }
    return spectrum, ble_audits
