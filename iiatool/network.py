"""Network audit functions for ARP, router socket, and flow parsing."""

import concurrent.futures
import json
import re
import socket
import subprocess

from .utils import _found, _log, _warn


def _resolve_arp_mac(ip_addr: str) -> str:
    """
    Resolve MAC address from local ARP table.

    Parameters
    ----------
    ip_addr : str
        Host IPv4 address.

    Returns
    -------
    str
        Colon-separated MAC or empty string.
    """
    cmd = ["arp", "-n", ip_addr]
    out = subprocess.run(cmd, capture_output=True, text=True).stdout
    pat = r"([0-9a-fA-F]{1,2}(?::[0-9a-fA-F]{1,2}){5})"
    match = re.search(pat, out)
    return match.group(1).lower() if match else ""


def _read_socket_chunk(sock: socket.socket) -> bytes:
    """
    Read single buffer slice from socket.

    Parameters
    ----------
    sock : socket.socket
        Active socket.

    Returns
    -------
    bytes
        Slice bytes or empty on error.
    """
    try:
        return sock.recv(65536)
    except OSError:
        return b""


def _recv_socket_chunks(sock: socket.socket) -> bytes:
    """
    Read incoming socket stream until timeout.

    Parameters
    ----------
    sock : socket.socket
        Active stream socket.

    Returns
    -------
    bytes
        Accumulated stream payload.
    """
    chunks = []
    while data := _read_socket_chunk(sock):
        chunks.append(data)
    return b"".join(chunks)


def _query_router_socket(router_ip: str, cmd: str = "get_flows") -> str:
    """
    Request data from gateway agent socket.

    Parameters
    ----------
    router_ip : str
        Router IPv4 address.
    cmd : str
        JSON command name for the agent.

    Returns
    -------
    str
        Raw JSON string from router.
    """
    request = json.dumps({"cmd": cmd}) + "\n"
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.settimeout(1.0)
        s.connect((router_ip, 4200))
        s.sendall(request.encode("utf-8"))
        raw_bytes = _recv_socket_chunks(s)
        return raw_bytes.decode("utf-8", "ignore")


def _flow_matches(flow: dict, target_ip: str) -> bool:
    """
    Check if flow involves target IP.

    Parameters
    ----------
    flow : dict
        Flow dictionary.
    target_ip : str
        Target IP.

    Returns
    -------
    bool
        True if matching.
    """
    src = flow.get("src") or flow.get("src_addr")
    dst = flow.get("dst") or flow.get("dst_addr")
    return src == target_ip or dst == target_ip


def _parse_flows_list(obj: dict) -> list:
    """
    Extract flow records from parsed router response.

    Parameters
    ----------
    obj : dict
        Parsed outer response.

    Returns
    -------
    list
        Raw flow records list.
    """
    if not isinstance(obj, dict):
        return []
    msg = obj.get("msg")
    if isinstance(msg, str) and msg.startswith("["):
        try:
            return json.loads(msg)
        except json.JSONDecodeError:
            return []
    return obj.get("flows", [])


def _filter_flows(target_ip: str, raw_json: str) -> list:
    """
    Filter socket flows involving target IP.

    Parameters
    ----------
    target_ip : str
        Filter IP address.
    raw_json : str
        JSON payload from router.

    Returns
    -------
    list
        Matching network flow records.
    """
    try:
        obj = json.loads(raw_json)
    except json.JSONDecodeError:
        return []
    return [f for f in _parse_flows_list(obj) if _flow_matches(f, target_ip)]


def _record_router_flows(intel: dict, target_ip: str, router_ip: str) -> None:
    """
    Fetch and store gateway flows.

    Parameters
    ----------
    intel : dict
        Intelligence state dictionary.
    target_ip : str
        Target IPv4 address.
    router_ip : str
        Gateway router address.

    Returns
    -------
    None
    """
    try:
        raw = _query_router_socket(router_ip)
        intel["network_flows"] = _filter_flows(target_ip, raw)
        _found(f"Captured {len(intel['network_flows'])} gateway flows")
    except OSError as err:
        _warn(f"Router socket skipped: {err}")


def _audit_network(intel: dict, target_ip: str, router_ip: str) -> None:
    """
    Perform local ARP and gateway flow audit.

    Parameters
    ----------
    intel : dict
        Intelligence state dictionary.
    target_ip : str
        Target IPv4 address.
    router_ip : str
        Gateway router address.

    Returns
    -------
    None
    """
    _log("NETWORK", f"Auditing target network state: {target_ip}")
    if not intel["target"].get("mac"):
        mac = _resolve_arp_mac(target_ip)
        intel["target"]["mac"] = mac
        _found(f"Resolved MAC: {mac}")
    _record_router_flows(intel, target_ip, router_ip)


def _fetch_router_flows_all(router_ip: str) -> list:
    """
    Pull all flow records from router agent once.

    Parameters
    ----------
    router_ip : str
        Gateway agent address.

    Returns
    -------
    list
        Unfiltered router flow records.
    """
    obj = _fetch_router_json_cmd(router_ip, "get_flows")
    return _parse_flows_list(obj) if obj else []


def _fetch_router_json_cmd(router_ip: str, cmd: str) -> dict:
    """
    Query router agent and parse JSON response, tolerating failure.

    Parameters
    ----------
    router_ip : str
        Gateway agent address.
    cmd : str
        Agent command name.

    Returns
    -------
    dict
        Parsed JSON object or empty dict when unavailable.
    """
    try:
        raw = _query_router_socket(router_ip, cmd)
        return json.loads(raw)
    except (OSError, json.JSONDecodeError) as err:
        _warn(f"Router {cmd} query skipped: {err}")
        return {}


def _fetch_router_aux(router_ip: str) -> tuple:
    """
    Pull unredacted Wi-Fi AP scan and client table from router agent.

    Router agent commands:
      get_wifi_scan -> {"networks"/"aps"/"scan": [{ssid, bssid, channel,
                          rssi/quality, security, band}]}
      get_clients   -> {"clients"/"leases": [{ip, mac, name, hostname}]}

    Parameters
    ----------
    router_ip : str
        Gateway agent address.

    Returns
    -------
    tuple
        (AP list, client list) from router agent (may be empty).
    """
    aps, clients = [], []
    raw = _fetch_router_json_cmd(router_ip, "get_wifi_scan")
    if raw:
        aps = raw.get("networks") or raw.get("aps") or raw.get("scan") or []
    raw = _fetch_router_json_cmd(router_ip, "get_clients")
    if raw:
        clients = raw.get("clients") or raw.get("leases") or []
    return aps, clients


def _arp_all_hosts() -> list:
    """
    Enumerate local network hosts from the ARP table.

    Parameters
    ----------
    None

    Returns
    -------
    list
        Host dictionaries with IP and MAC.
    """
    out = _arp_table()
    if out is None:
        return []
    return _parse_arp(out)


def _arp_table():
    """
    Read the kernel ARP table, or None on failure.

    Parameters
    ----------
    None

    Returns
    -------
    str or None
        Raw ``arp -an`` output.
    """
    try:
        return subprocess.run(
            ["arp", "-an"], capture_output=True, text=True, timeout=10
        ).stdout
    except (OSError, subprocess.SubprocessError) as err:
        _warn(f"ARP discovery failed: {err}")
        return None


def _parse_arp(out: str) -> list:
    """
    Parse ``arp -an`` output into host records.

    Parameters
    ----------
    out : str
        Raw ARP table text.

    Returns
    -------
    list
        Host dictionaries with IP and MAC.
    """
    hosts = []
    pattern = re.compile(r"\(([0-9.]+)\)\s+at\s+([0-9a-fA-F:]+)")
    for line in out.splitlines():
        host = _arp_host(pattern.search(line))
        if host:
            hosts.append(host)
    return hosts


def _arp_valid(match) -> bool:
    """
    Report whether an ARP match is a usable unicast host line.

    Parameters
    ----------
    match : re.Match or None
        Regex match.

    Returns
    -------
    bool
        True when the line names a usable host IP.
    """
    return bool(match) and not _arp_skip_ip(match.group(1))


def _arp_skip_ip(ip: str) -> bool:
    """
    Report whether an IP is multicast, link-local, or broadcast.

    Parameters
    ----------
    ip : str
        Host IP.

    Returns
    -------
    bool
        True when the IP should be skipped.
    """
    if ip.startswith(("224.", "239.", "169.254.")):
        return True
    return ip == "255.255.255.255" or ip.endswith(".255")


def _arp_mac(raw_mac: str) -> str:
    """
    Normalize an ARP MAC field.

    Parameters
    ----------
    raw_mac : str
        Raw MAC text.

    Returns
    -------
    str
        Normalized MAC or empty string.
    """
    mac = raw_mac.lower() if raw_mac != "?" else ""
    if mac:
        mac = ":".join(part.zfill(2) for part in mac.split(":"))
    return mac


def _arp_host(match):
    """
    Build a host record from an ARP line match.

    Parameters
    ----------
    match : re.Match or None
        Regex match.

    Returns
    -------
    dict or None
        Host record, or None when the line should be skipped.
    """
    if not _arp_valid(match):
        return None
    mac = _arp_mac(match.group(2))
    if mac in ("ff:ff:ff:ff:ff:ff", "00:00:00:00:00:00"):
        return None
    return {"ip": match.group(1), "mac": mac}


def _local_ipv4() -> str:
    """
    Determine this host's primary LAN IPv4 address.

    Parameters
    ----------
    None

    Returns
    -------
    str
        Local IPv4 address, or empty string when undiscoverable.
    """
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        sock.connect(("8.8.8.8", 80))
        return sock.getsockname()[0]
    except OSError:
        return ""
    finally:
        sock.close()


def _ping_once(ip: str) -> str:
    """
    Send a single ICMP echo so the kernel resolves the peer's MAC.

    Parameters
    ----------
    ip : str
        Target IPv4 address.

    Returns
    -------
    str
        The probed address (result is unused; the side effect matters).
    """
    try:
        subprocess.run(
            ["ping", "-c", "1", "-W", "400", ip],
            capture_output=True,
            timeout=2,
        )
    except (OSError, subprocess.SubprocessError):
        return ""
    return ip


def _ping_sweep() -> list:
    """
    Populate the ARP cache across the local /24, then enumerate hosts.

    ICMP is sent in parallel to every address in this host's subnet so the
    kernel resolves each live peer's MAC; the ARP table is then read once.
    This surfaces hosts that never generated recent local traffic and would
    otherwise be missing from the ARP cache.

    Parameters
    ----------
    None

    Returns
    -------
    list
        Host dictionaries with IP and MAC.
    """
    local = _local_ipv4()
    if not local:
        return _arp_all_hosts()
    prefix = local.rsplit(".", 1)[0] + "."
    targets = [prefix + str(i) for i in range(1, 255)]
    with concurrent.futures.ThreadPoolExecutor(max_workers=64) as pool:
        list(pool.map(_ping_once, targets))
    return _arp_all_hosts()
