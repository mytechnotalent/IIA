"""Packet capture forensics and cloud endpoint enrichment."""

import json
import os
import re
import urllib.error
import urllib.request

from .constants import IPINFO_URL
from .utils import _found, _log, _warn

try:
    import scapy.all as scapy

    HAS_SCAPY = True
except ImportError:
    HAS_SCAPY = False


def _is_tls_app_data(payload: bytes) -> bool:
    """
    Validate presence of TLS 1.2 Application Data header.

    Parameters
    ----------
    payload : bytes
        Raw TCP payload slice.

    Returns
    -------
    bool
        True if starts with 0x17 0x03 0x03.
    """
    return len(payload) >= 5 and payload[:3] == b"\x17\x03\x03"


def _extract_tcp_meta(p: object, target_ip: str) -> tuple:
    """
    Extract tuple metadata from one TCP IP packet.

    Parameters
    ----------
    p : object
        Scapy packet frame.
    target_ip : str
        Monitored device IP address.

    Returns
    -------
    tuple
        Deduplication key, remote endpoint, and stack profile.
    """
    ipl = p[scapy.IP]
    tcpl = p[scapy.TCP]
    tx_key = (ipl.src, ipl.dst, tcpl.seq, ipl.id)
    ep, stack = _packet_endpoint(ipl, tcpl, target_ip)
    return tx_key, ep, stack


def _packet_endpoint(ipl, tcpl, target_ip: str) -> tuple:
    """
    Derive the remote endpoint and stack profile for a packet.

    Parameters
    ----------
    ipl : object
        Scapy IP layer.
    tcpl : object
        Scapy TCP layer.
    target_ip : str
        Monitored device IP address.

    Returns
    -------
    tuple
        (endpoint, stack profile).
    """
    if ipl.src == target_ip:
        return (ipl.dst, tcpl.dport), {"ttl": ipl.ttl, "window": tcpl.window}
    if ipl.dst == target_ip:
        return (ipl.src, tcpl.sport), None
    return None, None


def _tls_handshake_sni(payload: bytes) -> str:
    """
    Extract the TLS Server Name Indication from a ClientHello.

    Parameters
    ----------
    payload : bytes
        Raw TCP payload.

    Returns
    -------
    str
        SNI hostname or empty string.
    """
    head = _tls_head(payload)
    if head is None:
        return ""
    return _tls_sni_body(payload, head[0], head[1])


def _tls_head(payload: bytes):
    """
    Parse a TLS record/handshake header into bounds.

    Parameters
    ----------
    payload : bytes
        Raw TCP payload.

    Returns
    -------
    tuple or None
        (handshake start offset, handshake end offset).
    """
    if len(payload) < 6 or payload[0] != 0x16 or payload[1] != 0x03:
        return None
    offset = 5
    handshake_len = int.from_bytes(payload[offset + 1: offset + 4], "big")
    offset += 4
    return offset + 34, min(offset + handshake_len, len(payload))


def _tls_skip_var(payload: bytes, offset: int, end: int):
    """
    Skip a one-byte-length-prefixed field.

    Parameters
    ----------
    payload : bytes
        Raw payload.
    offset : int or None
        Field offset.
    end : int
        Handshake end offset.

    Returns
    -------
    int or None
        Next offset, or None when out of bounds.
    """
    if offset is None or offset + 1 > end:
        return None
    return offset + 1 + payload[offset]


def _tls_skip_fixed(offset: int, width: int, end: int):
    """
    Skip a fixed-width field.

    Parameters
    ----------
    offset : int or None
        Field offset.
    width : int
        Field width.
    end : int
        Handshake end offset.

    Returns
    -------
    int or None
        Next offset, or None when out of bounds.
    """
    if offset is None or offset + width > end:
        return None
    return offset + width


def _tls_sni_body(payload: bytes, offset: int, end: int) -> str:
    """
    Skip session, cipher, and compression fields, then scan extensions.

    Parameters
    ----------
    payload : bytes
        Raw payload.
    offset : int
        Handshake body offset.
    end : int
        Handshake end offset.

    Returns
    -------
    str
        SNI hostname or empty string.
    """
    offset = _tls_skip_var(payload, offset, end)
    offset = _tls_skip_fixed(offset, 2, end)
    offset = _tls_skip_var(payload, offset, end)
    if offset is None or offset + 2 > end:
        return ""
    return _tls_sni_ext(payload, offset, end)


def _tls_ext_step(payload: bytes, offset: int, ext_end: int):
    """
    Process one TLS extension.

    Parameters
    ----------
    payload : bytes
        Raw payload.
    offset : int
        Extension offset.
    ext_end : int
        Extensions end offset.

    Returns
    -------
    tuple
        (name or None, next offset).
    """
    ext_type = int.from_bytes(payload[offset: offset + 2], "big")
    ext_len = int.from_bytes(payload[offset + 2: offset + 4], "big")
    offset += 4
    if ext_type == 0 and offset + 2 <= ext_end:
        return _sni_name(payload, offset), offset + ext_len
    return None, offset + ext_len


def _sni_name(payload: bytes, offset: int) -> str:
    """
    Decode the SNI host name from a server-name extension.

    Parameters
    ----------
    payload : bytes
        Raw payload.
    offset : int
        Extension data offset.

    Returns
    -------
    str
        SNI hostname.
    """
    name_len = int.from_bytes(payload[offset: offset + 2], "big")
    name = payload[offset + 2: offset + 2 + name_len]
    return name.decode("utf-8", "ignore").strip()


def _tls_sni_ext(payload: bytes, offset: int, end: int) -> str:
    """
    Scan TLS extensions for the Server Name Indication.

    Parameters
    ----------
    payload : bytes
        Raw payload.
    offset : int
        Extension-length field offset.
    end : int
        Handshake end offset.

    Returns
    -------
    str
        SNI hostname or empty string.
    """
    ext_total = int.from_bytes(payload[offset: offset + 2], "big")
    offset += 2
    ext_end = min(offset + ext_total, end)
    while offset + 4 <= ext_end:
        name, offset = _tls_ext_step(payload, offset, ext_end)
        if name is not None:
            return name
    return ""


def _extract_http_host(payload: bytes) -> str:
    """
    Extract HTTP Host header from a request payload.

    Parameters
    ----------
    payload : bytes
        Raw TCP payload.

    Returns
    -------
    str
        Host value or empty string.
    """
    if len(payload) < 10:
        return ""
    match = re.search(rb"[Hh][Oo][Ss][Tt]:\s*([^\r\n]+)", payload[:1024])
    if not match:
        return ""
    return match.group(1).decode("latin1", "ignore").strip()


def _extract_mqtt_topics(payload: bytes) -> list:
    """
    Extract MQTT topics and client identifiers from MQTT frames.

    Parameters
    ----------
    payload : bytes
        Raw TCP payload.

    Returns
    -------
    list
        Discovered topic and client-id strings.
    """
    if not payload:
        return []
    fixed = payload[0]
    if fixed & 0xF0 == 0x30:
        return _mqtt_publish(payload)
    if fixed & 0xF0 == 0x10:
        return _mqtt_connect(payload)
    return []


def _mqtt_varint(payload: bytes, idx: int = 1) -> int:
    """
    Skip an MQTT remaining-length varint.

    Parameters
    ----------
    payload : bytes
        Raw payload.
    idx : int
        Starting index.

    Returns
    -------
    int
        Index after the varint.
    """
    while idx < len(payload):
        byte = payload[idx]
        idx += 1
        if byte & 0x80 == 0:
            break
    return idx


def _mqtt_publish(payload: bytes) -> list:
    """
    Extract the topic from a PUBLISH frame.

    Parameters
    ----------
    payload : bytes
        Raw payload.

    Returns
    -------
    list
        Topic strings.
    """
    idx = _mqtt_varint(payload)
    if idx + 2 > len(payload):
        return []
    topic_len = int.from_bytes(payload[idx: idx + 2], "big")
    topic = payload[idx + 2: idx + 2 + topic_len].decode("utf-8", "ignore")
    return [topic] if topic else []


def _mqtt_client(payload: bytes, idx: int) -> list:
    """
    Extract the client identifier from a CONNECT frame.

    Parameters
    ----------
    payload : bytes
        Raw payload.
    idx : int
        Client-id offset.

    Returns
    -------
    list
        Client-id strings.
    """
    if idx + 2 > len(payload):
        return []
    client_len = int.from_bytes(payload[idx: idx + 2], "big")
    client_id = payload[idx + 2: idx + 2 + client_len].decode(
        "utf-8", "ignore"
    )
    return [f"client_id:{client_id}"] if client_id else []


def _mqtt_connect(payload: bytes) -> list:
    """
    Extract the client identifier from a CONNECT frame.

    Parameters
    ----------
    payload : bytes
        Raw payload.

    Returns
    -------
    list
        Client-id strings.
    """
    idx = _mqtt_varint(payload)
    if idx + 2 > len(payload):
        return []
    idx += 2 + int.from_bytes(payload[idx: idx + 2], "big") + 1
    return _mqtt_client(payload, idx)


def _update_pcap_state(state: dict, p: object, target_ip: str) -> None:
    """
    Process single TCP frame into accumulation state.

    Parameters
    ----------
    state : dict
        Tracking dictionary.
    p : object
        Scapy packet.
    target_ip : str
        Target IP address.

    Returns
    -------
    None
    """
    key, ep, stack = _extract_tcp_meta(p, target_ip)
    state["tx_set"].add(key)
    raw_payload = _record_endpoint(state, ep, bytes(p[scapy.TCP].payload))
    _record_stack(state, stack)
    _record_payload(state, raw_payload)
    _record_dns(state, p)


def _record_endpoint(state: dict, ep, raw: bytes) -> bytes:
    """
    Record endpoint traffic statistics for one packet.

    Parameters
    ----------
    state : dict
        Tracking dictionary.
    ep : tuple or None
        Remote endpoint.
    raw : bytes
        Raw TCP payload.

    Returns
    -------
    bytes
        The raw payload (unchanged).
    """
    if not ep:
        return raw
    remote_ip, remote_port = ep
    endpoint = state["endpoints"].setdefault(
        remote_ip, {"ports": set(), "pkts": 0, "bytes": 0}
    )
    endpoint["ports"].add(remote_port)
    endpoint["pkts"] += 1
    endpoint["bytes"] += len(raw)
    return raw


def _record_stack(state: dict, stack) -> None:
    """
    Record the first observed stack profile.

    Parameters
    ----------
    state : dict
        Tracking dictionary.
    stack : dict or None
        Stack profile.

    Returns
    -------
    None
    """
    if stack and not state["stack"]:
        state["stack"] = stack


def _record_payload(state: dict, raw: bytes) -> None:
    """
    Record TLS, HTTP, and MQTT indicators from a payload.

    Parameters
    ----------
    state : dict
        Tracking dictionary.
    raw : bytes
        Raw TCP payload.

    Returns
    -------
    None
    """
    if _is_tls_app_data(raw):
        state["tls"] = True
    for value in (_tls_handshake_sni(raw), _extract_http_host(raw)):
        if value:
            state["domains"].add(value)
    state["mqtt_topics"].update(_extract_mqtt_topics(raw))


def _record_dns(state: dict, p: object) -> None:
    """
    Record DNS query names carried by a packet.

    Parameters
    ----------
    state : dict
        Tracking dictionary.
    p : object
        Scapy packet.

    Returns
    -------
    None
    """
    if p.haslayer(scapy.DNS) and p[scapy.DNS].qr == 0:
        query = p[scapy.DNS].qd
        if query and query.qname:
            state["domains"].add(str(query.qname).rstrip("."))


def _collect_dns_names(state: dict, p: object) -> None:
    """
    Record DNS query names for non-TCP DNS frames.

    Parameters
    ----------
    state : dict
        Tracking dictionary.
    p : object
        Scapy packet.

    Returns
    -------
    None
    """
    if p.haslayer(scapy.DNS) and p[scapy.DNS].qr == 0:
        query = p[scapy.DNS].qd
        if query and query.qname:
            state["domains"].add(str(query.qname).rstrip("."))


def _parse_pcap_frames(packets: list, target_ip: str) -> tuple:
    """
    Iterate over raw packets to extract deep flow intelligence.

    Parameters
    ----------
    packets : list
        Scapy packet collection.
    target_ip : str
        Target device IPv4 address.

    Returns
    -------
    tuple
        Unique transaction count, endpoint stats map, stack info, TLS flag,
        observed domain names, and MQTT topics.
    """
    st = {
        "tx_set": set(),
        "endpoints": {},
        "stack": {},
        "tls": False,
        "domains": set(),
        "mqtt_topics": set(),
    }
    for p in packets:
        _frame_step(st, p, target_ip)
    return (
        len(st["tx_set"]),
        st["endpoints"],
        st["stack"],
        st["tls"],
        st["domains"],
        st["mqtt_topics"],
    )


def _frame_step(state: dict, p: object, target_ip: str) -> None:
    """
    Dispatch one packet to the TCP or DNS handler.

    Parameters
    ----------
    state : dict
        Tracking dictionary.
    p : object
        Scapy packet.
    target_ip : str
        Target IP address.

    Returns
    -------
    None
    """
    if not p.haslayer(scapy.IP):
        return
    if p.haslayer(scapy.TCP):
        _update_pcap_state(state, p, target_ip)
    elif p.haslayer(scapy.DNS):
        _collect_dns_names(state, p)


def _fetch_ipinfo_dict(remote_ip: str) -> dict:
    """
    Query ipinfo API for IP metadata.

    Parameters
    ----------
    remote_ip : str
        Remote target IP address.

    Returns
    -------
    dict
        Parsed JSON dictionary from service.
    """
    url = f"{IPINFO_URL}{remote_ip}/json"
    req = urllib.request.Request(url, headers={"User-Agent": "Audit/1.0"})
    with urllib.request.urlopen(req, timeout=5.0) as resp:
        return json.loads(resp.read().decode())


def _enrich_endpoint(remote_ip: str) -> dict:
    """
    Retrieve full ASN, hosting, and geolocation data for a remote endpoint.

    Parameters
    ----------
    remote_ip : str
        Target remote IPv4 address.

    Returns
    -------
    dict
        Parsed geolocation and ASN data.
    """
    d = _fetch_ipinfo_dict(remote_ip)
    c2 = {
        "ip": remote_ip,
        "loc": d.get("loc", ""),
        "org": d.get("org", ""),
        "asn": d.get("asn", ""),
        "hostname": d.get("hostname", ""),
        "city": d.get("city", ""),
        "region": d.get("region", ""),
        "country": d.get("country", ""),
        "anycast": d.get("anycast", None),
    }
    return c2


def _process_cloud_endpoints(
    intel: dict, endpoints: dict, cache: dict = None
) -> None:
    """
    Enrich all remote C2 IP endpoints.

    Parameters
    ----------
    intel : dict
        Intelligence container.
    endpoints : dict
        Remote IP to stats mapping.
    cache : dict
        Optional ipinfo lookup cache.

    Returns
    -------
    None
    """
    if cache is None:
        cache = {}
    enriched = []
    for remote_ip, stats in endpoints.items():
        entry = _cloud_entry(cache, remote_ip)
        if entry:
            enriched.append(_stamp_entry(entry, stats, remote_ip))
    intel["cloud_c2"] = enriched


def _cloud_entry(cache: dict, remote_ip: str):
    """
    Return a cached or freshly enriched endpoint record.

    Parameters
    ----------
    cache : dict
        ipinfo lookup cache.
    remote_ip : str
        Remote IP address.

    Returns
    -------
    dict or None
        Endpoint record.
    """
    entry = cache.get(remote_ip)
    if entry is not None:
        return entry
    return _lookup_cloud(cache, remote_ip)


def _lookup_cloud(cache: dict, remote_ip: str):
    """
    Enrich a remote endpoint and cache the result.

    Parameters
    ----------
    cache : dict
        ipinfo lookup cache.
    remote_ip : str
        Remote IP address.

    Returns
    -------
    dict or None
        Endpoint record.
    """
    try:
        entry = _enrich_endpoint(remote_ip)
        cache[remote_ip] = entry
        return entry
    except urllib.error.URLError as err:
        _warn(f"Cloud endpoint lookup failed: {err}")
        return None


def _stamp_entry(entry: dict, stats: dict, remote_ip: str) -> dict:
    """
    Attach traffic statistics to an enriched endpoint record.

    Parameters
    ----------
    entry : dict
        Enriched endpoint record.
    stats : dict
        Traffic statistics.
    remote_ip : str
        Remote IP address.

    Returns
    -------
    dict
        Stamped endpoint record.
    """
    entry = dict(entry)
    entry["ports"] = sorted(stats["ports"])
    entry["pkts"] = stats["pkts"]
    entry["bytes"] = stats["bytes"]
    _found(f"C2: {remote_ip} ({entry.get('org')}) ports {entry['ports']}")
    return entry


def _read_pcap_frames(pcap_path: str) -> list:
    """
    Load raw packet frames from disk capture.

    Parameters
    ----------
    pcap_path : str
        Filesystem path to pcap.

    Returns
    -------
    list
        Loaded packet frames.
    """
    _log("PCAP", f"Dissecting packet capture: {pcap_path}")
    return scapy.rdpcap(pcap_path)


def _audit_pcap(intel: dict, pcap_path: str, target_ip: str) -> None:
    """
    Audit packet capture file for stack fingerprint and C2 endpoints.

    Parameters
    ----------
    intel : dict
        Intelligence container.
    pcap_path : str
        Filesystem path to pcap.
    target_ip : str
        Monitored IP address.

    Returns
    -------
    None
    """
    if not (HAS_SCAPY and pcap_path and os.path.exists(pcap_path)):
        _warn("PCAP file or Scapy not available; skipping packet audit")
        return
    pkts = _read_pcap_frames(pcap_path)
    parsed = _parse_pcap_frames(pkts, target_ip)
    _store_pcap(intel, parsed)
    _process_cloud_endpoints(intel, parsed[1])


def _store_pcap(intel: dict, parsed: tuple) -> None:
    """
    Store parsed pcap intelligence and announce it.

    Parameters
    ----------
    intel : dict
        Intelligence container.
    parsed : tuple
        Parsed pcap tuple.

    Returns
    -------
    None
    """
    u_tx, _endpoints, stack, tls, domains, mqtt = parsed
    intel["pcap_forensics"] = {
        "unique_tx": u_tx,
        "stack_fingerprint": stack,
        "tls_application_data": tls,
        "observed_domains": sorted(domains),
        "mqtt_topics": sorted(mqtt),
    }
    _found(f"PCAP: frames ({u_tx} tx) | Stack: {stack}")
    _found(f"Domains observed: {len(domains)} | MQTT topics: {len(mqtt)}")
