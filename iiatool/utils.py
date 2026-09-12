"""Utility functions for the IoT Intel Audit tool."""

import os
from datetime import datetime, timezone


def _log(section: str, msg: str) -> None:
    """
    Print an informational log line.

    Parameters
    ----------
    section : str
        Subsystem tag.
    msg : str
        Log message content.

    Returns
    -------
    None
    """
    print(f"[*] [{section}] {msg}")


def _warn(msg: str) -> None:
    """
    Print a warning log line.

    Parameters
    ----------
    msg : str
        Warning details.

    Returns
    -------
    None
    """
    print(f"[!] [WARNING] {msg}")


def _found(msg: str) -> None:
    """
    Print a discovered finding log line.

    Parameters
    ----------
    msg : str
        Discovery description.

    Returns
    -------
    None
    """
    print(f"[+] [FOUND] {msg}")


def _base_intel_dict(target_ip: str, target_mac: str) -> dict:
    """
    Construct base target metadata.

    Parameters
    ----------
    target_ip : str
        Target IPv4 address.
    target_mac : str
        Target MAC address.

    Returns
    -------
    dict
        Base container.
    """
    ts = datetime.now(timezone.utc).isoformat()
    tgt = {"ip": target_ip, "mac": target_mac}
    return {"timestamp": ts, "target": tgt, "regulatory": {}}


def _init_intel(target_ip: str, target_mac: str) -> dict:
    """
    Initialize empty intelligence container.

    Parameters
    ----------
    target_ip : str
        Target IP address.
    target_mac : str
        Target MAC address.

    Returns
    -------
    dict
        Structured intelligence records.
    """
    intel = _base_intel_dict(target_ip, target_mac)
    intel["vendor_oui"] = {}
    intel["network_flows"] = []
    intel["ble_telemetry"] = {}
    intel["pcap_forensics"] = {}
    intel["cloud_c2"] = {}
    intel["blue_team_risk_assessment"] = []
    return intel


def _clean_mac(mac: str) -> str:
    """
    Strip delimiters and uppercase MAC string.

    Parameters
    ----------
    mac : str
        Input MAC address.

    Returns
    -------
    str
        Cleaned hex characters.
    """
    return mac.replace(":", "").replace("-", "").upper()


def _write_file(path_str: str, content: str) -> None:
    """
    Write text content to file.

    Parameters
    ----------
    path_str : str
        Target file path.
    content : str
        String payload.

    Returns
    -------
    None
    """
    parent = os.path.dirname(path_str)
    if parent:
        os.makedirs(parent, exist_ok=True)
    with open(path_str, "w", encoding="utf-8") as f:
        f.write(content)
    _found(f"Exported artifact: {path_str}")
