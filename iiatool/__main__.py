"""Command-line entry point for the IIA IoT intelligence auditor."""

import argparse
import json
import os
import sys
from datetime import datetime, timezone

from .ble import _audit_bluetooth
from .constants import DEFAULT_IP, DEFAULT_MAC, DEFAULT_ROUTER
from .cve import _assess_vulnerabilities
from .firmware import (
    carve_findings,
    detect_upx,
    entropy_pass,
    extract_tree,
    scan_file,
)
from .network import (
    _audit_network,
    _fetch_router_aux,
    _fetch_router_flows_all,
)
from .pcap import _audit_pcap
from .report import (
    _export_firmware_reports,
    _export_reports,
    _format_giant_markdown,
)
from .static import (
    build_sbom,
    join_cves,
    load_mirror,
    scan_licenses,
    scan_secrets,
    to_cyclonedx,
    to_spdx,
)
from .scan import (
    _audit_bt_classic_peer,
    _audit_host_intel,
    _audit_wifi_network,
    _scan_host_ports,
    _scan_radio_spectrum,
)
from .utils import _found, _init_intel, _log, _write_file
from .vendor import _audit_vendor_regulatory, _maybe_fcc_resolve


def _parser_net_args() -> list:
    """
    Return network-related argument configs.

    Parameters
    ----------
    None

    Returns
    -------
    list
        Network argument configurations.
    """
    return [
        ("--target-ip", DEFAULT_IP, "Target IPv4"),
        ("--target-mac", DEFAULT_MAC, "Target MAC"),
        ("--router-ip", DEFAULT_ROUTER, "Gateway IP"),
        ("--ble", "tovala", "BLE search filter"),
        ("--ble-timeout", 5.0, "BLE scan timeout"),
    ]


def _parser_file_args() -> list:
    """
    Return file-related argument configs.

    Default report outputs are timestamped and written to reports/ so
    successive audits never overwrite one another.

    Parameters
    ----------
    None

    Returns
    -------
    list
        File argument configurations.
    """
    stamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    json_dflt = os.path.join("reports", f"iot_intel_report_{stamp}.json")
    md_dflt = os.path.join("reports", f"IOT_BLUE_TEAM_AUDIT_{stamp}.md")
    return [
        ("--pcap", "tovala.pcap", "PCAP path"),
        ("--json", json_dflt, "JSON output path"),
        ("--report", md_dflt, "Markdown report path"),
    ]


def _parser_arguments() -> list:
    """
    Return CLI argument configuration list.

    Parameters
    ----------
    None

    Returns
    -------
    list
        Argument option configurations.
    """
    return _parser_net_args() + _parser_file_args()


def _build_arg_parser() -> argparse.ArgumentParser:
    """
    Assemble command-line interface arguments.

    Parameters
    ----------
    None

    Returns
    -------
    argparse.ArgumentParser
        Configured argument parser.
    """
    parser = argparse.ArgumentParser(description="IoT Intelligence Auditor")
    for opt, dflt, help_txt in _parser_arguments():
        t = float if isinstance(dflt, float) else str
        parser.add_argument(opt, default=dflt, type=t, help=help_txt)
    _add_mode_args(parser)
    _add_firmware_args(parser)
    return parser


def _add_mode_args(parser: argparse.ArgumentParser) -> None:
    """
    Add the network/radio mode arguments to the parser.

    Parameters
    ----------
    parser : argparse.ArgumentParser
        Target parser.

    Returns
    -------
    None
    """
    parser.add_argument(
        "--all",
        action="store_true",
        help=(
            "Network-wide mode: sweep the radio spectrum (Wi-Fi 2.4/5 GHz, "
            "BLE, BT Classic, mDNS, ARP hosts), audit every address, and "
            "write a combined report plus info.json"
        ),
    )
    parser.add_argument(
        "--info",
        default=os.path.join(
            "reports", f"info_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        ),
        help="Discovery inventory output path (used with --all)",
    )
    parser.add_argument(
        "--no-scan-ports",
        action="store_true",
        help="Disable active TCP port scanning of discovered hosts",
    )
    parser.add_argument(
        "--ports",
        default="",
        help='Custom TCP ports to scan, e.g. "22,80,443" or "8000-9000"',
    )
    parser.add_argument(
        "--fcc-id",
        default="",
        help="FCC equipment authorization ID to resolve directly, "
        "e.g. VPYLB1MDIMP004",
    )


def _add_firmware_args(parser: argparse.ArgumentParser) -> None:
    """
    Add the offline firmware/static arguments to the parser.

    Parameters
    ----------
    parser : argparse.ArgumentParser
        Target parser.

    Returns
    -------
    None
    """
    parser.add_argument(
        "--firmware",
        default="",
        help="Offline firmware/rootfs analysis: identify, entropy, UPX, "
        "secrets, SBOM, licenses, and (with --extract-dir) unpacking",
    )
    parser.add_argument(
        "--extract-dir",
        default="",
        help="Unpack recursively into this directory (used with --firmware)",
    )
    parser.add_argument(
        "--carve-dir",
        default="",
        help=(
            "Carve identified regions into this directory "
            "(used with --firmware)"
        ),
    )
    parser.add_argument(
        "--broad",
        action="store_true",
        help="Load general file-type signatures during identification",
    )
    parser.add_argument(
        "--cve-mirror",
        default="",
        help="Offline advisory mirror JSON to join against the SBOM",
    )
    parser.add_argument(
        "--sbom-out",
        default="",
        help="Write CycloneDX and SPDX JSON into this directory",
    )


def _run_audit_steps(intel: dict, args: argparse.Namespace) -> None:
    """
    Execute all audit phases sequentially.

    Parameters
    ----------
    intel : dict
        Intelligence data.
    args : argparse.Namespace
        Parsed CLI arguments.

    Returns
    -------
    None
    """
    _audit_network(intel, args.target_ip, args.router_ip)
    _audit_vendor_regulatory(intel, intel["target"]["mac"])
    _maybe_fcc_step(intel, args)
    _port_step(intel, args)
    _audit_bluetooth(intel, args.ble, args.ble_timeout)
    _audit_pcap(intel, args.pcap, args.target_ip)
    _export_reports(intel, args.json, args.report)


def _maybe_fcc_step(intel: dict, args: argparse.Namespace) -> None:
    """
    Resolve the requested FCC ID, if any.

    Parameters
    ----------
    intel : dict
        Intelligence data.
    args : argparse.Namespace
        Parsed CLI arguments.

    Returns
    -------
    None
    """
    if not args.fcc_id:
        return
    intel["fcc_id_override"] = args.fcc_id
    _maybe_fcc_resolve(intel, intel["target"]["name"], args.fcc_id)


def _port_step(intel: dict, args: argparse.Namespace) -> None:
    """
    Scan ports and assess vulnerabilities unless disabled.

    Parameters
    ----------
    intel : dict
        Intelligence data.
    args : argparse.Namespace
        Parsed CLI arguments.

    Returns
    -------
    None
    """
    if args.no_scan_ports:
        return
    intel["open_ports"] = _scan_host_ports(args.target_ip, args.ports)
    if intel["open_ports"]:
        _found(f"Open ports: {[p['port'] for p in intel['open_ports']]}")
    _assess_vulnerabilities(intel)


def _run_all_audit(args: argparse.Namespace) -> int:
    """
    Execute the network-wide (--all) radio spectrum audit.

    Parameters
    ----------
    args : argparse.Namespace
        Parsed CLI arguments.

    Returns
    -------
    int
        Zero on successful wide audit completion.
    """
    spectrum, ble_audits = _scan_radio_spectrum(args.ble_timeout)
    flows_all = _fetch_router_flows_all(args.router_ip)
    _merge_router(spectrum, args.router_ip)
    _maybe_inventory(spectrum, flows_all, args)
    audits = _all_audits(spectrum, ble_audits, flows_all, args)
    _maybe_fcc_all(audits, args)
    _write_giant(audits, spectrum, args)
    return 0


def _add_ap(spectrum: dict, net: dict, known: set) -> None:
    """
    Merge one router-provided AP into the spectrum when new.

    Parameters
    ----------
    spectrum : dict
        Spectrum inventory.
    net : dict
        Router AP record.
    known : set
        Known AP keys.

    Returns
    -------
    None
    """
    key = net.get("bssid") or (net.get("ssid"), net.get("channel"))
    if key not in known:
        spectrum["wifi_networks"].append(net)
        known.add(key)


def _merge_aps(spectrum: dict, aps: list) -> None:
    """
    Merge a router-provided AP scan into the spectrum.

    Parameters
    ----------
    spectrum : dict
        Spectrum inventory.
    aps : list
        Router AP records.

    Returns
    -------
    None
    """
    if not aps:
        return
    _found(f"Router provided unredacted AP scan: {len(aps)} networks")
    known = {
        n.get("bssid") or (n.get("ssid"), n.get("channel"))
        for n in spectrum.get("wifi_networks", [])
    }
    for net in aps:
        _add_ap(spectrum, net, known)
    spectrum["router_ap_scan"] = len(aps)
    spectrum["wifi_source"] = "mac_system_profiler + router agent"


def _add_client(spectrum: dict, client: dict, existing: set) -> None:
    """
    Merge one router-provided client into the local host list when new.

    Parameters
    ----------
    spectrum : dict
        Spectrum inventory.
    client : dict
        Router client record.
    existing : set
        Known (ip, mac) pairs.

    Returns
    -------
    None
    """
    ip = client.get("ip") or client.get("address")
    mac = client.get("mac") or client.get("client_mac")
    if (ip, mac) in existing or not (ip and mac):
        return
    spectrum["local_hosts"].append({
        "ip": ip,
        "mac": mac,
        "name": client.get("hostname") or client.get("name", ""),
        "source": "router",
        "lease": bool(client.get("leases") or client.get("lease")),
    })
    existing.add((ip, mac))


def _merge_clients(spectrum: dict, clients: list) -> None:
    """
    Merge a router-provided client table into the local host list.

    Parameters
    ----------
    spectrum : dict
        Spectrum inventory.
    clients : list
        Router client records.

    Returns
    -------
    None
    """
    if not clients:
        return
    _found(f"Router provided client table: {len(clients)} hosts")
    existing = {
        (h.get("ip"), h.get("mac"))
        for h in spectrum.get("local_hosts", [])
    }
    for client in clients:
        _add_client(spectrum, client, existing)
    spectrum["router_client_count"] = len(clients)


def _merge_router(spectrum: dict, router_ip: str) -> None:
    """
    Merge router-provided APs and clients into the spectrum.

    Parameters
    ----------
    spectrum : dict
        Spectrum inventory.
    router_ip : str
        Gateway address.

    Returns
    -------
    None
    """
    aps, clients = _fetch_router_aux(router_ip)
    _merge_aps(spectrum, aps)
    _merge_clients(spectrum, clients)


def _maybe_inventory(spectrum: dict, flows_all: list, args) -> None:
    """
    Write the discovery inventory when an output path is set.

    Parameters
    ----------
    spectrum : dict
        Spectrum inventory.
    flows_all : list
        Router flow records.
    args : argparse.Namespace
        Parsed CLI arguments.

    Returns
    -------
    None
    """
    if not args.info:
        return
    inventory = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "mode": "network-wide (--all)",
        "router_flows": len(flows_all),
        **spectrum,
    }
    _write_file(args.info, json.dumps(inventory, indent=2))
    _found(f"Saved discovery inventory: {args.info}")


def _all_audits(
    spectrum: dict, ble_audits: list, flows_all: list, args
) -> list:
    """
    Audit every discovered Wi-Fi network, host, and peer.

    Parameters
    ----------
    spectrum : dict
        Spectrum inventory.
    ble_audits : list
        BLE audit records.
    flows_all : list
        Router flow records.
    args : argparse.Namespace
        Parsed CLI arguments.

    Returns
    -------
    list
        Per-device audit records.
    """
    ports = "" if args.no_scan_ports else args.ports
    audits = []
    audits += [
        _audit_wifi_network(n) for n in spectrum.get("wifi_networks", [])
    ]
    audits += [
        _audit_host_intel(h, flows_all, ports)
        for h in spectrum.get("local_hosts", [])
    ]
    audits += [
        _audit_bt_classic_peer(p) for p in spectrum.get("bt_classic", [])
    ]
    audits += ble_audits
    return audits


def _maybe_fcc_all(audits: list, args) -> None:
    """
    Resolve the explicit FCC ID across every audit record.

    Parameters
    ----------
    audits : list
        Audit records.
    args : argparse.Namespace
        Parsed CLI arguments.

    Returns
    -------
    None
    """
    if not args.fcc_id:
        return
    for audit in audits:
        if not audit.get("fcc_id_override"):
            audit["fcc_id_override"] = args.fcc_id
            _maybe_fcc_resolve(
                audit, audit["target"].get("name", ""), args.fcc_id
            )


def _write_giant(audits: list, spectrum: dict, args) -> None:
    """
    Write the combined network-wide JSON and Markdown report.

    Parameters
    ----------
    audits : list
        Audit records.
    spectrum : dict
        Spectrum inventory.
    args : argparse.Namespace
        Parsed CLI arguments.

    Returns
    -------
    None
    """
    giant = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "mode": "network-wide (--all)",
        "spectrum": spectrum,
        "device_audits": audits,
    }
    if args.json:
        _write_file(args.json, json.dumps(giant, indent=2))
    if args.report:
        _write_file(args.report, _format_giant_markdown(giant))
    _log(
        "ALL",
        "Wide audit complete: {} addresses audited -> {}, {}".format(
            len(audits), args.json, args.report
        ),
    )


def _read_bytes(path: str) -> bytes:
    """
    Read a file into memory, returning an empty blob on failure.

    Parameters
    ----------
    path : str
        File path.

    Returns
    -------
    bytes
        File contents.
    """
    try:
        with open(path, "rb") as handle:
            return handle.read()
    except OSError:
        return b""


def _write_sbom(sbom: dict, outdir: str) -> None:
    """
    Write CycloneDX and SPDX documents into a directory.

    Parameters
    ----------
    sbom : dict
        Discovered SBOM.
    outdir : str
        Destination directory.

    Returns
    -------
    None
    """
    os.makedirs(outdir, exist_ok=True)
    _write_file(
        os.path.join(outdir, "sbom.cdx.json"),
        json.dumps(to_cyclonedx(sbom), indent=2),
    )
    _write_file(
        os.path.join(outdir, "sbom.spdx.json"),
        json.dumps(to_spdx(sbom), indent=2),
    )


def _run_firmware_audit(args: argparse.Namespace) -> int:
    """
    Run the offline firmware and static analysis pipeline.

    Parameters
    ----------
    args : argparse.Namespace
        Parsed CLI arguments.

    Returns
    -------
    int
        Zero on successful completion.
    """
    _log("FIRMWARE", "Offline firmware/static analysis: " + args.firmware)
    data = _read_bytes(args.firmware)
    doc = _firmware_doc(args, data)
    _maybe_extract(doc, args)
    _maybe_carve(doc, args, data)
    _run_static_passes(doc, args)
    _export_firmware_reports(doc, args.json, args.report)
    return 0


def _firmware_doc(args: argparse.Namespace, data: bytes) -> dict:
    """
    Build the base firmware analysis document.

    Parameters
    ----------
    args : argparse.Namespace
        Parsed CLI arguments.
    data : bytes
        Firmware bytes.

    Returns
    -------
    dict
        Analysis document.
    """
    return {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "path": args.firmware,
        "identification": scan_file(args.firmware, args.broad),
        "entropy": entropy_pass(data),
        "upx": detect_upx(data),
    }


def _maybe_extract(doc: dict, args: argparse.Namespace) -> None:
    """
    Recursively extract the firmware when a directory is set.

    Parameters
    ----------
    doc : dict
        Analysis document.
    args : argparse.Namespace
        Parsed CLI arguments.

    Returns
    -------
    None
    """
    if args.extract_dir:
        doc["extraction"] = extract_tree(args.firmware, args.extract_dir)


def _maybe_carve(doc: dict, args: argparse.Namespace, data: bytes) -> None:
    """
    Carve identified regions when a directory is set.

    Parameters
    ----------
    doc : dict
        Analysis document.
    args : argparse.Namespace
        Parsed CLI arguments.
    data : bytes
        Firmware bytes.

    Returns
    -------
    None
    """
    if args.carve_dir:
        doc["carving"] = carve_findings(
            data, doc["identification"]["findings"], args.carve_dir
        )


def _run_static_passes(doc: dict, args: argparse.Namespace) -> None:
    """
    Run secrets, SBOM, licenses, and CVE passes over the analysis target.

    Parameters
    ----------
    doc : dict
        Firmware analysis document (mutated in place).
    args : argparse.Namespace
        Parsed CLI arguments.

    Returns
    -------
    None
    """
    target = args.extract_dir or args.firmware
    doc["secrets"] = scan_secrets(target)
    doc["sbom"] = build_sbom(target)
    doc["licenses"] = scan_licenses(target)
    _maybe_cve(doc, args)
    _maybe_sbom(doc, args)
    _announce_static(doc)


def _maybe_cve(doc: dict, args: argparse.Namespace) -> None:
    """
    Join the SBOM against a local advisory mirror when supplied.

    Parameters
    ----------
    doc : dict
        Analysis document.
    args : argparse.Namespace
        Parsed CLI arguments.

    Returns
    -------
    None
    """
    if args.cve_mirror:
        doc["cve"] = join_cves(
            doc["sbom"]["components"], load_mirror(args.cve_mirror)
        )


def _maybe_sbom(doc: dict, args: argparse.Namespace) -> None:
    """
    Write CycloneDX and SPDX documents when a directory is set.

    Parameters
    ----------
    doc : dict
        Analysis document.
    args : argparse.Namespace
        Parsed CLI arguments.

    Returns
    -------
    None
    """
    if args.sbom_out:
        _write_sbom(doc["sbom"], args.sbom_out)


def _announce_static(doc: dict) -> None:
    """
    Log a summary of the static-analysis passes.

    Parameters
    ----------
    doc : dict
        Analysis document.

    Returns
    -------
    None
    """
    _found(
        "Static: {} secrets, {} components, {} licenses".format(
            doc["secrets"]["count"],
            doc["sbom"]["count"],
            len(doc["licenses"].get("findings", [])),
        )
    )


def main() -> int:
    """
    Execute IoT blue team intelligence gathering pipeline.

    Parameters
    ----------
    None

    Returns
    -------
    int
        Zero on successful audit completion.
    """
    args = _build_arg_parser().parse_args()
    if args.firmware:
        return _run_firmware_audit(args)
    if args.all:
        _log("MAIN", "Network-wide radio spectrum audit requested (--all)")
        return _run_all_audit(args)
    return _run_single(args)


def _run_single(args: argparse.Namespace) -> int:
    """
    Run the single-host forensic audit.

    Parameters
    ----------
    args : argparse.Namespace
        Parsed CLI arguments.

    Returns
    -------
    int
        Zero on success.
    """
    _log("MAIN", "Starting automated IoT intelligence gathering")
    intel = _init_intel(args.target_ip, args.target_mac)
    _run_audit_steps(intel, args)
    _log("MAIN", "Forensic audit complete")
    return 0


if __name__ == "__main__":
    sys.exit(main())
