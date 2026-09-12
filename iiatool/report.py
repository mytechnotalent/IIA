"""Markdown and JSON report export functions."""

import json

from .utils import _write_file


def _build_risk_findings() -> list:
    """
    Generate baseline blue team architectural risks.

    Parameters
    ----------
    None

    Returns
    -------
    list
        Synthesized risk dictionary items.
    """
    v1 = "Cloud-Tethered Microcontroller Architecture"
    d1 = "Device uses outbound TLS tunnel (31314) with zero inbound ports."
    v2 = "Continuous Over-The-Air BLE Advertising"
    d2 = "Device broadcasts BLE beaconing continuously after association."
    return [
        {"severity": "INFORMATIONAL", "vuln": v1, "detail": d1},
        {"severity": "LOW", "vuln": v2, "detail": d2},
    ]


def _target_header_lines(tgt: dict, ts: str) -> list:
    """
    Format target header lines.

    Parameters
    ----------
    tgt : dict
        Target info dictionary.
    ts : str
        Timestamp string.

    Returns
    -------
    list
        Header strings.
    """
    t_str = f"**Target:** `{tgt['ip']}` (`{tgt['mac']}`)  "
    return [
        "# Blue Team IoT Intelligence and Forensic Audit Report",
        f"**Timestamp:** `{ts}`  ",
        t_str,
    ]


def _platform_header_lines(reg: dict) -> list:
    """
    Format platform header lines.

    Parameters
    ----------
    reg : dict
        Regulatory dictionary.

    Returns
    -------
    list
        Platform strings.
    """
    mcu = f"**Host MCU:** `{reg.get('mcu', 'N/A')}`  "
    rad = f"**Radio:** `{reg.get('radio', 'N/A')}`  "
    return [f"**Platform:** `{reg.get('platform', 'N/A')}`  ", mcu, rad]


def _summary_headers(intel: dict) -> list:
    """
    Construct top metadata rows.

    Parameters
    ----------
    intel : dict
        Intelligence container.

    Returns
    -------
    list
        Header lines.
    """
    h1 = _target_header_lines(intel["target"], intel["timestamp"])
    h2 = _platform_header_lines(intel.get("regulatory", {}))
    return h1 + h2


def _summary_bullets(intel: dict) -> list:
    """
    Construct summary bullet points.

    Parameters
    ----------
    intel : dict
        Intelligence container.

    Returns
    -------
    list
        Executive bullet points.
    """
    vendor = intel.get("vendor_oui", {}).get("company", "N/A")
    ports = intel.get("open_ports", [])
    return [
        "---",
        "## Executive Summary",
        f"- Vendor OUI: {vendor}",
        f"- Cloud C2: {_c2_summary(intel)}",
        f"- Open ports: {[p['port'] for p in ports] or 'none found'}",
        "---",
        "## Risk Findings",
    ]


def _c2_summary(intel: dict) -> str:
    """
    Summarize the first cloud C2 endpoint.

    Parameters
    ----------
    intel : dict
        Intelligence container.

    Returns
    -------
    str
        Endpoint summary or N/A.
    """
    cloud = intel.get("cloud_c2", [])
    if not cloud:
        return "N/A"
    first = cloud[0]
    return f"{first.get('ip', 'N/A')} ({first.get('org', 'N/A')})"


def _build_summary_lines(intel: dict) -> list:
    """
    Construct summary lines for Markdown export.

    Parameters
    ----------
    intel : dict
        Intelligence container.

    Returns
    -------
    list
        Formatted markdown lines.
    """
    return _summary_headers(intel) + _summary_bullets(intel)


def _format_markdown_report(intel: dict) -> str:
    """
    Construct full-depth Markdown intelligence artifact.

    Parameters
    ----------
    intel : dict
        Complete intelligence dictionary.

    Returns
    -------
    str
        Markdown document content.
    """
    lines = _build_summary_lines(intel)
    _md_risks(lines, intel)
    _md_ports(lines, intel)
    _md_vulns(lines, intel)
    _md_cloud(lines, intel)
    _md_pcap(lines, intel)
    _md_ble(lines, intel)
    return "\n".join(lines)


def _md_risks(lines: list, intel: dict) -> None:
    """
    Append risk-assessment lines.

    Parameters
    ----------
    lines : list
        Markdown lines.
    intel : dict
        Intelligence container.

    Returns
    -------
    None
    """
    for risk in intel["blue_team_risk_assessment"]:
        lines.append(f"### [{risk['severity']}] {risk['vuln']}")
        lines.append(f"{risk['detail']}\n")


def _port_row(port: dict) -> str:
    """
    Render one open-port row.

    Parameters
    ----------
    port : dict
        Open-port record.

    Returns
    -------
    str
        Markdown table row.
    """
    banner = port.get("banner", "")
    return f"| {port['port']} | {port.get('service', '?')} | {banner} |"


def _md_ports(lines: list, intel: dict) -> None:
    """
    Append the open-ports table.

    Parameters
    ----------
    lines : list
        Markdown lines.
    intel : dict
        Intelligence container.

    Returns
    -------
    None
    """
    open_ports = intel.get("open_ports", [])
    if not open_ports:
        return
    lines += ["## Open Ports", "| Port | Service | Banner |", "|---|---|---|"]
    for port in open_ports:
        lines.append(_port_row(port))
    lines.append("")


def _vuln_heading(port: dict) -> str:
    """
    Render a port vulnerability heading.

    Parameters
    ----------
    port : dict
        Port assessment.

    Returns
    -------
    str
        Markdown heading.
    """
    severity = port["severity"]
    label = "CHECK" if severity == "N/A" else severity
    return f"### [{label}] Port {port['port']} ({port['service']})"


def _cve_line(cve: dict) -> str:
    """
    Render one CVE list item.

    Parameters
    ----------
    cve : dict
        CVE record.

    Returns
    -------
    str
        Markdown list item.
    """
    score = cve.get("score")
    score_txt = f" (CVSS {score})" if score is not None else ""
    return (
        f"- **{cve['id']}**{score_txt}: {cve['summary']} "
        f"[{cve.get('source', '')}]"
    )


def _md_vuln_port(lines: list, port: dict) -> None:
    """
    Append one port's vulnerability detail.

    Parameters
    ----------
    lines : list
        Markdown lines.
    port : dict
        Port assessment.

    Returns
    -------
    None
    """
    lines.append(_vuln_heading(port))
    for risk in port.get("risks", []):
        lines.append(f"- Risk: {risk}")
    if port.get("banner"):
        lines.append(f"- Banner: `{port['banner']}`")
    for cve in port.get("cves", []):
        lines.append(_cve_line(cve))
    lines.append("")


def _md_vulns(lines: list, intel: dict) -> None:
    """
    Append the vulnerability assessment section.

    Parameters
    ----------
    lines : list
        Markdown lines.
    intel : dict
        Intelligence container.

    Returns
    -------
    None
    """
    vulns = intel.get("vulnerabilities", {})
    vuln_ports = vulns.get("ports", [])
    if not vuln_ports:
        return
    lines.append("## Vulnerability Assessment")
    lines.append(f"_Sources: {', '.join(vulns.get('sources', []))}_")
    for port in vuln_ports:
        _md_vuln_port(lines, port)


def _cloud_row(cloud: dict) -> str:
    """
    Render one cloud C2 table row.

    Parameters
    ----------
    cloud : dict
        Cloud endpoint record.

    Returns
    -------
    str
        Markdown table row.
    """
    port_str = ",".join(str(x) for x in cloud.get("ports", []))
    return (
        f"| {cloud.get('ip', '')} | {cloud.get('org', '')} | "
        f"{cloud.get('city', '')}/{cloud.get('region', '')} | {port_str} | "
        f"{cloud.get('hostname', '')} |"
    )


def _md_cloud(lines: list, intel: dict) -> None:
    """
    Append the cloud C2 endpoints table.

    Parameters
    ----------
    lines : list
        Markdown lines.
    intel : dict
        Intelligence container.

    Returns
    -------
    None
    """
    cloud = intel.get("cloud_c2", [])
    if not cloud:
        return
    lines += [
        "## Cloud C2 Endpoints",
        "| IP | ASN / Org | City / Region | Ports | Hostname |",
        "|---|---|---|---|---|",
    ]
    for endpoint in cloud:
        lines.append(_cloud_row(endpoint))
    lines.append("")


def _md_list(lines: list, title: str, items: list) -> None:
    """
    Append a titled bullet list.

    Parameters
    ----------
    lines : list
        Markdown lines.
    title : str
        Section title.
    items : list
        List items.

    Returns
    -------
    None
    """
    if not items:
        return
    lines.append(title)
    for item in items:
        lines.append(f"- `{item}`")
    lines.append("")


def _md_pcap(lines: list, intel: dict) -> None:
    """
    Append the pcap domains and MQTT sections.

    Parameters
    ----------
    lines : list
        Markdown lines.
    intel : dict
        Intelligence container.

    Returns
    -------
    None
    """
    pcap = intel.get("pcap_forensics", {})
    _md_list(
        lines, "## Observed Domains (DNS / TLS SNI / HTTP)",
        pcap.get("observed_domains", []),
    )
    _md_list(lines, "## MQTT Topics", pcap.get("mqtt_topics", []))


def _md_adv(lines: list, adv: dict) -> None:
    """
    Append the BLE advertisement section.

    Parameters
    ----------
    lines : list
        Markdown lines.
    adv : dict
        Advertisement data.

    Returns
    -------
    None
    """
    lines.append("## BLE Advertisement")
    for entry in adv.get("manufacturer_data", []) or []:
        lines.append(
            f"- **Manufacturer data:** {entry.get('company')} "
            f"({entry.get('company_id')}): `{entry.get('hex')}`"
        )
    for key in ("service_uuids", "tx_power", "appearance", "connectable"):
        if adv.get(key) is not None:
            lines.append(f"- **{key}:** {adv.get(key)}")
    lines.append("")


def _md_device_info(lines: list, info: dict) -> None:
    """
    Append the BLE device-info section.

    Parameters
    ----------
    lines : list
        Markdown lines.
    info : dict
        Device information.

    Returns
    -------
    None
    """
    lines.append("## BLE Device Info")
    for key, value in info.items():
        if value:
            lines.append(f"- **{key}:** `{value}`")
    lines.append("")


def _md_ble(lines: list, intel: dict) -> None:
    """
    Append the BLE advertisement and device-info sections.

    Parameters
    ----------
    lines : list
        Markdown lines.
    intel : dict
        Intelligence container.

    Returns
    -------
    None
    """
    ble = intel.get("ble_telemetry", {})
    adv = ble.get("adv", {})
    if adv:
        _md_adv(lines, adv)
    info = ble.get("device_info", {})
    if info and any(info.values()):
        _md_device_info(lines, info)


def _export_reports(intel: dict, json_path: str, md_path: str) -> None:
    """
    Write JSON and Markdown output files to disk.

    Parameters
    ----------
    intel : dict
        Intelligence data.
    json_path : str
        Target JSON output path.
    md_path : str
        Target Markdown report path.

    Returns
    -------
    None
    """
    intel["blue_team_risk_assessment"].extend(_build_risk_findings())
    if json_path:
        _write_file(json_path, json.dumps(intel, indent=2))
    if md_path:
        _write_file(md_path, _format_markdown_report(intel))


def _format_giant_markdown(giant: dict) -> str:
    """
    Render the network-wide (--all) report as Markdown.

    Parameters
    ----------
    giant : dict
        Aggregated network-wide report dictionary.

    Returns
    -------
    str
        Markdown document content.
    """
    spectrum = giant.get("spectrum", {})
    audits = giant.get("device_audits", [])
    lines = _giant_header(giant, spectrum, audits)
    _giant_wifi(lines, spectrum)
    lines.append("---")
    for index, audit in enumerate(audits, 1):
        _giant_audit(lines, index, audit)
    return "\n".join(lines)


def _giant_header(giant: dict, spectrum: dict, audits: list) -> list:
    """
    Build the network-wide report header and inventory.

    Parameters
    ----------
    giant : dict
        Aggregated report.
    spectrum : dict
        Spectrum inventory.
    audits : list
        Audit records.

    Returns
    -------
    list
        Markdown lines.
    """
    lines = [
        "# Blue Team IoT Network-Wide Intelligence Report",
        f"**Timestamp:** `{giant.get('timestamp', '')}`  ",
        "---",
        "## Visible Radio Spectrum Inventory",
        f"- Wi-Fi networks: **{len(spectrum.get('wifi_networks', []))}**",
        f"- Bluetooth LE devices: **{len(spectrum.get('ble_devices', []))}**",
        f"- Bluetooth Classic peers: "
        f"**{len(spectrum.get('bt_classic', []))}**",
        f"- mDNS/Bonjour service types: "
        f"**{len(spectrum.get('mdns_services', []))}**",
        f"- Local hosts (ARP): **{len(spectrum.get('local_hosts', []))}**",
        f"- Audited addresses: **{len(audits)}**",
        "---",
        "## Spectrum Observability Notes",
    ]
    for note in spectrum.get("observability_notes", []):
        lines.append(f"- {note}")
    lines.append("")
    return lines


def _wifi_row(net: dict) -> str:
    """
    Render one Wi-Fi table row.

    Parameters
    ----------
    net : dict
        Wi-Fi network record.

    Returns
    -------
    str
        Markdown table row.
    """
    return (
        f"| {net.get('ssid', '')} | {net.get('bssid', '')} | "
        f"{net.get('band', '')} | {net.get('channel', '')} | "
        f"{net.get('rssi', '')} | {net.get('security', '')} |"
    )


def _giant_wifi(lines: list, spectrum: dict) -> None:
    """
    Append the Wi-Fi networks table.

    Parameters
    ----------
    lines : list
        Markdown lines.
    spectrum : dict
        Spectrum inventory.

    Returns
    -------
    None
    """
    wifi = spectrum.get("wifi_networks", [])
    if not wifi:
        return
    lines += [
        "## Wi-Fi Networks (2.4/5 GHz)",
        "| SSID | BSSID | Band | Ch | RSSI | Security |",
        "|---|---|---|---|---|---|",
    ]
    for net in wifi:
        lines.append(_wifi_row(net))
    lines.append("")


def _audit_name(target: dict, index: int) -> str:
    """
    Derive a display name for an audit record.

    Parameters
    ----------
    target : dict
        Audit target.
    index : int
        Record index.

    Returns
    -------
    str
        Display name.
    """
    return (
        target.get("name")
        or target.get("ip")
        or target.get("mac")
        or f"record {index}"
    )


def _audit_vendor(lines: list, vendor: dict) -> None:
    """
    Append vendor identity lines.

    Parameters
    ----------
    lines : list
        Markdown lines.
    vendor : dict
        Vendor record.

    Returns
    -------
    None
    """
    source = f" ({vendor.get('source', '')})" if vendor.get("source") else ""
    lines.append(
        f"- **Vendor:** {vendor.get('company', 'N/A')}{source}  "
    )
    if vendor.get("model_claimed"):
        lines.append(f"- **Claimed model:** `{vendor['model_claimed']}`  ")
    if vendor.get("mac_flags"):
        lines.append(f"- **MAC flags:** {vendor['mac_flags']}  ")


def _audit_regulatory(lines: list, reg: dict) -> None:
    """
    Append FCC and platform lines.

    Parameters
    ----------
    lines : list
        Markdown lines.
    reg : dict
        Regulatory record.

    Returns
    -------
    None
    """
    grant = reg.get("fcc_grant", {})
    if grant:
        lines.append(
            f"- **FCC ID:** `{grant.get('grant', '')}` "
            f"({grant.get('url', '')})  "
        )
    if reg.get("platform"):
        lines.append(
            f"- **Platform:** `{reg.get('platform')}` / "
            f"MCU `{reg.get('mcu', 'N/A')}` / "
            f"Radio `{reg.get('radio', 'N/A')}`  "
        )


def _audit_wifi_bt(lines: list, audit: dict) -> None:
    """
    Append Wi-Fi and Bluetooth Classic lines.

    Parameters
    ----------
    lines : list
        Markdown lines.
    audit : dict
        Audit record.

    Returns
    -------
    None
    """
    wifi = audit.get("wifi", {})
    if wifi.get("channel"):
        lines.append(
            f"- **Wi-Fi:** {wifi.get('band', '')} ch "
            f"{wifi.get('channel', '')} RSSI {wifi.get('rssi', '')}dBm "
            f"security {wifi.get('security', '')}  "
        )
    bt = audit.get("bluetooth_classic", {})
    if bt:
        lines.append(
            f"- **BT Classic:** {bt.get('major_type', '')} / "
            f"{bt.get('minor_type', '')}  "
        )


def _giant_audit_head(lines: list, index: int, audit: dict) -> None:
    """
    Append the header block for one audit record.

    Parameters
    ----------
    lines : list
        Markdown lines.
    index : int
        Record index.
    audit : dict
        Audit record.

    Returns
    -------
    None
    """
    target = audit.get("target", {})
    device_type = audit.get("device_type", "?").upper()
    lines.append(
        f"## {index}. {device_type} — {_audit_name(target, index)}"
    )
    lines.append(
        f"- **Address:** `{target.get('ip', '')}` "
        f"(`{target.get('mac', '')}`)  "
    )
    _audit_vendor(lines, audit.get("vendor_oui", {}))
    _audit_regulatory(lines, audit.get("regulatory", {}))
    _audit_wifi_bt(lines, audit)
    lines.append(
        f"- **Gateway flows:** {len(audit.get('network_flows', []))}  "
    )


def _device_parts(info: dict) -> list:
    """
    Build BLE device-info fragments.

    Parameters
    ----------
    info : dict
        Device information.

    Returns
    -------
    list
        Fragment strings.
    """
    parts = [
        f"model `{info.get('model')}`",
        f"firmware `{info.get('firmware')}`",
        f"id `{info.get('dev_id')}`",
    ]
    if info.get("manufacturer"):
        parts.append(f"mfr `{info.get('manufacturer')}`")
    if info.get("serial"):
        parts.append(f"serial `{info.get('dev_id')}`")
    return parts


def _md_adv_manufacturer(lines: list, entries: list) -> None:
    """
    Append advertisement manufacturer lines.

    Parameters
    ----------
    lines : list
        Markdown lines.
    entries : list
        Manufacturer-data records.

    Returns
    -------
    None
    """
    lines.append("- **BLE adv manufacturer:**")
    for entry in entries:
        lines.append(
            f"  - {entry.get('company')} "
            f"({entry.get('company_id')}): `{entry.get('hex')}`"
        )


def _giant_audit_ble(lines: list, telemetry: dict) -> None:
    """
    Append BLE device-info and advertisement lines.

    Parameters
    ----------
    lines : list
        Markdown lines.
    telemetry : dict
        BLE telemetry.

    Returns
    -------
    None
    """
    info = telemetry.get("device_info", {})
    if info and any(info.values()):
        lines.append(
            "- **BLE device info:** " + ", ".join(_device_parts(info)) + "  "
        )
    adv = telemetry.get("adv", {})
    if adv.get("manufacturer_data"):
        _md_adv_manufacturer(lines, adv["manufacturer_data"])
    if adv.get("service_uuids"):
        lines.append(
            "- **BLE adv services:** "
            + ", ".join(str(u) for u in adv["service_uuids"])
            + "  "
        )


def _giant_audit_ports(lines: list, audit: dict) -> None:
    """
    Append open-port lines for one audit.

    Parameters
    ----------
    lines : list
        Markdown lines.
    audit : dict
        Audit record.

    Returns
    -------
    None
    """
    open_ports = audit.get("open_ports", [])
    if not open_ports:
        return
    lines.append("- **Open ports:**")
    for port in open_ports:
        banner = port.get("banner", "")
        lines.append(
            f"  - `{port['port']}` {port.get('service', '?')}"
            + (f" — `{banner}`" if banner else "")
        )


def _giant_cve_line(cve: dict) -> str:
    """
    Render one per-port CVE line.

    Parameters
    ----------
    cve : dict
        CVE record.

    Returns
    -------
    str
        Markdown line.
    """
    score = cve.get("score")
    score_txt = f" CVSS {score}" if score is not None else ""
    return f"    - {cve['id']}{score_txt}: {cve['summary'][:160]}"


def _giant_vuln_port(lines: list, port: dict) -> None:
    """
    Append one port's vulnerability lines.

    Parameters
    ----------
    lines : list
        Markdown lines.
    port : dict
        Port assessment.

    Returns
    -------
    None
    """
    top = port.get("cves", [])[0] if port.get("cves") else None
    if port.get("top_score") is not None:
        verdict = f"top CVSS {port.get('top_score')} ({port.get('severity')})"
    else:
        verdict = f"no quantified CVEs ({port.get('severity')})"
    lines.append(
        f"  - `{port['port']}` {port['service']}: {verdict}"
        + (f" — **{top['id']}**" if top else "")
    )
    for cve in port.get("cves", [])[:4]:
        lines.append(_giant_cve_line(cve))


def _giant_finding_line(finding: dict) -> str:
    """
    Render one high-severity finding line.

    Parameters
    ----------
    finding : dict
        Finding record.

    Returns
    -------
    str
        Markdown line.
    """
    return (
        f"- **{finding['severity']} finding:** {finding['service']} "
        f"({finding['port']}) exposed — "
        f"{finding.get('top_cve') or 'vulnerable family'}  "
    )


def _giant_audit_vulns(lines: list, audit: dict) -> None:
    """
    Append vulnerability lines for one audit.

    Parameters
    ----------
    lines : list
        Markdown lines.
    audit : dict
        Audit record.

    Returns
    -------
    None
    """
    vuln_ports = audit.get("vulnerabilities", {}).get("ports", [])
    if vuln_ports:
        lines.append("- **Vulnerability assessment:**")
        for port in vuln_ports:
            _giant_vuln_port(lines, port)
    for finding in audit.get("vulnerabilities", {}).get("findings", []):
        lines.append(_giant_finding_line(finding))


def _giant_audit_c2(lines: list, audit: dict) -> None:
    """
    Append cloud C2 endpoint lines for one audit.

    Parameters
    ----------
    lines : list
        Markdown lines.
    audit : dict
        Audit record.

    Returns
    -------
    None
    """
    endpoints = audit.get("cloud_c2", [])
    if not endpoints:
        return
    lines.append("- **C2 endpoints:**")
    for endpoint in endpoints:
        port_str = ",".join(str(x) for x in endpoint.get("ports", []))
        lines.append(
            f"  - `{endpoint.get('ip', '')}` ports {port_str} — "
            f"{endpoint.get('org', '')} "
            f"{endpoint.get('city', '')}/{endpoint.get('country', '')}"
        )


def _giant_audit_domains(lines: list, audit: dict) -> None:
    """
    Append observed-domain lines for one audit.

    Parameters
    ----------
    lines : list
        Markdown lines.
    audit : dict
        Audit record.

    Returns
    -------
    None
    """
    domains = audit.get("pcap_forensics", {}).get("observed_domains", [])
    if not domains:
        return
    lines.append(
        "- **Domains:** "
        + ", ".join(f"`{d}`" for d in domains[:15])
        + (" ..." if len(domains) > 15 else "")
    )


def _giant_audit_risks(lines: list, audit: dict) -> None:
    """
    Append risk-assessment lines for one audit.

    Parameters
    ----------
    lines : list
        Markdown lines.
    audit : dict
        Audit record.

    Returns
    -------
    None
    """
    for risk in audit.get("blue_team_risk_assessment", []):
        lines.append(
            f"- **Risk [{risk['severity']}]** "
            f"{risk['vuln']}: {risk['detail']}  "
        )


def _giant_audit(lines: list, index: int, audit: dict) -> None:
    """
    Append the full block for one network-wide audit record.

    Parameters
    ----------
    lines : list
        Markdown lines.
    index : int
        Record index.
    audit : dict
        Audit record.

    Returns
    -------
    None
    """
    _giant_audit_head(lines, index, audit)
    _giant_audit_ble(lines, audit.get("ble_telemetry", {}))
    _giant_audit_ports(lines, audit)
    _giant_audit_vulns(lines, audit)
    _giant_audit_c2(lines, audit)
    _giant_audit_domains(lines, audit)
    _giant_audit_risks(lines, audit)
    lines.append("")


def _format_firmware_markdown(doc: dict) -> str:
    """
    Render a firmware/static analysis document as Markdown.

    Parameters
    ----------
    doc : dict
        Firmware analysis document.

    Returns
    -------
    str
        Markdown document content.
    """
    lines = [
        "# Blue Team Firmware and Static Analysis Report",
        f"**Timestamp:** `{doc.get('timestamp', '')}`  ",
        f"**Target:** `{doc.get('path', '')}`  ",
        "---",
    ]
    for key, builder in _FIRMWARE_SECTIONS:
        lines.extend(builder(doc.get(key, {})))
    return "\n".join(lines)


def _firmware_identification_lines(ident: dict) -> list:
    """
    Format the identification findings section.

    Parameters
    ----------
    ident : dict
        Identification result.

    Returns
    -------
    list
        Markdown lines.
    """
    if not ident:
        return []
    primary = ident.get("primary") or {}
    lines = [
        "## Identification",
        f"- Size: **{ident.get('size', 0)}** bytes",
        f"- Primary type: **{primary.get('type', 'unknown')}** "
        f"(confidence {primary.get('confidence', 0)})",
        "",
        "| Offset | Type | Confidence | Source |",
        "|---|---|---|---|",
    ]
    for item in ident.get("findings", [])[:80]:
        lines.append(
            "| 0x{:x} | {} | {} | {} |".format(
                item.get("offset", 0),
                item.get("type", ""),
                item.get("confidence", 0),
                item.get("source", ""),
            )
        )
    lines.append("")
    return lines


def _firmware_entropy_lines(ent: dict) -> list:
    """
    Format the entropy section.

    Parameters
    ----------
    ent : dict
        Entropy result.

    Returns
    -------
    list
        Markdown lines.
    """
    if not ent:
        return []
    lines = [
        "## Entropy",
        f"- Overall entropy: **{ent.get('overall_entropy', 0)}** bits/byte",
        f"- High-entropy regions (>= {ent.get('threshold', 0)}): "
        f"**{len(ent.get('regions', []))}**",
    ]
    for region in ent.get("regions", [])[:20]:
        lines.append(
            "- 0x{:x}-0x{:x} peak {:.2f}".format(
                region.get("start", 0),
                region.get("end", 0),
                region.get("peak", 0),
            )
        )
    lines.append("")
    return lines


def _firmware_upx_lines(upx: dict) -> list:
    """
    Format the UPX detection section.

    Parameters
    ----------
    upx : dict
        UPX result.

    Returns
    -------
    list
        Markdown lines.
    """
    if not upx or not upx.get("packed"):
        return []
    return [
        "## Packed Executable",
        f"- UPX marker at offset **0x{upx.get('marker_offset', 0):x}**",
        f"- Host format: `{upx.get('host_format', 'unknown')}`",
        f"- Header zeroed/altered: **{upx.get('zeroed_header', False)}**",
        "",
    ]


def _firmware_extract_lines(ext: dict) -> list:
    """
    Format the extraction manifest section.

    Parameters
    ----------
    ext : dict
        Extraction result.

    Returns
    -------
    list
        Markdown lines.
    """
    if not ext or not ext.get("entries"):
        return []
    lines = [
        "## Extraction",
        f"- Files recovered: **{ext.get('files', 0)}**",
        "",
    ]
    for entry in ext["entries"][:60]:
        lines.append(
            "- `{}` ({})".format(entry.get("path", ""), entry.get("type", ""))
        )
    lines.append("")
    return lines


def _firmware_secret_lines(sec: dict) -> list:
    """
    Format the secrets section.

    Parameters
    ----------
    sec : dict
        Secrets result.

    Returns
    -------
    list
        Markdown lines.
    """
    if not sec or not sec.get("findings"):
        return []
    lines = [
        "## Embedded Secrets",
        f"- Findings: **{sec.get('count', 0)}**",
        "",
    ]
    for item in sec["findings"][:60]:
        lines.append(
            "- **{}** [{}] {} @ `{}`".format(
                item.get("rule", ""),
                item.get("tier", ""),
                item.get("evidence", ""),
                item.get("location", ""),
            )
        )
    lines.append("")
    return lines


def _firmware_sbom_lines(sbom: dict) -> list:
    """
    Format the SBOM section.

    Parameters
    ----------
    sbom : dict
        SBOM result.

    Returns
    -------
    list
        Markdown lines.
    """
    if not sbom or not sbom.get("components"):
        return []
    lines = [
        "## Software Bill of Materials",
        f"- Components: **{sbom.get('count', 0)}**",
        "",
        "| Component | Version | purl |",
        "|---|---|---|",
    ]
    for component in sbom["components"][:80]:
        lines.append(
            "| {} | {} | `{}` |".format(
                component.get("name", ""),
                component.get("version", ""),
                component.get("purl", ""),
            )
        )
    lines.append("")
    return lines


def _firmware_license_lines(lic: dict) -> list:
    """
    Format the licenses section.

    Parameters
    ----------
    lic : dict
        License result.

    Returns
    -------
    list
        Markdown lines.
    """
    summary = (lic or {}).get("summary") or {}
    if not summary:
        return []
    lines = ["## Licenses", "", "| SPDX ID | Count |", "|---|---|"]
    for spdx, entry in sorted(summary.items()):
        lines.append("| {} | {} |".format(spdx, entry.get("count", 0)))
    lines.append("")
    return lines


def _firmware_cve_lines(cve: dict) -> list:
    """
    Format the component CVE section.

    Parameters
    ----------
    cve : dict
        CVE join result.

    Returns
    -------
    list
        Markdown lines.
    """
    if not cve or not cve.get("findings"):
        return []
    summary = cve.get("summary", {})
    lines = [
        "## Component CVEs",
        f"- Total: **{summary.get('total', 0)}**, on CISA KEV: "
        f"**{summary.get('kev', 0)}**, "
        f"top CVSS: **{summary.get('top_cvss')}**",
        "",
    ]
    for item in cve["findings"][:60]:
        lines.append(
            "- **{}** {} {} — CVSS {} ({}), matched by {}".format(
                item.get("cve", ""),
                item.get("component", ""),
                item.get("version", ""),
                item.get("cvss"),
                item.get("severity", ""),
                item.get("matched_by", ""),
            )
        )
    lines.append("")
    return lines


_FIRMWARE_SECTIONS = (
    ("identification", _firmware_identification_lines),
    ("entropy", _firmware_entropy_lines),
    ("upx", _firmware_upx_lines),
    ("extraction", _firmware_extract_lines),
    ("secrets", _firmware_secret_lines),
    ("sbom", _firmware_sbom_lines),
    ("licenses", _firmware_license_lines),
    ("cve", _firmware_cve_lines),
)


def _export_firmware_reports(doc: dict, json_path: str, md_path: str) -> None:
    """
    Write firmware analysis JSON and Markdown outputs.

    Parameters
    ----------
    doc : dict
        Firmware analysis document.
    json_path : str
        Target JSON path.
    md_path : str
        Target Markdown path.

    Returns
    -------
    None
    """
    if json_path:
        _write_file(json_path, json.dumps(doc, indent=2))
    if md_path:
        _write_file(md_path, _format_firmware_markdown(doc))
