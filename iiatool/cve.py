"""Vulnerability assessment, CVE knowledge base, and NVD lookup."""

import json
import re
import time as _time
import urllib.error
import urllib.parse
import urllib.request

from .constants import (
    APACHE_KB_CVES,
    BIND_KB_CVES,
    CVE_BANNER_PRODUCT_RE,
    CVE_KEYWORD_BUDGET,
    CVE_NVD_URL,
    CVE_RATE_LIMIT_S,
    DNSMASQ_CVE_OLD,
    HAPROXY_KB_CVES,
    NETGEAR_CURRENT_BASELINE,
    NETGEAR_OLD_CVES,
    REALVNC_KB_CVES,
    SERVICE_VULN_KB,
    WIFI_OPEN_SECURITY,
)
from .utils import _found

_CVE_CACHE = {}
_CVE_BUDGET = CVE_KEYWORD_BUDGET
_CVE_LAST_REQUEST = 0.0


def _lookup_nvd_cves(keyword: str) -> list:
    """
    Query NVD API 2.0 for CVE records matching a product keyword.

    Rate-limited and budgeted to respect anonymous NVD access; results are
    cached for the duration of the run. Anonymous tier allows ~5 req/30s.

    Parameters
    ----------
    keyword : str
        Product keyword (e.g. "dropbear", "nginx").

    Returns
    -------
    list
        CVE dictionaries with id, score, and English summary.
    """
    global _CVE_BUDGET
    keyword = (keyword or "").strip().lower()
    if len(keyword) < 3 or keyword in _CVE_CACHE:
        return _CVE_CACHE.get(keyword, [])
    if _CVE_BUDGET <= 0:
        return []
    _CVE_BUDGET -= 1
    return _nvd_collect(keyword)


def _nvd_throttle() -> None:
    """
    Enforce the minimum interval between NVD requests.

    Parameters
    ----------
    None

    Returns
    -------
    None
    """
    global _CVE_LAST_REQUEST
    wait = CVE_RATE_LIMIT_S - (_time.monotonic() - _CVE_LAST_REQUEST)
    if wait > 0:
        _time.sleep(wait)
    _CVE_LAST_REQUEST = _time.monotonic()


def _nvd_url(keyword: str) -> str:
    """
    Build the NVD keyword-search URL for a product.

    Parameters
    ----------
    keyword : str
        Product keyword.

    Returns
    -------
    str
        Fully qualified query URL.
    """
    return (
        CVE_NVD_URL
        + "?keywordSearch="
        + urllib.parse.quote(keyword)
        + "&resultsPerPage=20"
    )


def _nvd_fetch(keyword: str) -> dict:
    """
    Fetch and parse an NVD response, tolerating network failure.

    Parameters
    ----------
    keyword : str
        Product keyword.

    Returns
    -------
    dict
        Parsed payload or empty dict.
    """
    try:
        req = urllib.request.Request(
            _nvd_url(keyword), headers={"User-Agent": "Mozilla/5.0"}
        )
        with urllib.request.urlopen(req, timeout=20.0) as resp:
            return json.loads(resp.read().decode("utf-8", "ignore"))
    except (OSError, urllib.error.URLError, json.JSONDecodeError):
        return {}


def _metric_score(cve: dict):
    """
    Extract the first available CVSS base score from a CVE record.

    Parameters
    ----------
    cve : dict
        CVE object.

    Returns
    -------
    float or None
        Base score.
    """
    metrics = (
        "cvssMetricV40",
        "cvssMetricV31",
        "cvssMetricV30",
        "cvssMetricV2",
    )
    for metric in metrics:
        try:
            value = cve["metrics"][metric][0]["cvssData"].get("baseScore")
        except (KeyError, IndexError, TypeError):
            continue
        if value is not None:
            return value
    return None


def _english_summary(cve: dict) -> str:
    """
    Return the English description for a CVE record.

    Parameters
    ----------
    cve : dict
        CVE object.

    Returns
    -------
    str
        English summary or empty string.
    """
    for desc in cve.get("descriptions", []) or []:
        if desc.get("lang") == "en":
            return desc.get("value", "")
    return ""


def _nvd_records(payload: dict) -> list:
    """
    Convert an NVD payload into ranked CVE records.

    Parameters
    ----------
    payload : dict
        Parsed NVD response.

    Returns
    -------
    list
        Up to five CVE records, worst first.
    """
    records = []
    for item in payload.get("vulnerabilities", []) or []:
        cve = item.get("cve", {})
        records.append({
            "id": cve.get("id", ""),
            "score": _metric_score(cve),
            "summary": _english_summary(cve)[:240],
        })
    records.sort(
        key=lambda r: (r["score"] is not None, r["score"] or 0), reverse=True
    )
    return records[:5]


def _nvd_collect(keyword: str) -> list:
    """
    Throttle, query, cache, and announce results for one keyword.

    Parameters
    ----------
    keyword : str
        Product keyword.

    Returns
    -------
    list
        CVE records.
    """
    _nvd_throttle()
    records = _nvd_records(_nvd_fetch(keyword))
    _CVE_CACHE[keyword] = records
    if records:
        _found(
            "NVD: {} CVEs for '{}' (top {})".format(
                len(records), keyword, records[0]["score"] or "N/A"
            )
        )
    return records


def _banner_product(banner: str, service: str, port: int) -> str:
    """
    Derive a CVE-searchable product keyword from a service banner.

    Parameters
    ----------
    banner : str
        Raw service banner text.
    service : str
        Port service label.
    port : int
        Port number.

    Returns
    -------
    str
        Product keyword, or empty string when nothing confident is found.
    """
    low = (banner or "").lower()
    match = CVE_BANNER_PRODUCT_RE.search(low)
    if match:
        return match.group(1).strip()
    return _fallback_product(low, port)


def _fallback_product(low: str, port: int) -> str:
    """
    Derive a product from a banner when no product regex matches.

    Parameters
    ----------
    low : str
        Lowercased banner text.
    port : int
        Port number.

    Returns
    -------
    str
        Product keyword or empty string.
    """
    if "ssh" in low or port in (22,):
        return "openssh"
    if "mqtt" in low and "mosquitto" not in low and port in (1883, 8883):
        return "mosquitto"
    if "dnsmasq" in low:
        return "dnsmasq"
    return ""


def _severity_label(score, port_entry: dict) -> str:
    """
    Map a CVSS base score to a severity label.

    Parameters
    ----------
    score : float or None
        CVSS base score.
    port_entry : dict
        Port assessment entry.

    Returns
    -------
    str
        CRITICAL/HIGH/MEDIUM/LOW label.
    """
    bands = ((9.0, "CRITICAL"), (7.0, "HIGH"), (4.0, "MEDIUM"))
    for threshold, label in bands:
        if score is not None and score >= threshold:
            return label
    return "LOW"


def _assess_one_port(port_record: dict) -> dict:
    """
    Build the full vulnerability picture for one open port.

    Combines the curated offline knowledge base with live NVD enrichment
    keyed off the service banner product.

    Parameters
    ----------
    port_record : dict
        Open-port record (port/service/banner).

    Returns
    -------
    dict
        Assessment with risks, curated CVEs, live CVEs, and verdict.
    """
    port = int(port_record.get("port", 0))
    banner = str(port_record.get("banner", ""))
    kb, netgear_fw = _assess_kb(port_record, port, banner)
    all_cves = _all_cves(kb, banner, port_record, port, netgear_fw)
    top_score = _top_score(all_cves)
    return _verdict(port, port_record, banner, kb, all_cves, top_score)


def _base_kb(port: int) -> dict:
    """
    Return the curated baseline knowledge base for a port.

    Parameters
    ----------
    port : int
        Port number.

    Returns
    -------
    dict
        Baseline risks and CVEs.
    """
    return SERVICE_VULN_KB.get(
        port,
        {
            "risks": [
                "Non-standard or unidentified listener — verify service "
                "identity before trusting",
            ],
            "cves": [],
        },
    )


def _netgear_fw(banner: str) -> str:
    """
    Extract a NETGEAR firmware version from a banner.

    Parameters
    ----------
    banner : str
        Service banner.

    Returns
    -------
    str
        Firmware version or empty string.
    """
    m = re.search(r"NETGEAR\s+\S+\s+firmware\s+([\w._]+)", banner)
    return m.group(1).lstrip("vV") if m else ""


def _netgear_current(fw: str) -> dict:
    """
    Build the knowledge base for a current NETGEAR firmware.

    Parameters
    ----------
    fw : str
        Firmware version.

    Returns
    -------
    dict
        Risks and baseline marker.
    """
    return {
        "risks": [
            "NETGEAR httpd (Basic Auth) — confirmed current firmware " + fw,
            "Use strong admin credentials; keep web/SOAP interfaces off WAN",
        ],
        "cves": [
            (
                "NETGEAR-baseline-" + fw,
                None,
                "Device verified on the current {} security release; the "
                "2021-2023 R6700v3 advisory batch (CVE-2022-27641..47, "
                "CVE-2022-48196) is addressed.".format(fw),
            )
        ],
    }


def _netgear_outdated(fw: str) -> dict:
    """
    Build the knowledge base for an outdated NETGEAR firmware.

    Parameters
    ----------
    fw : str
        Firmware version.

    Returns
    -------
    dict
        Risks and CVEs.
    """
    return {
        "risks": [
            "NETGEAR httpd — OUTDATED firmware " + fw
            + "; current release is 1.0.5.128 (July 2025)",
            "Legacy firmware exposes unauthenticated network-adjacent "
            "RCE paths",
        ],
        "cves": NETGEAR_OLD_CVES,
    }


def _netgear_unconfirmed() -> dict:
    """
    Build the knowledge base for an unidentified NETGEAR firmware.

    Parameters
    ----------
    None

    Returns
    -------
    dict
        Risks and CVEs.
    """
    return {
        "risks": [
            "NETGEAR httpd (Basic Auth) — firmware version not confirmed",
            "Require firmware at or above 1.0.5.128 to cover the "
            "2021-2023 advisory batch",
        ],
        "cves": NETGEAR_OLD_CVES,
    }


def _netgear_kb(banner: str, port: int):
    """
    Select a NETGEAR or baseline knowledge base for a port.

    Parameters
    ----------
    banner : str
        Service banner.
    port : int
        Port number.

    Returns
    -------
    tuple
        (knowledge base, confirmed firmware version or empty).
    """
    if "netgear" not in banner.lower():
        return _base_kb(port), ""
    fw = _netgear_fw(banner)
    if not fw:
        return _netgear_unconfirmed(), ""
    if fw.startswith(NETGEAR_CURRENT_BASELINE):
        return _netgear_current(fw), fw
    return _netgear_outdated(fw), fw


def _apache_kb() -> dict:
    """
    Build the knowledge base for a confirmed Apache httpd.

    Parameters
    ----------
    None

    Returns
    -------
    dict
        Risks and CVEs.
    """
    return {
        "risks": [
            "Apache httpd identified — confirm the release is not "
            "2.4.49/2.4.50",
        ],
        "cves": APACHE_KB_CVES,
    }


def _realvnc_kb() -> dict:
    """
    Build the knowledge base for a confirmed RealVNC server.

    Parameters
    ----------
    None

    Returns
    -------
    dict
        Risks and CVEs.
    """
    return {
        "risks": [
            "RealVNC server identified — confirm the release is not "
            "4.1 pre-1.1.1",
        ],
        "cves": REALVNC_KB_CVES,
    }


def _haproxy_kb() -> dict:
    """
    Build the knowledge base for a confirmed HAProxy reverse proxy.

    Parameters
    ----------
    None

    Returns
    -------
    dict
        Risks and CVEs.
    """
    return {
        "risks": [
            "HTTPS-alt confirmed HAProxy reverse proxy — "
            "request-smuggling surface if unpatched",
        ],
        "cves": HAPROXY_KB_CVES,
    }


def _bind_kb() -> dict:
    """
    Build the knowledge base for a confirmed BIND server.

    Parameters
    ----------
    None

    Returns
    -------
    dict
        Risks and CVEs.
    """
    return {
        "risks": [
            "DNS service identified as BIND (CHAOS TXT version.bind) — "
            "apply current vendor patch level",
            "Open recursive resolvers enable amplification/reflection "
            "DDoS; hold DNS to trusted LAN",
        ],
        "cves": BIND_KB_CVES,
    }


def _banner_kb(kb: dict, banner: str, netgear_fw: str) -> dict:
    """
    Override the knowledge base for a banner-confirmed product.

    Parameters
    ----------
    kb : dict
        Current knowledge base.
    banner : str
        Service banner.
    netgear_fw : str
        Confirmed NETGEAR firmware, if any.

    Returns
    -------
    dict
        Knowledge base.
    """
    if netgear_fw:
        return kb
    low = banner.lower()
    if "apache" in low:
        return _apache_kb()
    if "realvnc" in low:
        return _realvnc_kb()
    return kb


def _special_kb(kb, port_record, port, banner, netgear_fw):
    """
    Apply port-specific and banner-specific knowledge base overrides.

    Parameters
    ----------
    kb : dict
        Current knowledge base.
    port_record : dict
        Open-port record.
    port : int
        Port number.
    banner : str
        Service banner.
    netgear_fw : str
        Confirmed NETGEAR firmware, if any.

    Returns
    -------
    dict
        Knowledge base.
    """
    if port == 53:
        return _dns_kb(kb, port_record)
    if port == 8443 and "haproxy" in banner.lower():
        return _haproxy_kb()
    return _banner_kb(kb, banner, netgear_fw)


def _assess_kb(port_record: dict, port: int, banner: str):
    """
    Select the full knowledge base for a port.

    Parameters
    ----------
    port_record : dict
        Open-port record.
    port : int
        Port number.
    banner : str
        Service banner.

    Returns
    -------
    tuple
        (knowledge base, confirmed NETGEAR firmware or empty).
    """
    kb, netgear_fw = _netgear_kb(banner, port)
    return _special_kb(kb, port_record, port, banner, netgear_fw), netgear_fw


def _dns_kb(kb: dict, port_record: dict) -> dict:
    """
    Fingerprint a DNS server and select its knowledge base.

    Parameters
    ----------
    kb : dict
        Current knowledge base.
    port_record : dict
        Open-port record.

    Returns
    -------
    dict
        Knowledge base.
    """
    from .scan import _probe_dns_version

    ip = str(port_record.get("host", ""))
    low = _probe_dns_version(ip).lower() if ip else ""
    if "dnsmasq" in low:
        return _dnsmasq_kb(low)
    if "bind" in low:
        return _bind_kb()
    return kb


def _dnsmasq_kb(low: str) -> dict:
    """
    Build the knowledge base for a confirmed dnsmasq server.

    Parameters
    ----------
    low : str
        Lowercased dnsmasq identity string.

    Returns
    -------
    dict
        Risks and CVEs.
    """
    m = re.search(r"dnsmasq[-\s]*(\d+)\.(\d+)", low)
    label = "dnsmasq " + (m.group(0).replace("-", " ") if m else "?")
    cves, note = _dns_tier(m)
    return {
        "risks": [
            "DNS service identified as {} (CHAOS TXT version.bind) — "
            "{}".format(label, note),
            "Open recursive resolvers enable amplification/reflection "
            "DDoS; hold DNS to trusted LAN",
        ],
        "cves": cves,
    }


_DNS_TIERS = (
    ((2, 90), [], "current release — 2020-2023 advisory batch addressed"),
    ((2, 87), DNSMASQ_CVE_OLD[3:], "updates needed for CVE-2023-28450"),
    ((2, 86), DNSMASQ_CVE_OLD[2:],
     "updates needed for CVE-2021-45949 + CVE-2023-28450"),
    ((2, 83), DNSMASQ_CVE_OLD[1:],
     "updates needed for the 2021-2023 batch"),
)


def _dns_tier(m):
    """
    Select the dnsmasq CVE slice and note for a matched version.

    Parameters
    ----------
    m : re.Match or None
        Version regex match.

    Returns
    -------
    tuple
        (CVEs, note).
    """
    if not m:
        return DNSMASQ_CVE_OLD, "version not confirmed"
    version = tuple(int(x) for x in m.groups())
    for bound, cves, note in _DNS_TIERS:
        if version >= bound:
            return cves, note
    return DNSMASQ_CVE_OLD, "OUTDATED — update to 2.90+"


def _curated(kb: dict) -> list:
    """
    Convert curated knowledge-base CVEs into finding records.

    Parameters
    ----------
    kb : dict
        Knowledge base.

    Returns
    -------
    list
        Curated CVE records.
    """
    return [
        {
            "id": cid,
            "score": score,
            "summary": summary,
            "source": "curated knowledge base",
        }
        for (cid, score, summary) in kb.get("cves", [])
    ]


def _all_cves(kb, banner, port_record, port, netgear_fw) -> list:
    """
    Merge curated and live CVEs for a port verdict.

    Parameters
    ----------
    kb : dict
        Knowledge base.
    banner : str
        Service banner.
    port_record : dict
        Open-port record.
    port : int
        Port number.
    netgear_fw : str
        Confirmed NETGEAR firmware, if any.

    Returns
    -------
    list
        Merged CVE records.
    """
    curated = _curated(kb)
    product = _banner_product(banner, port_record.get("service", ""), port)
    live = _lookup_nvd_cves(product) if product and not netgear_fw else []
    known = {c["id"] for c in curated}
    return curated + [
        {**cve, "source": f"NVD live (keyword '{product}')"}
        for cve in live
        if cve["id"] not in known
    ]


def _top_score(all_cves: list):
    """
    Return the highest CVSS score among the findings.

    Parameters
    ----------
    all_cves : list
        CVE records.

    Returns
    -------
    float or None
        Highest score.
    """
    return max(
        (c.get("score") for c in all_cves if c.get("score") is not None),
        default=None,
    )


def _verdict(port, port_record, banner, kb, all_cves, top_score) -> dict:
    """
    Assemble the final per-port verdict.

    Parameters
    ----------
    port : int
        Port number.
    port_record : dict
        Open-port record.
    banner : str
        Service banner.
    kb : dict
        Knowledge base.
    all_cves : list
        Merged CVE records.
    top_score : float or None
        Highest CVSS score.

    Returns
    -------
    dict
        Port verdict.
    """
    return {
        "port": port,
        "service": port_record.get("service", "?"),
        "banner": banner,
        "risks": kb.get("risks", []),
        "cves": all_cves,
        "top_score": top_score,
        "severity": _severity_label(top_score, port_record),
    }


def _assess_vulnerabilities(intel: dict) -> None:
    """
    Assess every open port for vulnerabilities on a device.

    Populates intel["vulnerabilities"] with per-port verdicts and appends
    high/critical findings to the risk assessment.

    Parameters
    ----------
    intel : dict
        Intelligence container.

    Returns
    -------
    None
    """
    open_ports = intel.get("open_ports", []) or []
    if not open_ports:
        intel["vulnerabilities"] = _empty_vulnerabilities()
        return
    ports = [_assess_one_port(p) for p in open_ports]
    findings = _high_findings(ports)
    intel["vulnerabilities"] = _vulnerability_doc(ports, findings)
    _finalize_assessment(intel, ports, findings)


def _empty_vulnerabilities() -> dict:
    """
    Build the empty vulnerability document for a host with no open ports.

    Parameters
    ----------
    None

    Returns
    -------
    dict
        Empty vulnerability assessment.
    """
    return {
        "assessed": True,
        "ports_exposed": 0,
        "ports": [],
        "findings": [],
    }


def _finding_from_port(port_assessment: dict) -> dict:
    """
    Convert one port verdict into a high-severity finding.

    Parameters
    ----------
    port_assessment : dict
        Per-port assessment.

    Returns
    -------
    dict
        Finding record.
    """
    cves = port_assessment["cves"]
    return {
        "severity": port_assessment["severity"],
        "port": port_assessment["port"],
        "service": port_assessment["service"],
        "top_cve": cves[0]["id"] if cves else None,
    }


def _high_findings(ports: list) -> list:
    """
    Collect high and critical findings from per-port verdicts.

    Parameters
    ----------
    ports : list
        Per-port assessments.

    Returns
    -------
    list
        High/critical findings.
    """
    findings = []
    for port_assessment in ports:
        if port_assessment["severity"] in ("HIGH", "CRITICAL"):
            findings.append(_finding_from_port(port_assessment))
    return findings


def _vulnerability_doc(ports: list, findings: list) -> dict:
    """
    Build the vulnerability document for a host with open ports.

    Parameters
    ----------
    ports : list
        Per-port assessments.
    findings : list
        High/critical findings.

    Returns
    -------
    dict
        Vulnerability assessment.
    """
    return {
        "assessed": True,
        "ports_exposed": len(ports),
        "ports": ports,
        "findings": findings,
        "sources": [
            "Offline curated CVE/risk knowledge base",
            "NVD API 2.0 live CVE lookup (anonymous tier)",
        ],
    }


def _append_risk(intel: dict, finding: dict) -> None:
    """
    Append one high-severity finding to the risk assessment.

    Parameters
    ----------
    intel : dict
        Intelligence container.
    finding : dict
        Finding record.

    Returns
    -------
    None
    """
    intel["blue_team_risk_assessment"].append(
        {
            "severity": finding["severity"],
            "vuln": (
                f"{finding['service']} ({finding['port']}) exposure — "
                f"{finding['top_cve'] or 'known vulnerable family'}"
            ),
            "detail": (
                "Open service is part of a known-vulnerable family; see "
                "vulnerability assessment for CVE matches."
            ),
        }
    )


def _finalize_assessment(intel: dict, ports: list, findings: list) -> None:
    """
    Append risk entries and announce the vulnerability summary.

    Parameters
    ----------
    intel : dict
        Intelligence container.
    ports : list
        Per-port assessments.
    findings : list
        High/critical findings.

    Returns
    -------
    None
    """
    for finding in findings:
        _append_risk(intel, finding)
    _announce_assessment(ports, findings)


def _announce_assessment(ports: list, findings: list) -> None:
    """
    Log the vulnerability assessment summary.

    Parameters
    ----------
    ports : list
        Per-port assessments.
    findings : list
        High/critical findings.

    Returns
    -------
    None
    """
    critical = len([f for f in findings if f["severity"] == "CRITICAL"])
    high = len([f for f in findings if f["severity"] == "HIGH"])
    _found(
        "Vuln assessment: {} open ports, {} critical, {} high".format(
            len(ports), critical, high
        )
    )


def _assess_wifi_security(intel: dict, network: dict) -> None:
    """
    Add a Wi-Fi hardening verdict for an audited network.

    Parameters
    ----------
    intel : dict
        Intelligence container.
    network : dict
        Wi-Fi network metadata.

    Returns
    -------
    None
    """
    security = str(network.get("security", "") or "N/A")
    band = network.get("band", "")
    if security in WIFI_OPEN_SECURITY or security.upper() == "OPEN":
        intel["blue_team_risk_assessment"].append(
            {
                "severity": "HIGH",
                "vuln": f"Open / legacy Wi-Fi network ({security})",
                "detail": (
                    f"Network {intel['target']['name']} permits "
                    "unauthenticated or legacy (WEP/WPA1) association "
                    "on " + band + " — "
                    "rogue device and sniffing risk elevated."
                ),
            }
        )
    else:
        intel["wifi"][
            "hardening"
        ] = "WPA2/WPA3 class security; verify PSK strength"
        intel["blue_team_risk_assessment"].append(
            {
                "severity": "INFORMATIONAL",
                "vuln": "Wi-Fi secured ({})".format(security),
                "detail": (
                    f"Network {intel['target']['name']} uses "
                    f"{security} on {band}."
                ),
            }
        )


def _assess_bt_security(intel: dict, peer: dict) -> None:
    """
    Record Bluetooth authentication posture for a classic peer.

    Parameters
    ----------
    intel : dict
        Intelligence container.
    peer : dict
        Classic peer metadata.

    Returns
    -------
    None
    """
    intel["blue_team_risk_assessment"].append(
        {
            "severity": "INFORMATIONAL",
            "vuln": "Bluetooth Classic peer in range",
            "detail": (
                f"Peer {intel['target']['name']} is discoverable; "
                "verify pairing mode and disable discoverability "
                "when unused."
            ),
        }
    )
