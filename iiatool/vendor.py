"""Vendor OUI lookup and FCC regulatory audit functions."""

import json
import re
import urllib.error
import urllib.parse
import urllib.request

from .constants import (
    FCC_GRANT_URL,
    FCC_SEARCH_URL,
    FCC_TOKEN_RE,
    MAC_API_URL,
)
from .utils import _clean_mac, _found, _log, _warn

_FCC_PROBE_BUDGET = 12


def _oui_flags(mac: str) -> str:
    """
    Classify MAC address flags from the first octet.

    Parameters
    ----------
    mac : str
        Hardware MAC address.

    Returns
    -------
    str
        "unicast/multicast, globally unique/locally administered" label.
    """
    clean = _clean_mac(mac)
    if len(clean) < 2:
        return ""
    first = int(clean[:2], 16)
    kind = "multicast" if first & 1 else "unicast"
    owner = (
        "locally administered (randomized/private)"
        if first & 2
        else "globally unique (IEEE-registered)"
    )
    return f"{kind}, {owner}"


def _oui_is_locally_administered(mac: str) -> bool:
    """
    Determine whether a MAC uses the locally administered flag.

    Parameters
    ----------
    mac : str
        Hardware MAC address.

    Returns
    -------
    bool
        True when the address is randomized/private.
    """
    clean = _clean_mac(mac)
    if len(clean) < 2:
        return False
    return bool(int(clean[:2], 16) & 2)


def _fetch_oui_vendor(mac: str) -> dict:
    """
    Lookup IEEE vendor via public web API.

    Parameters
    ----------
    mac : str
        Hardware MAC address.

    Returns
    -------
    dict
        Parsed vendor details.
    """
    url = f"{MAC_API_URL}{mac}"
    req = urllib.request.Request(url, headers={"User-Agent": "Audit/1.0"})
    with urllib.request.urlopen(req, timeout=5.0) as resp:
        return json.loads(resp.read().decode())


def _fcc_search(query: str) -> dict:
    """
    Best-effort FCC ID search by product/model name.

    Queries the public FCC ID database via fccid.io, takes the top grant
    whose grantee code parses cleanly, and pulls its frequency table.

    Parameters
    ----------
    query : str
        Product model, manufacturer name, or device name.

    Returns
    -------
    dict
        Grant record with ID, URL, and parsed frequencies.
    """
    url = FCC_SEARCH_URL + "?q=" + urllib.parse.quote(query) + "&x=0&y=0"
    chosen = _pick_grant(_http_get(url))
    if not chosen:
        return {}
    return _grant_record(chosen)


def _http_get(url: str) -> str:
    """
    Fetch a text resource with the audit user agent.

    Parameters
    ----------
    url : str
        Resource URL.

    Returns
    -------
    str
        Decoded response body.
    """
    req = urllib.request.Request(url, headers={"User-Agent": "Audit/1.0"})
    with urllib.request.urlopen(req, timeout=6.0) as resp:
        return resp.read().decode("utf-8", "ignore")


def _pick_grant(html: str) -> str:
    """
    Choose the first grantee code from search-result HTML.

    Parameters
    ----------
    html : str
        Search-result HTML.

    Returns
    -------
    str
        Uppercased grantee code, or empty string.
    """
    grantee_re = re.compile(r"^[A-Za-z]{2,5}[0-9][A-Za-z0-9]{4,}$")
    for grant in re.findall(r'href="/([A-Za-z0-9]+)"', html):
        if _valid_grant(grant, grantee_re):
            return grant.upper()
    return ""


def _valid_grant(grant: str, grantee_re) -> bool:
    """
    Report whether a candidate string is a plausible grantee code.

    Parameters
    ----------
    grant : str
        Candidate grantee code.
    grantee_re : re.Pattern
        Compiled grantee-code pattern.

    Returns
    -------
    bool
        True when the code is plausible.
    """
    if len(grant) < 6 or not grantee_re.fullmatch(grant):
        return False
    return grant.lower() not in ("search", "login")


def _grant_record(chosen: str, source: str = "") -> dict:
    """
    Build a grant record and fetch its frequency table.

    Parameters
    ----------
    chosen : str
        Grantee code.
    source : str
        Optional resolution source label.

    Returns
    -------
    dict
        Grant record.
    """
    grant = {
        "grant": chosen,
        "url": FCC_GRANT_URL.format(chosen),
        "frequencies": [],
    }
    if source:
        grant["source"] = source
    try:
        grant["frequencies"] = _parse_fcc_frequencies(_http_get(grant["url"]))
    except (urllib.error.URLError, OSError):
        pass
    return grant


def _fcc_lookup_direct(fcc_id: str) -> dict:
    """
    Resolve a known FCC ID against the certification grant page.

    Direct grant pages on fccid.io are server-rendered, so a known FCC ID
    yields its frequency table without any JavaScript.

    Parameters
    ----------
    fcc_id : str
        FCC equipment authorization ID, e.g. "VPYLB1MDIMP004".

    Returns
    -------
    dict
        Grant record with ID, URL, and parsed frequencies.
    """
    fcc_id = (fcc_id or "").strip().upper()
    if not re.fullmatch(r"[A-Z0-9]{6,22}", fcc_id):
        return {}
    return _grant_record(fcc_id, "direct FCC ID")


def _extract_embedded_fcc_ids(intel: dict) -> list:
    """
    Mine probable FCC authorization IDs from captured device data.

    Searches manufacturer advertisement payloads and GATT device-info
    strings for grantee-code-shaped tokens.

    Parameters
    ----------
    intel : dict
        Intelligence container.

    Returns
    -------
    list
        Unique upper-case FCC ID candidates.
    """
    return sorted(_fcc_tokens(_fcc_corpus(intel)))


def _adv_corpus(adv: dict) -> list:
    """
    Collect advertisement payload strings for FCC mining.

    Parameters
    ----------
    adv : dict
        Advertisement data.

    Returns
    -------
    list
        Payload strings.
    """
    corpus = []
    for m in adv.get("manufacturer_data", []) or []:
        corpus.append(str(m.get("hex", "")))
        corpus.append(str(m.get("ascii", "")))
    return corpus


def _fcc_corpus(intel: dict) -> list:
    """
    Collect every device string that may contain an FCC ID.

    Parameters
    ----------
    intel : dict
        Intelligence container.

    Returns
    -------
    list
        Candidate strings.
    """
    telemetry = intel.get("ble_telemetry", {})
    adv = telemetry.get("adv", {}) or {}
    corpus = _adv_corpus(adv)
    corpus += [
        str(value or "")
        for value in (telemetry.get("device_info", {}) or {}).values()
    ]
    corpus += [
        str(c2.get("hostname", "")) for c2 in intel.get("cloud_c2", []) or []
    ]
    return corpus


def _fcc_tokens(corpus: list) -> set:
    """
    Extract FCC-ID-shaped tokens from candidate strings.

    Parameters
    ----------
    corpus : list
        Candidate strings.

    Returns
    -------
    set
        Unique tokens.
    """
    tokens = set()
    for item in corpus:
        for token in FCC_TOKEN_RE.findall(item):
            if 6 <= len(token) <= 22:
                tokens.add(token)
    return tokens


def _maybe_fcc_resolve(intel: dict, query: str = "", fcc_id: str = "") -> None:
    """
    Resolve an otherwise-unknown device against the FCC database.

    Resolution order:
      1. Explicit FCC ID (--fcc-id or fcc_id_override)
      2. FCC-ID-shaped tokens mined from the device's own data
      3. Free-text search probe (best effort; fccid.io search is JS-only
         and may yield nothing without a browser)

    Parameters
    ----------
    intel : dict
        Intelligence container.
    query : str
        Free-text search query (model/name/manufacturer).
    fcc_id : str
        Optional explicit FCC equipment authorization ID.

    Returns
    -------
    None
    """
    fcc_id = (fcc_id or intel.get("fcc_id_override") or "").strip().upper()
    if fcc_id and _try_grant(intel, fcc_id):
        return
    if _try_embedded(intel):
        return
    _try_query(intel, query)


def _try_grant(intel: dict, fcc_id: str) -> bool:
    """
    Resolve one explicit FCC ID against the grant database.

    Parameters
    ----------
    intel : dict
        Intelligence container.
    fcc_id : str
        FCC equipment authorization ID.

    Returns
    -------
    bool
        True when a grant with frequencies was stored.
    """
    global _FCC_PROBE_BUDGET
    _FCC_PROBE_BUDGET -= 1
    grant = _fcc_lookup_direct(fcc_id)
    if grant.get("frequencies"):
        _store_fcc_grant(intel, grant)
        return True
    return False


def _try_embedded(intel: dict) -> bool:
    """
    Resolve FCC-ID-shaped tokens mined from the device's own data.

    Parameters
    ----------
    intel : dict
        Intelligence container.

    Returns
    -------
    bool
        True when a grant with frequencies was stored.
    """
    for token in _extract_embedded_fcc_ids(intel):
        if _FCC_PROBE_BUDGET <= 0:
            return False
        if _try_grant(intel, token):
            return True
    return False


def _query_ok(query: str) -> bool:
    """
    Report whether a free-text FCC query is worth probing.

    Parameters
    ----------
    query : str
        Search query.

    Returns
    -------
    bool
        True when the query is long enough and contains a digit.
    """
    return len(query) >= 4 and bool(re.search(r"\d", query))


def _safe_search(query: str) -> dict:
    """
    Run an FCC search, returning an empty dict on network failure.

    Parameters
    ----------
    query : str
        Search query.

    Returns
    -------
    dict
        Grant record or empty dict.
    """
    try:
        return _fcc_search(query)
    except urllib.error.URLError:
        return {}


def _fcc_search_grant(intel: dict, query: str) -> bool:
    """
    Budget a free-text FCC search and store any resolved grant.

    Parameters
    ----------
    intel : dict
        Intelligence container.
    query : str
        Search query.

    Returns
    -------
    bool
        True when a grant was stored.
    """
    if not _budget_ok():
        return False
    grant = _safe_search(query)
    if grant:
        _store_fcc_grant(intel, grant)
        return True
    return False


def _budget_ok() -> bool:
    """
    Consume one FCC probe from the budget when available.

    Parameters
    ----------
    None

    Returns
    -------
    bool
        True when a probe may proceed.
    """
    global _FCC_PROBE_BUDGET
    if _FCC_PROBE_BUDGET <= 0:
        return False
    _FCC_PROBE_BUDGET -= 1
    return True


def _try_query(intel: dict, query: str) -> None:
    """
    Attempt a free-text FCC search for a query.

    Parameters
    ----------
    intel : dict
        Intelligence container.
    query : str
        Search query.

    Returns
    -------
    None
    """
    query = (query or "").strip()
    if not _query_ok(query):
        return
    _fcc_search_grant(intel, query)


def _store_fcc_grant(intel: dict, grant: dict) -> None:
    """
    Persist an FCC grant record and announce the resolution.

    Parameters
    ----------
    intel : dict
        Intelligence container.
    grant : dict
        Resolved grant record.

    Returns
    -------
    None
    """
    intel.setdefault("regulatory", {})["fcc_grant"] = grant
    _found(
        f"FCC resolved: {grant['grant']} "
        f"({grant['url']} / {len(grant['frequencies'])} freq rows)"
    )


def _clean_table_row(row_html: str) -> str:
    """
    Strip HTML tags and collapse spaces.

    Parameters
    ----------
    row_html : str
        Raw HTML table row string.

    Returns
    -------
    str
        Normalized text.
    """
    clean = re.sub(r"<[^<]+?>", " ", row_html)
    return re.sub(r"\s+", " ", clean).strip()


def _parse_fcc_frequencies(html: str) -> list:
    """
    Extract frequency grant lines from FCC HTML.

    Parameters
    ----------
    html : str
        Raw HTML text from FCC page.

    Returns
    -------
    list
        Discovered frequency statements.
    """
    rows = re.findall(r"<tr>(.*?)</tr>", html, re.DOTALL)
    cleaned = [_clean_table_row(r) for r in rows]
    return [h for h in cleaned if "2402" in h or "2412" in h]


def _fetch_fcc_grant(fcc_id: str = "VPYLB1MDIMP004") -> list:
    """
    Retrieve FCC certification records for a granted equipment ID.

    Parameters
    ----------
    fcc_id : str
        FCC equipment authorization ID (defaults to the imp004m module
        used by Cloud-Tethered appliances).

    Returns
    -------
    list
        Extracted authorization rows.
    """
    req = urllib.request.Request(
        FCC_GRANT_URL.format(fcc_id or "VPYLB1MDIMP004"),
        headers={"User-Agent": "A/1.0"},
    )
    with urllib.request.urlopen(req, timeout=5.0) as resp:
        return _parse_fcc_frequencies(resp.read().decode("utf-8", "ignore"))


def _query_fcc_grant_info(intel: dict, fcc_id: str = "VPYLB1MDIMP004") -> None:
    """
    Query and attach FCC grant details.

    Parameters
    ----------
    intel : dict
        Intelligence container.
    fcc_id : str
        FCC equipment authorization ID.

    Returns
    -------
    None
    """
    try:
        intel["regulatory"]["fcc_grant"] = _fetch_fcc_grant(fcc_id)[:3]
        _found("FCC: 2412-2462MHz Wi-Fi, 2402-2480MHz BLE")
    except urllib.error.URLError as err:
        _warn(f"FCC lookup skipped: {err}")


def _assign_imp_regulatory(intel: dict) -> None:
    """
    Attach Electric Imp module and silicon attribution.

    Parameters
    ----------
    intel : dict
        Intelligence container.

    Returns
    -------
    None
    """
    intel["regulatory"]["platform"] = "Electric Imp imp004m"
    intel["regulatory"]["mcu"] = "STM32F412 (ARM Cortex-M4)"
    intel["regulatory"]["radio"] = "Cypress CYW43438 (Wi-Fi + BLE)"
    _query_fcc_grant_info(intel)


def _store_vendor_info(intel: dict, mac: str, data: dict) -> None:
    """
    Store vendor data and trigger regulatory lookup.

    Parameters
    ----------
    intel : dict
        Intelligence container.
    mac : str
        Hardware MAC address.
    data : dict
        API response dictionary.

    Returns
    -------
    None
    """
    vendor = str(data.get("company") or "").strip() or "Unknown"
    pfx = _clean_mac(mac)[:6]
    if vendor in ("Unknown", "Private", "private", ""):
        vendor = (
            "Locally administered (randomized/private) address"
            if _oui_is_locally_administered(mac)
            else "No registered OUI (unassigned prefix)"
        )
    intel["vendor_oui"] = {
        "company": vendor,
        "prefix": pfx,
        "source": "IEEE OUI registry",
        "mac_flags": _oui_flags(mac),
        "mac_locally_administered": _oui_is_locally_administered(mac),
    }
    _found(f"Vendor: {vendor}")
    if "electric imp" in vendor.lower():
        _assign_imp_regulatory(intel)


def _audit_vendor_regulatory(intel: dict, mac: str) -> None:
    """
    Resolve OUI registration and regulatory identity.

    Parameters
    ----------
    intel : dict
        Intelligence container.
    mac : str
        Target hardware MAC.

    Returns
    -------
    None
    """
    _log("VENDOR", f"Querying IEEE OUI for MAC: {mac}")
    try:
        data = _fetch_oui_vendor(mac)
        _store_vendor_info(intel, mac, data)
    except urllib.error.URLError as err:
        _warn(f"OUI lookup skipped: {err}")


def _auto_vendor_lookup(intel: dict, mac: str) -> None:
    """
    Resolve device vendor identity from every available signal.

    Merges, in order of authority:
      1. IEEE OUI registry (maclookup API) for the hardware address
      2. BLE advertisement manufacturer-data company ID table
      3. BLE GATT "Device Information" manufacturer/model name string
      4. MAC flag classification (randomized/private vs registered)
      5. FCC ID database probe using the claimed model/name

    The resulting vendor record is never left blank — unknowns are labeled
    "Locally administered (randomized/private) address" or "No registered OUI".

    Parameters
    ----------
    intel : dict
        Per-device intelligence container.
    mac : str
        MAC-like hardware address.

    Returns
    -------
    None
    """
    is_mac = _is_mac(mac)
    oui_company, oui_error = _oui_lookup(intel, mac, is_mac)
    ident = _ble_identity(intel)
    evidence = _evidence(oui_company, ident, oui_error)
    company, source = _choose_vendor(oui_company, ident, is_mac, mac)
    _store_vendor(
        intel, mac, is_mac, company, source, evidence, ident["claimed_model"]
    )
    _vendor_fcc(intel, ident)


def _is_mac(mac: str) -> bool:
    """
    Report whether a string is a 48-bit MAC address.

    Parameters
    ----------
    mac : str
        Candidate address.

    Returns
    -------
    bool
        True when the string is a MAC.
    """
    pattern = r"(?:[0-9a-fA-F]{2}[:\-]){5}[0-9a-fA-F]{2}$"
    return bool(mac) and bool(re.match(pattern, mac))


def _printable(text: str) -> str:
    """
    Keep only printable characters of a string.

    Parameters
    ----------
    text : str
        Input text.

    Returns
    -------
    str
        Printable text.
    """
    return "".join(ch for ch in (text or "") if ch.isprintable()).strip()


def _oui_fetch(mac: str):
    """
    Fetch the OUI vendor for a MAC, returning errors as text.

    Parameters
    ----------
    mac : str
        Hardware MAC address.

    Returns
    -------
    tuple
        (company, error text).
    """
    try:
        return _printable(_fetch_oui_vendor(mac).get("company")), ""
    except urllib.error.URLError as err:
        return "", str(err)


def _warn_no_mac(intel: dict) -> None:
    """
    Warn that a non-MAC identifier cannot be OUI-resolved.

    Parameters
    ----------
    intel : dict
        Intelligence container.

    Returns
    -------
    None
    """
    name = _printable(intel.get("target", {}).get("name", ""))
    _warn("No MAC for OUI lookup: " + (name or "unknown device"))


def _oui_lookup(intel: dict, mac: str, is_mac: bool):
    """
    Resolve a MAC against the IEEE OUI registry.

    Parameters
    ----------
    intel : dict
        Intelligence container.
    mac : str
        Hardware address.
    is_mac : bool
        Whether the address is a MAC.

    Returns
    -------
    tuple
        (vendor company, error text).
    """
    if is_mac:
        return _oui_fetch(mac)
    if not mac:
        _warn_no_mac(intel)
    return "", ""


def _adv_companies(adv: dict) -> list:
    """
    List known manufacturer companies in advertisement data.

    Parameters
    ----------
    adv : dict
        Advertisement data.

    Returns
    -------
    list
        Company names.
    """
    return [
        m.get("company")
        for m in adv.get("manufacturer_data", []) or []
        if m.get("company") and m.get("company") != "Unknown"
    ]


def _ble_identity(intel: dict) -> dict:
    """
    Collect BLE identity signals from a device record.

    Parameters
    ----------
    intel : dict
        Intelligence container.

    Returns
    -------
    dict
        Advertisement, device-info, and derived identity fields.
    """
    telemetry = intel.get("ble_telemetry", {})
    device_info = telemetry.get("device_info", {}) or {}
    adv = telemetry.get("adv", {}) or {}
    return {
        "device_info": device_info,
        "adv": adv,
        "gatt_mfr": _printable(device_info.get("manufacturer")),
        "claimed_model": _printable(device_info.get("model")),
        "adv_companies": _adv_companies(adv),
    }


def _evidence(oui_company: str, ident: dict, oui_error: str) -> list:
    """
    Build the evidence trail for a vendor attribution.

    Parameters
    ----------
    oui_company : str
        IEEE OUI vendor, if any.
    ident : dict
        BLE identity fields.
    oui_error : str
        OUI lookup error text, if any.

    Returns
    -------
    list
        Evidence strings.
    """
    evidence = _evidence_names(oui_company, ident["gatt_mfr"])
    evidence += [
        f"advertised company ID = {company}"
        for company in ident["adv_companies"]
    ]
    if oui_error:
        evidence.append(f"OUI lookup offline ({oui_error})")
    return evidence


def _evidence_names(oui_company: str, gatt_mfr: str) -> list:
    """
    Build name-based evidence entries.

    Parameters
    ----------
    oui_company : str
        IEEE OUI vendor, if any.
    gatt_mfr : str
        GATT manufacturer name, if any.

    Returns
    -------
    list
        Evidence strings.
    """
    evidence = []
    if oui_company:
        evidence.append(f"IEEE OUI = {oui_company}")
    if gatt_mfr:
        evidence.append(f"GATT manufacturer name = {gatt_mfr}")
    return evidence


def _vendor_source(oui_company: str, ident: dict):
    """
    Select the most authoritative vendor name and its source label.

    Parameters
    ----------
    oui_company : str
        IEEE OUI vendor, if any.
    ident : dict
        BLE identity fields.

    Returns
    -------
    tuple
        (company, source label).
    """
    if oui_company:
        return oui_company, "IEEE OUI registry"
    if ident["gatt_mfr"]:
        return ident["gatt_mfr"], "GATT Device Information"
    if ident["adv_companies"]:
        return ident["adv_companies"][0], "BLE advertisement manufacturer data"
    return "", ""


def _fallback_vendor(is_mac: bool, mac: str):
    """
    Label a vendor when no authoritative source is available.

    Parameters
    ----------
    is_mac : bool
        Whether the address is a MAC.
    mac : str
        Hardware address.

    Returns
    -------
    tuple
        (company, source label).
    """
    if not is_mac:
        return (
            "Non-MAC identifier (no OUI applicable)",
            "identifier type classification",
        )
    if _oui_is_locally_administered(mac):
        return (
            "Locally administered (randomized/private) address",
            "MAC flag classification",
        )
    return "No registered OUI (unassigned prefix)", "MAC flag classification"


def _choose_vendor(oui_company: str, ident: dict, is_mac: bool, mac: str):
    """
    Choose the vendor name and source, falling back when unknown.

    Parameters
    ----------
    oui_company : str
        IEEE OUI vendor, if any.
    ident : dict
        BLE identity fields.
    is_mac : bool
        Whether the address is a MAC.
    mac : str
        Hardware address.

    Returns
    -------
    tuple
        (company, source label).
    """
    company, source = _vendor_source(oui_company, ident)
    if company:
        return company, source
    return _fallback_vendor(is_mac, mac)


def _store_vendor(
    intel: dict, mac: str, is_mac: bool, company: str, source: str,
    evidence: list, claimed_model: str,
) -> None:
    """
    Persist the vendor record and announce it.

    Parameters
    ----------
    intel : dict
        Intelligence container.
    mac : str
        Hardware address.
    is_mac : bool
        Whether the address is a MAC.
    company : str
        Vendor name.
    source : str
        Source label.
    evidence : list
        Evidence strings.
    claimed_model : str
        Claimed model name.

    Returns
    -------
    None
    """
    intel["vendor_oui"] = {
        "company": company,
        "prefix": _clean_mac(mac)[:6] if is_mac else "",
        "source": source,
        "evidence": evidence,
        "model_claimed": claimed_model,
        "mac_flags": _oui_flags(mac) if is_mac else "",
        "mac_locally_administered": (
            _oui_is_locally_administered(mac) if mac else False
        ),
        "is_mac_address": is_mac,
    }
    _found(f"Vendor: {company}" + (f" ({source})" if source else ""))


def _vendor_fcc(intel: dict, ident: dict) -> None:
    """
    Trigger an FCC probe when the device exposes identifying data.

    Parameters
    ----------
    intel : dict
        Intelligence container.
    ident : dict
        BLE identity fields.

    Returns
    -------
    None
    """
    wants_fcc = bool(intel.get("fcc_id_override")) or bool(
        ident["device_info"] or ident["adv"].get("manufacturer_data")
    )
    if wants_fcc:
        fcc_query = (
            ident["claimed_model"]
            or _printable(intel.get("target", {}).get("name", ""))
            or ident["gatt_mfr"]
        )
        _maybe_fcc_resolve(intel, fcc_query)
