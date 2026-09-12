"""Bluetooth Low Energy audit functions."""

import asyncio

from .constants import (
    CHR_DEVICE_ID,
    CHR_FIRMWARE,
    CHR_MODEL,
    GATT_CHAR_NAMES,
    GATT_DESCRIPTOR_NAMES,
    GATT_SERVICE_NAMES,
    MANUFACTURER_IDS,
    SRV_DEV_INFO,
)
from .utils import _found, _init_intel, _log, _warn
from .vendor import _auto_vendor_lookup

try:
    import bleak

    HAS_BLEAK = True
except ImportError:
    HAS_BLEAK = False


def _match_ble_name(name: str, pattern: str) -> bool:
    """
    Match candidate BLE name against filter pattern.

    Parameters
    ----------
    name : str
        Observed BLE local name.
    pattern : str
        Target search substring.

    Returns
    -------
    bool
        True when candidate matches filter.
    """
    low = name.lower()
    if pattern:
        return pattern.lower() in low
    return any(k in low for k in ("tovala", "imp", "smart"))


def _find_ble_target(devices: dict, pattern: str) -> tuple:
    """
    Locate first matching BLE device record.

    Parameters
    ----------
    devices : dict
        Mapping of Bleak devices to advertisement data.
    pattern : str
        Search filter substring.

    Returns
    -------
    tuple
        Matched device and advertisement pair.
    """
    for dev, adv in devices.values():
        name = dev.name or adv.local_name or ""
        if _match_ble_name(name, pattern):
            return dev, adv
    return None, None


def _decode_gatt_bytes(val: bytes) -> str:
    """
    Safely decode GATT characteristic byte array.

    Parameters
    ----------
    val : bytes
        Raw bytes returned from GATT read.

    Returns
    -------
    str
        Decoded text or repr.
    """
    try:
        return val.decode("utf-8")
    except UnicodeDecodeError:
        return repr(val)


async def _try_read_char(client: object, uuid: str) -> tuple:
    """
    Attempt to read GATT characteristic.

    Parameters
    ----------
    client : object
        Active client.
    uuid : str
        Characteristic UUID.

    Returns
    -------
    tuple
        Hex string, decoded string, and error string.
    """
    try:
        val = await client.read_gatt_char(uuid)
        return val.hex(), _decode_gatt_bytes(val), None
    except Exception as err:
        return "", "", str(err)


async def _read_one_char(client: object, char: object) -> dict:
    """
    Read individual GATT characteristic values.

    Parameters
    ----------
    client : object
        Active BleakClient connection.
    char : object
        GATT characteristic descriptor.

    Returns
    -------
    dict
        Hex and ASCII representation plus descriptors.
    """
    info = _char_info(char)
    if "read" in char.properties:
        hx, asc, err = await _try_read_char(client, char.uuid)
        info["hex"], info["ascii"], info["err"] = hx, asc, err
    if getattr(char, "descriptors", None):
        info["descriptors"] = await _read_descriptors(
            client, char.descriptors
        )
    return info


def _char_info(char: object) -> dict:
    """
    Build the base characteristic record.

    Parameters
    ----------
    char : object
        GATT characteristic.

    Returns
    -------
    dict
        Characteristic metadata.
    """
    return {
        "uuid": char.uuid,
        "name": GATT_CHAR_NAMES.get(char.uuid, ""),
        "props": list(char.properties),
    }


async def _read_descriptors(client: object, descriptors) -> dict:
    """
    Read every descriptor of a characteristic.

    Parameters
    ----------
    client : object
        Active BleakClient connection.
    descriptors : iterable
        GATT descriptors.

    Returns
    -------
    dict
        Descriptor UUID to record.
    """
    out = {}
    for desc in descriptors:
        out[desc.uuid] = await _read_descriptor(client, desc)
    return out


async def _read_descriptor(client: object, desc: object) -> dict:
    """
    Read one GATT descriptor value.

    Parameters
    ----------
    client : object
        Active BleakClient connection.
    desc : object
        GATT descriptor.

    Returns
    -------
    dict
        Descriptor record.
    """
    entry = {
        "uuid": desc.uuid,
        "name": GATT_DESCRIPTOR_NAMES.get(desc.uuid, ""),
    }
    try:
        value = await client.read_gatt_descriptor(desc.handle)
        entry["hex"] = value.hex()
        entry["ascii"] = _decode_gatt_bytes(value)
    except Exception as err:
        entry["err"] = str(err)
    return entry


async def _dump_service_chars(client: object, srv: object) -> dict:
    """
    Dump characteristics for one service.

    Parameters
    ----------
    client : object
        Active BleakClient connection.
    srv : object
        BLE GATT service object.

    Returns
    -------
    dict
        Characteristic mapping.
    """
    chars = {}
    for ch in srv.characteristics:
        chars[ch.uuid] = await _read_one_char(client, ch)
    return chars


async def _dump_gatt_services(client: object) -> dict:
    """
    Traverse all services on connected BLE peripheral.

    Parameters
    ----------
    client : object
        Active BleakClient connection.

    Returns
    -------
    dict
        Nested service and characteristic map.
    """
    dump = {}
    for srv in client.services:
        dump[srv.uuid] = {
            "name": GATT_SERVICE_NAMES.get(srv.uuid, ""),
            "chars": await _dump_service_chars(client, srv),
        }
    return dump


def _char_ascii(chars: dict, uuid: str) -> str:
    """
    Fetch ASCII value of characteristic.

    Parameters
    ----------
    chars : dict
        Characteristic map.
    uuid : str
        Target UUID.

    Returns
    -------
    str
        Decoded ASCII value or None.
    """
    return chars.get(uuid, {}).get("ascii")


def _extract_device_info(gatt_dump: dict) -> dict:
    """
    Extract standard 0x180A device metadata plus deep device identifiers.

    Parameters
    ----------
    gatt_dump : dict
        Complete GATT traversal map.

    Returns
    -------
    dict
        Parsed model, firmware, serial, manufacturer, PnP and device ID.
    """
    ch = gatt_dump.get(SRV_DEV_INFO, {}).get("chars", {})
    return {
        "model": _char_ascii(ch, CHR_MODEL),
        "firmware": _char_ascii(ch, CHR_FIRMWARE),
        "dev_id": _char_ascii(ch, CHR_DEVICE_ID),
        "manufacturer": _char_ascii(
            ch, "00002a29-0000-1000-8000-00805f9b34fb"
        ),
        "hardware_rev": _char_ascii(
            ch, "00002a27-0000-1000-8000-00805f9b34fb"
        ),
        "software_rev": _char_ascii(
            ch, "00002a28-0000-1000-8000-00805f9b34fb"
        ),
        "system_id": _char_ascii(ch, "00002a23-0000-1000-8000-00805f9b34fb"),
        "pnp_id": _char_ascii(ch, "00002a50-0000-1000-8000-00805f9b34fb"),
    }


def _decode_manufacturer_data(manufacturer_data: dict) -> list:
    """
    Decode BLE manufacturer-specific advertisement payloads.

    Parameters
    ----------
    manufacturer_data : dict
        Raw company-ID to bytes mapping.

    Returns
    -------
    list
        Decoded manufacturer records.
    """
    decoded = []
    for company_id, data in (manufacturer_data or {}).items():
        decoded.append(_manuf_record(company_id, data))
    return decoded


def _manuf_hex(data: object) -> str:
    """
    Render manufacturer data bytes as hexadecimal.

    Parameters
    ----------
    data : object
        Raw manufacturer data.

    Returns
    -------
    str
        Hex string.
    """
    if isinstance(data, (bytes, bytearray, memoryview)):
        return bytes(data).hex()
    return str(data)


def _manuf_record(company_id, data) -> dict:
    """
    Build one manufacturer-data record.

    Parameters
    ----------
    company_id : int
        Bluetooth company identifier.
    data : object
        Raw manufacturer data.

    Returns
    -------
    dict
        Decoded record.
    """
    ascii_value = (
        _decode_gatt_bytes(bytes(data)) if isinstance(data, bytes) else ""
    )
    return {
        "company_id": f"0x{int(company_id):04X}",
        "company": MANUFACTURER_IDS.get(int(company_id), "Unknown"),
        "hex": _manuf_hex(data),
        "ascii": ascii_value,
    }


def _format_adv_value(value: object) -> object:
    """
    Normalize an advertisement value for JSON output.

    Parameters
    ----------
    value : object
        Raw attribute value from AdvertisementData.

    Returns
    -------
    object
        JSON-safe representation.
    """
    if isinstance(value, bytes):
        return {"hex": value.hex(), "ascii": _decode_gatt_bytes(value)}
    if isinstance(value, (bytearray, memoryview)):
        return {"hex": bytes(value).hex()}
    return value


def _adv_payload(adv: object, name: str) -> dict:
    """
    Extract every useful advertisement field from a BLE scan.

    Parameters
    ----------
    adv : object
        Bleak AdvertisementData.
    name : str
        Best-effort device name.

    Returns
    -------
    dict
        Complete advertisement record.
    """
    return {
        "name": name,
        "rssi": getattr(adv, "rssi", None),
        "tx_power": getattr(adv, "tx_power", None),
        "appearance": getattr(adv, "appearance", None),
        "connectable": getattr(adv, "connectable", None),
        "anonymous": getattr(adv, "is_anonymous", None),
        "active": getattr(adv, "active", None),
        "service_uuids": [
            str(u) for u in getattr(adv, "service_uuids", []) or []
        ],
        "manufacturer_data": _decode_manufacturer_data(
            getattr(adv, "manufacturer_data", {}) or {}
        ),
        "service_data": {
            str(u): _format_adv_value(d)
            for u, d in (getattr(adv, "service_data", {}) or {}).items()
        },
    }


def _extract_survey_lines(val: str) -> list:
    """
    Split and clean survey SSID strings.

    Parameters
    ----------
    val : str
        Raw characteristic value.

    Returns
    -------
    list
        Extracted SSIDs.
    """
    if "locked" not in val or "\n" not in val:
        return []
    lines = [item.strip() for item in val.split("\n")]
    return [x for x in lines if x and x != "locked"]


def _check_ssid_leakage(gatt_dump: dict) -> list:
    """
    Detect plain-text Wi-Fi SSID lists in GATT attributes.

    Parameters
    ----------
    gatt_dump : dict
        Traversed GATT tree.

    Returns
    -------
    list
        Discovered leaked SSIDs.
    """
    leaked = []
    for srv in gatt_dump.values():
        for ch in srv.get("chars", {}).values():
            ssids = _extract_survey_lines(ch.get("ascii", ""))
            leaked.extend(ssids)
    return leaked


def _record_leakage_risk(intel: dict, leaked: list) -> None:
    """
    Append medium-severity finding for SSID leakage.

    Parameters
    ----------
    intel : dict
        Intelligence container.
    leaked : list
        List of leaked SSID strings.

    Returns
    -------
    None
    """
    _warn(f"Leaked Wi-Fi SSIDs in BLE characteristic: {leaked}")
    d = f"Visible local SSIDs exposed unauthenticated: {leaked}"
    intel["blue_team_risk_assessment"].append(
        {
            "severity": "MEDIUM",
            "vuln": "BLE Wi-Fi Survey Leakage",
            "detail": d,
        }
    )


async def _store_ble_results(intel: dict, dump: dict) -> None:
    """
    Store extracted BLE attributes.

    Parameters
    ----------
    intel : dict
        Intelligence state dictionary.
    dump : dict
        Traversed GATT tree.

    Returns
    -------
    None
    """
    info = _extract_device_info(dump)
    intel["ble_telemetry"]["device_info"] = info
    intel["ble_telemetry"]["gatt"] = dump
    _auto_vendor_lookup(intel, intel["target"]["mac"])
    _announce_info(info)
    leaked = _check_ssid_leakage(dump)
    if leaked:
        _record_leakage_risk(intel, leaked)


def _announce_info(info: dict) -> None:
    """
    Log the discovered device identity fields.

    Parameters
    ----------
    info : dict
        Device information.

    Returns
    -------
    None
    """
    _found(f"Device ID: {info.get('dev_id')}")
    labels = {
        "Model": info.get("model"),
        "Manufacturer": info.get("manufacturer"),
        "Firmware": info.get("firmware"),
    }
    for label, value in labels.items():
        if value:
            _found(f"{label}: {value}")


async def _interrogate_ble_target(intel: dict, dev: object) -> None:
    """
    Establish GATT connection and harvest attributes.

    Parameters
    ----------
    intel : dict
        Intelligence state dictionary.
    dev : object
        Bleak discovered device.

    Returns
    -------
    None
    """
    async with bleak.BleakClient(dev.address, timeout=10.0) as client:
        _found(f"Connected to BLE GATT: {dev.address}")
        dump = await _dump_gatt_services(client)
        await _store_ble_results(intel, dump)


async def _connect_target(intel: dict, dev: object, adv: object) -> None:
    """
    Record advertisement and connect to target.

    Parameters
    ----------
    intel : dict
        Intelligence container.
    dev : object
        Bleak device object.
    adv : object
        Bleak advertisement data.

    Returns
    -------
    None
    """
    name = dev.name or adv.local_name or "Unknown"
    _found(f"Discovered BLE: {name} ({dev.address}) | {adv.rssi} dBm")
    intel["ble_telemetry"]["adv"] = _adv_payload(adv, name)
    try:
        await _interrogate_ble_target(intel, dev)
    except Exception as err:
        _warn(f"GATT connection failed: {err}")


async def _scan_ble_pipeline(intel: dict, pat: str, timeout: float) -> None:
    """
    Execute asynchronous BLE scan and attribute dump.

    Parameters
    ----------
    intel : dict
        Intelligence container.
    pat : str
        Target search substring.
    timeout : float
        Scan window duration in seconds.

    Returns
    -------
    None
    """
    _log("BLE", f"Discovering BLE devices (timeout: {timeout}s)...")
    devs = await bleak.BleakScanner.discover(timeout=timeout, return_adv=True)
    dev, adv = _find_ble_target(devs, pat)
    if dev:
        await _connect_target(intel, dev, adv)
    else:
        _warn("Target BLE device not discovered in local radius")


def _audit_bluetooth(intel: dict, pattern: str, timeout: float) -> None:
    """
    Run Bluetooth LE examination wrapper.

    Parameters
    ----------
    intel : dict
        Intelligence container.
    pattern : str
        BLE name filter.
    timeout : float
        Scan duration in seconds.

    Returns
    -------
    None
    """
    if not HAS_BLEAK:
        _warn("Bleak library unavailable; skipping BLE audit")
        return
    asyncio.run(_scan_ble_pipeline(intel, pattern, timeout))


async def _audit_all_ble_async(timeout: float) -> tuple:
    """
    Discover and interrogate every visible BLE device.

    Parameters
    ----------
    timeout : float
        Scan window duration in seconds.

    Returns
    -------
    tuple
        Inventory list and per-device audit records.
    """
    devices = await _discover_all(timeout)
    if devices is None:
        return [], []
    _found(f"BLE discovery: {len(devices)} devices visible")
    return await _audit_devices(devices)


async def _discover_all(timeout: float):
    """
    Discover every visible BLE device, or None on scan failure.

    Parameters
    ----------
    timeout : float
        Scan window duration in seconds.

    Returns
    -------
    dict or None
        Device mapping or None.
    """
    try:
        return await bleak.BleakScanner.discover(
            timeout=timeout, return_adv=True
        )
    except Exception as err:
        _warn(f"BLE scan failed: {err}")
        return None


async def _audit_devices(devices: dict) -> tuple:
    """
    Audit every discovered BLE device.

    Parameters
    ----------
    devices : dict
        Mapping of devices to advertisement data.

    Returns
    -------
    tuple
        Inventory list and per-device audit records.
    """
    inventory = []
    audits = []
    for address, pair in devices.items():
        audit = await _audit_one(address, pair)
        inventory.append(audit["inventory"])
        audits.append(audit["intel"])
    return inventory, audits


async def _connect_safe(intel: dict, dev: object, adv: object) -> None:
    """
    Connect to a device, tolerating failures.

    Parameters
    ----------
    intel : dict
        Intelligence container.
    dev : object
        BLE device.
    adv : object
        Advertisement data.

    Returns
    -------
    None
    """
    try:
        await _connect_target(intel, dev, adv)
    except Exception as err:
        _warn(f"BLE audit failed for {intel['target'].get('name', '')}: {err}")


async def _audit_one(address: str, pair: tuple) -> dict:
    """
    Audit one BLE device and return its inventory and intel records.

    Parameters
    ----------
    address : str
        Device address.
    pair : tuple
        (device, advertisement data).

    Returns
    -------
    dict
        Inventory and intel records.
    """
    dev, adv = pair
    name = dev.name or adv.local_name or "Unknown"
    intel = _new_ble_intel(address, name)
    await _connect_safe(intel, dev, adv)
    inventory = {
        "name": name,
        "address": address,
        "adv": _adv_payload(adv, name),
    }
    return {"inventory": inventory, "intel": intel}


def _new_ble_intel(address: str, name: str) -> dict:
    """
    Create a BLE device intelligence container.

    Parameters
    ----------
    address : str
        Device address.
    name : str
        Device name.

    Returns
    -------
    dict
        Intelligence container.
    """
    intel = _init_intel("", address)
    intel["device_type"] = "ble"
    intel["target"]["name"] = name
    _log("BLE", f"Auditing device: {name} ({address})")
    return intel


def _audit_all_bluetooth(timeout: float) -> tuple:
    """
    Run full BLE interrogation across all visible devices.

    Parameters
    ----------
    timeout : float
        BLE scan duration.

    Returns
    -------
    tuple
        Inventory list and audit records.
    """
    if not HAS_BLEAK:
        _warn("Bleak unavailable; BLE discovery skipped")
        return [], []
    return asyncio.run(_audit_all_ble_async(timeout))
