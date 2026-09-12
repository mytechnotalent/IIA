"""Firmware-aware SBOM discovery and CycloneDX/SPDX emission (offline)."""

import os
import re

DB_FILES = (
    "/usr/lib/opkg/status",
    "/var/lib/opkg/status",
    "/var/lib/dpkg/status",
    "/lib/apk/db/installed",
)

BANNERS = (
    ("openssl", "openssl", re.compile(rb"OpenSSL\s+(\d+\.\d+\.\d+[a-z]?)")),
    ("busybox", "busybox", re.compile(rb"BusyBox\s+v(\d+\.\d+\.\d+)")),
    ("dropbear", "dropbear", re.compile(rb"dropbear[_ ]?v?(\d{4}\.\d+)")),
    ("openssh", "openbsd", re.compile(rb"OpenSSH[_ ](\d+\.\d+)")),
    ("zlib", "zlib", re.compile(rb"zlib[/ ](\d+\.\d+\.\d+)")),
    ("curl", "haxx", re.compile(rb"curl[/ ](\d+\.\d+\.\d+)")),
    ("dnsmasq", "dnsmasq", re.compile(rb"dnsmasq[-\s](\d+\.\d+)")),
    ("nginx", "nginx", re.compile(rb"nginx/(\d+\.\d+\.\d+)")),
    ("lighttpd", "lighttpd", re.compile(rb"lighttpd/(\d+\.\d+\.\d+)")),
    ("sqlite", "sqlite", re.compile(rb"SQLite\s+(\d+\.\d+\.\d+)")),
    ("uclibc", "uclibc", re.compile(rb"uClibc[-\s](\d+\.\d+\.\d+)")),
)

LIBNAMES = (
    ("libc", "gnu", re.compile(rb"libc-(\d+\.\d+)\.so")),
    ("libc", "gnu", re.compile(rb"libc\.so\.(\d+)")),
    ("uclibc", "uclibc", re.compile(rb"libuClibc[.-](\d+\.\d+\.\d+)")),
    ("musl", "musl", re.compile(rb"ld-musl-[^-]+\.so\.(\d+)")),
)

KERNEL = re.compile(rb"Linux version (\d+\.\d+\.\d+)")


def _parse_status(text: str) -> list:
    """
    Parse opkg/dpkg status or apk installed content.

    Parameters
    ----------
    text : str
        Package database text.

    Returns
    -------
    list
        Components with name, version, and source.
    """
    components = []
    state = {"name": None, "version": None, "source": _status_source(text)}
    for line in text.splitlines():
        _status_line(line, state, components)
    if state["name"] and state["version"]:
        components.append(_component(state))
    return components


def _status_source(text: str) -> str:
    """
    Infer the package database family from its content.

    Parameters
    ----------
    text : str
        Package database text.

    Returns
    -------
    str
        Source label.
    """
    return "dpkg" if "Status:" in text else "opkg"


def _status_package(line: str, state: dict) -> None:
    """
    Record a package name line into the parser state.

    Parameters
    ----------
    line : str
        Package name line.
    state : dict
        Mutable parser state.

    Returns
    -------
    None
    """
    state["name"] = line.split(":", 1)[1].strip()
    if line.startswith("P:"):
        state["source"] = "apk"


def _status_line(line: str, state: dict, components: list) -> None:
    """
    Apply one status line to the parser state.

    Parameters
    ----------
    line : str
        Input line.
    state : dict
        Mutable parser state.
    components : list
        Accumulated components.

    Returns
    -------
    None
    """
    if line.startswith(("Package:", "P:")):
        _status_package(line, state)
    elif line.startswith(("Version:", "V:")):
        state["version"] = line.split(":", 1)[1].strip()
    elif not line.strip() and state["name"] and state["version"]:
        components.append(_component(state))
        state["name"] = state["version"] = None


def _component(state: dict) -> dict:
    """
    Build a component record from parser state.

    Parameters
    ----------
    state : dict
        Parser state.

    Returns
    -------
    dict
        Component record.
    """
    return {
        "name": state["name"],
        "version": state["version"],
        "source": state["source"],
    }


def _banner_components(data: bytes) -> list:
    """
    Recover components from version strings embedded in a binary.

    Parameters
    ----------
    data : bytes
        File content.

    Returns
    -------
    list
        Components.
    """
    found = []
    for name, vendor, regex in BANNERS:
        for match in set(regex.findall(data)):
            found.append(
                {
                    "name": name,
                    "vendor": vendor,
                    "version": match.decode("ascii", "ignore"),
                    "source": "binary-banner",
                }
            )
    return found


def _libc_components(name: str) -> list:
    """
    Recover a libc component from a versioned library filename.

    Parameters
    ----------
    name : str
        File basename.

    Returns
    -------
    list
        Components.
    """
    raw = name.encode()
    found = []
    for product, vendor, regex in LIBNAMES:
        match = regex.search(raw)
        if match:
            found.append(
                {
                    "name": product,
                    "vendor": vendor,
                    "version": match.group(1).decode("ascii", "ignore"),
                    "source": "libc-filename",
                }
            )
    return found


def _kernel_component(data: bytes) -> list:
    """
    Recover the kernel version from a version banner.

    Parameters
    ----------
    data : bytes
        File content.

    Returns
    -------
    list
        Components.
    """
    match = KERNEL.search(data)
    if not match:
        return []
    return [
        {
            "name": "linux",
            "vendor": "linux",
            "version": match.group(1).decode("ascii", "ignore"),
            "source": "kernel-banner",
        }
    ]


def _merge(components: list) -> list:
    """
    De-duplicate components by (name, version), keeping provenance.

    Parameters
    ----------
    components : list
        Raw components.

    Returns
    -------
    list
        Merged components with a sources list.
    """
    merged = {}
    for item in components:
        key = (item["name"], item.get("version", ""))
        entry = merged.setdefault(
            key,
            {
                "name": item["name"],
                "vendor": item.get("vendor", ""),
                "version": item.get("version", ""),
                "sources": [],
            },
        )
        entry["sources"].append(item.get("source", ""))
    return sorted(merged.values(), key=lambda c: (c["name"], c["version"]))


def _purl(component: dict) -> str:
    """
    Build a package URL for a component.

    Parameters
    ----------
    component : dict
        Component.

    Returns
    -------
    str
        purl string (without trailing version when absent).
    """
    base = "pkg:generic/" + (component.get("name") or "unknown")
    return (
        base + "@" + component["version"] if component.get("version") else base
    )


def _cpe(component: dict) -> str:
    """
    Build a CPE 2.3 string for a component.

    Parameters
    ----------
    component : dict
        Component.

    Returns
    -------
    str
        CPE string.
    """
    vendor = component.get("vendor") or component.get("name") or "*"
    name = component.get("name") or "*"
    version = component.get("version") or "*"
    return "cpe:2.3:a:{}:{}:{}:*:*:*:*:*:*:*".format(vendor, name, version)


def build_sbom(path: str) -> dict:
    """
    Discover components from a file or an unpacked rootfs directory.

    Parameters
    ----------
    path : str
        File or directory.

    Returns
    -------
    dict
        Merged components with purl and cpe fields.
    """
    raw = []
    for target in _iter_files(path):
        raw.extend(_from_file(target))
    components = _merge(raw)
    for component in components:
        component["purl"] = _purl(component)
        component["cpe"] = _cpe(component)
    return {"path": path, "components": components, "count": len(components)}


def _from_file(target: str) -> list:
    """
    Extract components from one file.

    Parameters
    ----------
    target : str
        File path.

    Returns
    -------
    list
        Components.
    """
    name = os.path.basename(target)
    if name in ("status", "installed"):
        return _read_status(target)
    data = _read_binary(target)
    if data is None:
        return []
    return (
        _banner_components(data)
        + _libc_components(name)
        + _kernel_component(data)
    )


def _read_status(target: str) -> list:
    """
    Parse a package database file.

    Parameters
    ----------
    target : str
        File path.

    Returns
    -------
    list
        Components.
    """
    try:
        with open(target, "r", encoding="utf-8", errors="ignore") as handle:
            return _parse_status(handle.read())
    except OSError:
        return []


def _read_binary(target: str):
    """
    Read a bounded binary slice, or None on failure.

    Parameters
    ----------
    target : str
        File path.

    Returns
    -------
    bytes or None
        File bytes.
    """
    try:
        with open(target, "rb") as handle:
            return handle.read(4_000_000)
    except OSError:
        return None


def _iter_files(path: str):
    """
    Yield files under a path.

    Parameters
    ----------
    path : str
        File or directory.

    Yields
    ------
    str
        File paths.
    """
    if os.path.isfile(path):
        yield path
        return
    for dirpath, _dirs, names in os.walk(path):
        for name in names:
            yield os.path.join(dirpath, name)


def to_cyclonedx(sbom: dict) -> dict:
    """
    Render a discovered SBOM as a minimal CycloneDX 1.5 document.

    Parameters
    ----------
    sbom : dict
        Result of :func:`build_sbom`.

    Returns
    -------
    dict
        CycloneDX document.
    """
    return {
        "bomFormat": "CycloneDX",
        "specVersion": "1.5",
        "version": 1,
        "components": [
            {
                "type": "library",
                "name": component["name"],
                "version": component["version"],
                "purl": component["purl"],
                "cpe": component["cpe"],
            }
            for component in sbom.get("components", [])
        ],
    }


def to_spdx(sbom: dict) -> dict:
    """
    Render a discovered SBOM as a minimal SPDX 2.3 document.

    Parameters
    ----------
    sbom : dict
        Result of :func:`build_sbom`.

    Returns
    -------
    dict
        SPDX document.
    """
    packages = []
    for index, component in enumerate(sbom.get("components", []), 1):
        packages.append(
            {
                "name": component["name"],
                "versionInfo": component["version"],
                "SPDXID": "SPDXRef-Package-{}".format(index),
                "externalRefs": [
                    {
                        "referenceCategory": "PACKAGE-MANAGER",
                        "referenceType": "purl",
                        "referenceLocator": component["purl"],
                    }
                ],
            }
        )
    return {
        "spdxVersion": "SPDX-2.3",
        "dataLicense": "CC0-1.0",
        "SPDXID": "SPDXRef-DOCUMENT",
        "name": sbom.get("path", "firmware"),
        "packages": packages,
    }
