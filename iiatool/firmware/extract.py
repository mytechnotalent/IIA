"""Recursive, guard-bounded extraction across every supported container."""

import json
import os

from . import archives, containers, filesystems, jffs2, squashfs, ubi
from .compress import decompress
from .signatures import scan_bytes

MAX_DEPTH = 8
MAX_FILES = 10000
MAX_BYTES = 67108864


def _stream(codec: str):
    """
    Build a handler that decompresses a single stream to one file.

    Parameters
    ----------
    codec : str
        Codec name.

    Returns
    -------
    callable
        Handler taking (data, outdir, max_bytes).
    """

    def handler(data: bytes, outdir: str, max_bytes: int) -> list:
        payload = decompress(codec, data, max_bytes)
        if payload is None:
            return []
        return [
            archives._write_file(outdir, codec + ".out", payload, max_bytes)
        ]

    return handler


def _registry() -> dict:
    """
    Map detected signature types to extraction handlers.

    Parameters
    ----------
    None

    Returns
    -------
    dict
        Type name to handler.
    """
    reg = {}
    for name, codec in (
        ("gzip", "gzip"),
        ("zlib", "zlib"),
        ("bzip2", "bzip2"),
        ("xz", "xz"),
        ("lzma", "lzma"),
        ("zstd", "zstd"),
        ("lz4", "lz4"),
    ):
        reg[name] = _stream(codec)
    reg.update(
        {
            "tar": archives.extract_tar,
            "zip": archives.extract_zip,
            "cpio": archives.extract_cpio,
            "cpio-crc": archives.extract_cpio,
            "cpio-odc": archives.extract_cpio,
            "iso9660": archives.extract_iso,
            "ext2/3/4": filesystems.read_ext,
            "squashfs-le": squashfs.read_squashfs,
            "squashfs-be": squashfs.read_squashfs,
            "ubi": ubi.read_ubi,
            "jffs2-le": jffs2.read_jffs2,
            "jffs2-be": jffs2.read_jffs2,
            "u-boot legacy": containers.extract_uimage,
            "fdt": containers.extract_fit,
            "android boot": containers.extract_android_boot,
            "android sparse": containers.extract_sparse,
        }
    )
    return reg


REGISTRY = _registry()

CONTAINER_BACK = {
    "tar": 257,
    "ext2/3/4": 1080,
    "iso9660": 32769,
    "btrfs": 65600,
}


def _container_start(finding: dict) -> int:
    """
    Compute the byte offset where a container actually begins.

    Parameters
    ----------
    finding : dict
        Signature finding (its offset may be a magic inside the header).

    Returns
    -------
    int
        Container start offset.
    """
    back = CONTAINER_BACK.get(finding["type"], 0)
    return max(0, finding["offset"] - back)


def _extractable(findings: list):
    """
    Choose the earliest finding that has a registered handler.

    Parameters
    ----------
    findings : list
        Signature findings.

    Returns
    -------
    dict or None
        Chosen finding.
    """
    for item in sorted(
        findings, key=lambda f: (f["offset"], -f["confidence"])
    ):
        if item["type"] in REGISTRY:
            return item
    return None


def _recurse(path: str, outdir: str, state: dict) -> list:
    """
    Recursively extract a file's innermost supported container.

    Parameters
    ----------
    path : str
        File to inspect.
    outdir : str
        Destination directory.
    state : dict
        Mutable guard counters.

    Returns
    -------
    list
        Manifest entries contributed by this branch.
    """
    if state["depth"] <= 0 or state["files"] >= MAX_FILES:
        return []
    data = _read(path)
    chosen = _extractable(scan_bytes(data))
    if not chosen:
        return []
    return _recurse_chosen(data, chosen, outdir, state)


def _recurse_chosen(
    data: bytes, chosen: dict, outdir: str, state: dict
) -> list:
    """
    Extract a chosen container and recurse into its results.

    Parameters
    ----------
    data : bytes
        Whole blob.
    chosen : dict
        Chosen finding.
    outdir : str
        Destination directory.
    state : dict
        Mutable guard counters.

    Returns
    -------
    list
        Manifest entries.
    """
    start = _container_start(chosen)
    sub = os.path.join(outdir, "{:x}-{}".format(start, chosen["type"]))
    state["depth"] -= 1
    entries = _run(chosen, data[start:], sub, state)
    state["depth"] += 1
    return entries


def _run(finding: dict, data: bytes, outdir: str, state: dict) -> list:
    """
    Dispatch one finding to its handler and recurse into results.

    Parameters
    ----------
    finding : dict
        Chosen finding.
    data : bytes
        Bytes starting at the finding offset.
    outdir : str
        Destination directory.
    state : dict
        Mutable guard counters.

    Returns
    -------
    list
        Manifest entries for this subtree.
    """
    handler = REGISTRY.get(finding["type"])
    if handler is None or state["files"] >= MAX_FILES:
        return []
    try:
        written = handler(data, outdir, MAX_BYTES)
    except (OSError, ValueError, EOFError, MemoryError):
        written = []
    return _descend(written, outdir, state)


def _descend(written: list, outdir: str, state: dict) -> list:
    """
    Account for extracted files and recurse into each.

    Parameters
    ----------
    written : list
        Manifest entries from a handler.
    outdir : str
        Destination directory.
    state : dict
        Mutable guard counters.

    Returns
    -------
    list
        Flattened manifest including nested entries.
    """
    manifest = []
    for entry in written:
        state["files"] += 1
        state["bytes"] += entry.get("size", 0)
        manifest.append(entry)
    for entry in written:
        manifest.extend(_recurse(entry["path"], outdir, state))
    return manifest


def _read(path: str) -> bytes:
    """
    Read a file, returning an empty blob on failure.

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


def extract_tree(path: str, outdir: str, depth: int = MAX_DEPTH) -> dict:
    """
    Identify and recursively extract a firmware image or rootfs directory.

    Parameters
    ----------
    path : str
        File or directory to process.
    outdir : str
        Destination directory.
    depth : int
        Recursion depth cap.

    Returns
    -------
    dict
        Manifest summary with entries written under ``outdir``.
    """
    os.makedirs(outdir, exist_ok=True)
    state = {"depth": depth, "files": 0, "bytes": 0}
    entries = _extract_path(path, outdir, state)
    manifest = {"source": path, "entries": entries, "files": state["files"]}
    _write_manifest(outdir, manifest)
    return manifest


def _extract_path(path: str, outdir: str, state: dict) -> list:
    """
    Extract a file directly or every candidate within a directory.

    Parameters
    ----------
    path : str
        File or directory.
    outdir : str
        Destination directory.
    state : dict
        Mutable guard counters.

    Returns
    -------
    list
        Manifest entries.
    """
    if os.path.isdir(path):
        collected = []
        for name in sorted(os.listdir(path)):
            child = os.path.join(path, name)
            if os.path.isfile(child):
                collected.extend(_recurse(child, outdir, state))
        return collected
    return _recurse(path, outdir, state)


def _write_manifest(outdir: str, manifest: dict) -> None:
    """
    Persist a manifest mapping offsets to extracted paths.

    Parameters
    ----------
    outdir : str
        Destination directory.
    manifest : dict
        Manifest document.

    Returns
    -------
    None
    """
    try:
        with open(os.path.join(outdir, "manifest.json"), "w") as handle:
            json.dump(manifest, handle, indent=2)
    except OSError:
        pass


def identify_and_extract(
    path: str, outdir: str, depth: int = MAX_DEPTH
) -> dict:
    """
    Alias for :func:`extract_tree` used by the CLI and reports.

    Parameters
    ----------
    path : str
        File or directory.
    outdir : str
        Destination directory.
    depth : int
        Recursion depth cap.

    Returns
    -------
    dict
        Manifest summary.
    """
    return extract_tree(path, outdir, depth)
