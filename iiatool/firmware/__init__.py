"""Firmware identification, entropy, carving, and extraction for IIA.

This subpackage implements structural firmware analysis natively: a
signature engine that reports byte offsets, types, and confidence; an
entropy pass for unidentified or encrypted regions; raw carving; UPX
pack-header detection; and recursive, guard-bounded extraction of archives,
compression streams, boot containers, and filesystems. It performs no
network access and never requires root.
"""

from .carve import carve_findings
from .entropy import entropy_pass
from .extract import extract_tree, identify_and_extract
from .jffs2 import read_jffs2
from .signatures import scan_bytes, scan_file
from .squashfs import read_squashfs
from .ubi import read_ubi
from .upx import detect_upx

__all__ = [
    "carve_findings",
    "detect_upx",
    "entropy_pass",
    "extract_tree",
    "identify_and_extract",
    "read_jffs2",
    "read_squashfs",
    "read_ubi",
    "scan_bytes",
    "scan_file",
]
