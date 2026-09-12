"""Static content analysis: secrets, SBOM, licenses, and a CVE join.

This subpackage reads the *contents* of firmware or an unpacked rootfs. It
never unpacks, never touches the network, and always reports evidence with
a confidence so an empty result is a real answer rather than a failure.
"""

from .licenses import scan_licenses
from .sbom import build_sbom, to_cyclonedx, to_spdx
from .secrets import scan_secrets
from .vulns import join_cves, load_mirror

__all__ = [
    "build_sbom",
    "join_cves",
    "load_mirror",
    "scan_licenses",
    "scan_secrets",
    "to_cyclonedx",
    "to_spdx",
]
