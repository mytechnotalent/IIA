![image](https://github.com/mytechnotalent/IIA/blob/main/IIA.png?raw=true)

## FREE Reverse Engineering Self-Study Course [HERE](https://github.com/mytechnotalent/Reverse-Engineering-Tutorial)

<br>

# IoT Intel Audit

A no-sudo blue-team IoT toolkit: audit your LAN (Wi-Fi, BLE, ports, PCAP,
CVE/vendor/FCC intel) and forensically analyze firmware offline (identify,
extract, secrets, SBOM, licenses, component CVEs). Clean JSON and Markdown
out, no root ever.

## Requirements

- **Python 3.10 or newer** (`python3 --version`).
- **No root / sudo ever**; the LAN half talks only to your own network and
  the firmware/static half needs **no network at all**.
- Core is **standard library only**. Optional extras unlock more phases:

| Extra | pip package | Unlocks |
| --- | --- | --- |
| BLE | `bleak` | Bluetooth LE scan + GATT mining |
| PCAP | `scapy` | passive packet forensics |
| zstd codec | `zstandard` | zstd streams and SquashFS zstd blocks |
| lz4 codec | `lz4` | lz4 streams and SquashFS lz4 blocks |
| Dev/test | `pytest`, `coverage` | unit tests and coverage |

Missing extras degrade to a clean `unsupported` result, never a crash. The
tool needs **no external binaries** — every reader is native.

## Setup on a new computer

**macOS** (Wi-Fi/BT phases use built-in `swift`, `airport`,
`system_profiler`, and `dns-sd`; no brew packages required):

```bash
brew install python           # or install from python.org
git clone <repo> IIA && cd IIA
python3 -m venv .venv && source .venv/bin/activate
pip install -e . && pip install bleak scapy zstandard lz4
python3 -m iiatool --help
```

**Ubuntu / Debian** (the firmware/static half is fully cross-platform; the
macOS-only Wi-Fi/BT discovery phases skip gracefully):

```bash
sudo apt update
sudo apt install -y python3 python3-venv python3-pip libpcap-dev bluez
git clone <repo> IIA && cd IIA
python3 -m venv .venv && source .venv/bin/activate
pip install -e . && pip install bleak scapy zstandard lz4
python3 -m iiatool --help
```

**Windows** (Python 3.10+ from python.org, tick "Add to PATH"):

```powershell
py -m venv .venv
.\.venv\Scripts\activate
pip install -e . ; pip install bleak zstandard lz4
py -m iiatool --help
```

`pip install -e .` puts `iiatool` on your PATH; `python3 -m iiatool` always
works. macOS-only phases (Wi-Fi SSID scan via CoreWLAN, Bluetooth Classic,
mDNS) are guarded by availability checks and are skipped on other platforms —
the firmware identification, extraction, secrets, SBOM, license, and CVE
passes run identically everywhere.

### Optional test-fixture tools (developers only)

The test suite synthesizes its own images, so nothing is required to run it.
If you want to generate richer fixtures or extend coverage, these external
tools are optional:

| Tool | macOS | Ubuntu |
| --- | --- | --- |
| SquashFS images | `brew install squashfs` | `apt install squashfs-tools` |
| ext images | `brew install e2fsprogs` | `apt install e2fsprogs` |
| FAT images | `brew install dosfstools` | `apt install dosfstools` |
| ISO images | `brew install cdrtools` | `apt install genisoimage` |
| UPX fixture | `brew install upx` | `apt install upx-ucl` |

## CLI

```bash
# browse every option
python3 -m iiatool --help

# ---- live LAN / radio ----
# network-wide mode: sweep Wi-Fi 2.4/5/6 GHz, BLE, BT Classic, mDNS, ARP hosts,
# audit every discovered address, and write a combined report + info.json
iiatool --all --ble-timeout 8 --info reports/info.json \
        --json reports/all.json --report reports/ALL.md

# single-host audit (active port scan + banner + CVE assessment)
iiatool --target-ip 192.168.1.50 --target-mac 00:11:22:33:44:55

# focused audit (no port scan, custom ports, FCC id lookup)
iiatool --target-ip 192.168.1.50 --no-scan-ports --fcc-id ""
iiatool --target-ip 192.168.1.50 --ports 22,80,443,4200,8443

# ---- offline firmware / image ----
# identify + entropy + UPX + secrets + SBOM + licenses, with recursive unpacking
iiatool --firmware firmware.bin --extract-dir fw.extracted/ --broad \
        --carve-dir carved/ --sbom-out sbom/ \
        --cve-mirror mirror.json \
        --json reports/fw.json --report reports/FW.md
```

### Flags

| Flag | Default | Description |
| --- | --- | --- |
| `--all` | off | Network-wide radio + LAN sweep and combined report |
| `--target-ip` | `` | Single target IPv4 |
| `--target-mac` | `` | Single target MAC |
| `--router-ip` | `192.168.1.1` | Gateway for flow capture / router agent |
| `--ble` | `tovala` | BLE device name filter |
| `--ble-timeout` | `5.0` | BLE scan window in seconds |
| `--pcap` | `tovala.pcap` | PCAP file for passive forensics |
| `--no-scan-ports` | off | Disable the active TCP port scan |
| `--ports` | (default set) | Custom ports, e.g. `22,80,443` or `8000-9000` |
| `--fcc-id` | `` | Resolve a single FCC equipment authorization id |
| `--json` | `reports/iot_intel_report_<ts>.json` | JSON output path |
| `--report` | `reports/IOT_BLUE_TEAM_AUDIT_<ts>.md` | Markdown output path |
| `--info` | `reports/info_<ts>.json` | Discovery inventory (with `--all`) |
| `--firmware` | `` | Offline firmware/rootfs analysis target |
| `--extract-dir` | `` | Recursive extraction destination |
| `--carve-dir` | `` | Raw carve destination |
| `--broad` | off | Load general file-type signatures |
| `--cve-mirror` | `` | Offline advisory mirror JSON for the SBOM CVE join |
| `--sbom-out` | `` | Write CycloneDX + SPDX documents here |

### Network-wide mode (`--all`)

Sweeps all visible Wi-Fi networks, every BLE device, all Bluetooth Classic
peers, mDNS/Bonjour services, and the local `/24` (ICMP ARP-cache sweep plus
router/ARP hosts), then audits every discovered address and writes a combined
Markdown report, a JSON container, and an `info_<ts>.json` discovery
inventory.

### Offline firmware mode (`--firmware`)

Runs the full offline pipeline against a file or an unpacked rootfs:

1. **Identification** — magic/signature scan over fixed and searchable
   offsets with structural validators and a confidence score per finding.
2. **Entropy** — Shannon entropy windows flag unidentified or encrypted
   regions.
3. **Packed executables** — locates UPX-style pack markers, reports the host
   format, and flags zeroed or altered headers.
4. **Extraction** — recursively unpacks supported containers with depth,
   file, byte, and decompression-ratio guards, writing a `manifest.json`.
5. **Carving** — dumps identified regions to raw files.
6. **Secrets** — pattern, structural, and validated credential discovery.
7. **SBOM** — components from package databases, version banners, libc
   filenames, and the kernel banner; emitted as CycloneDX and SPDX.
8. **Licenses** — SPDX identification from tags and license text.
9. **CVEs** — the SBOM joined against a local advisory mirror (offline).

## Supported formats

- **Compression:** gzip, zlib, bzip2, xz/lzma, zstd (optional), lz4 (optional)
- **Archives / images:** tar, zip, cpio (newc/crc/odc), ISO 9660
- **Filesystems:** FAT12/16/32, ext2/3/4, SquashFS v4, JFFS2, UBI volumes
- **Boot / kernel containers:** U-Boot legacy uImage, U-Boot FIT/FDT, Android
  boot, Android sparse
- **Identified (structural) types:** SquashFS, ext, F2FS, XFS, btrfs, HFS+,
  NTFS, exFAT, cramfs, romfs, EROFS, UBIFS, JFFS2, ELF, PE, Mach-O, and more

Identification is always available; extraction is available for the formats
listed as extractable above, and unknown types degrade cleanly.

## Outputs

Written under `reports/` by default:

- `iot_intel_report_<ts>.json` — machine-readable intelligence container
- `IOT_BLUE_TEAM_AUDIT_<ts>.md` — blue-team auditor report
- `info_<ts>.json` — discovery inventory (with `--all`)
- firmware runs additionally emit `manifest.json` (extraction) and, with
  `--sbom-out`, `sbom.cdx.json` + `sbom.spdx.json`

## Modules

| Module | Responsibility |
| --- | --- |
| `utils` | Intel container factory, MAC/OUI helpers, logging |
| `constants` | Knowledge base (defaults, port/CVE/FCC knowledge) |
| `network` | ARP, `/24` sweep, LAN flows, router interrogation, sockets |
| `scan` | Wi-Fi / port / host / Bluetooth discovery and parsing |
| `ble` | BLE telemetry and GATT mining |
| `pcap` | Passive packet forensics (TLS SNI, MQTT topics, IP intel) |
| `vendor` | OUI mapping, FCC grant resolution |
| `cve` | Wi-Fi/BT security assessment + NVD vulnerability lookups |
| `report` | Markdown / JSON exporters |
| `firmware` | Signatures, entropy, carving, UPX, extraction, filesystems |
| `static` | Secrets, SBOM, licenses, offline CVE join |

Inside `firmware`: `signatures`, `entropy`, `carve`, `upx`, `compress`,
`archives`, `filesystems`, `squashfs`, `jffs2`, `ubi`, `containers`,
`extract`. Inside `static`: `secrets`, `sbom`, `licenses`, `vulns`.

## Design notes

- **Never "Unknown"**: every unknown device/network/peer still receives a
  labeled `blue_team_risk_assessment` entry (at minimum INFORMATIONAL), so
  the auditor output never silently drops a target.
- **No hardcoded target specifics**: `DEFAULT_IP` / `DEFAULT_MAC` and the
  FCC-id network lookup are templates; invoke with `--target-ip`,
  `--target-mac`, and `--fcc-id`.
- **No embedded credentials**: tokens, passwords, and live device inventory
  are never shipped in this repository.
- **Offline and deterministic**: the firmware/static half never touches the
  network; identical input yields identical output.
- **Safe on hostile input**: extraction writes through path-traversal-safe
  joins, bounds every read, and caps decompression.

## Secret hygiene

This repository ships a mandatory guardrail skill at
`.opencode/skills/repo-secret-hygiene/`. Before any commit or push:

```bash
python3 .opencode/skills/repo-secret-hygiene/scan_secrets.py --tree
python3 .opencode/skills/repo-secret-hygiene/scan_secrets.py --staged
python3 .opencode/skills/repo-secret-hygiene/scan_secrets.py --history
```

Install the pre-commit hook:

```bash
cp .opencode/skills/repo-secret-hygiene/pre-commit .git/hooks/pre-commit
chmod +x .git/hooks/pre-commit
```

If a secret is ever exposed: **rotate it first**, then purge history.

## Tests

```bash
pip install pytest coverage
python3 -m pytest tests/ -q
python3 -m coverage run -m pytest tests/ -q
python3 -m coverage report --include="iiatool/firmware/*,iiatool/static/*"
```

The firmware and static subpackages are tested against synthetic images built
with the standard library (archives, compression, FAT/ext/SquashFS/UBI/JFFS2,
U-Boot, Android, FDT), so no external tooling is required to run the suite.

<br>

## License

MIT — see [`LICENSE`](LICENSE).
