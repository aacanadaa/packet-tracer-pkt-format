# packet-tracer-pkt-format

Read, write, and generate Cisco Packet Tracer `.pkt` labs and `.pka` activities offline, without Packet Tracer installed.

This repo documents the Packet Tracer file format (both legacy PT 4.1–5.3.2 and modern PT 5.3.3–9.0.1 containers) and provides a byte-exact Python library (`pkt_core`), CLI (`pkt`), and offline lab builder that writes devices, modules, cables, IOS configs, PC IPs, instructions, activity-wizard passwords, and scoring trees directly to `.pkt`/`.pka` files.

<img src="https://raw.githubusercontent.com/aacanadaa/large-scale-packet-tracer/main/docs/iruma/img/pt_full_topology.png" alt="392-device Packet Tracer enterprise topology generated from code and opened in Packet Tracer 9.0.1" width="100%">

*Generated from code and opened in Packet Tracer 9.0.1 ([IRUMA-AB and Y-AMLT models](https://github.com/aacanadaa/large-scale-packet-tracer): 386 and 392 devices, 752 links, 28,073 config lines across 12 tiers).*

[![PyPI](https://img.shields.io/pypi/v/packet-tracer-pkt-format.svg)](https://pypi.org/project/packet-tracer-pkt-format/)
[![Docs](https://img.shields.io/badge/docs-aacanadaa.github.io-4c1.svg)](https://aacanadaa.github.io/packet-tracer-pkt-format/)
[![License: GPL v3](https://img.shields.io/badge/license-GPLv3-blue.svg)](LICENSE)
[![Ko-fi](https://img.shields.io/badge/Ko--fi-Support%20me-ff5e5b?logo=kofi&logoColor=white)](https://ko-fi.com/suoim)
[![Python 3.10+](https://img.shields.io/badge/python-3.10%2B-blue.svg)](https://www.python.org/)
[![No Packet Tracer needed](https://img.shields.io/badge/Packet_Tracer-not_required-32d74b.svg)](#quickstart)
[![Cisco Packet Tracer](https://img.shields.io/badge/Cisco_Packet_Tracer-1BA0D7?style=flat&logo=cisco&logoColor=white)](#format-support)

**Languages:** English | [简体中文](README.zh-CN.md)

<p align="center">
  <img src="https://count.getloli.com/@aacanadaa-pkt-format?name=aacanadaa-pkt-format&theme=moebooru&padding=8&offset=0&align=top&scale=1.3&pixelated=1&darkmode=auto" alt="Visitors"/>
</p>

## Install

```console
$ pip install packet-tracer-pkt-format
```

Requires Python 3.10+ and `pydantic`. No Packet Tracer installation, compiler, or system crypto library is required. Pure-Python Twofish, Serpent, and CAST-256 implementations are built in; if `libgcrypt` or the optional Rust extension (`native/pkt_core_native/`) is installed, they are used automatically for speed.

## Quickstart

Inspect, unpack, and repack an existing `.pkt` or `.pka` file:

```console
$ pkt info my_lab.pkt
$ pkt export my_lab.pkt --format graphviz -o topology.dot
$ pkt unpack my_lab.pkt -o out/
$ pkt pack out/my_lab.xml -o rebuilt.pkt
```

Read a lab from Python:

```python
from pkt_core import decode
from pkt_core.models import Lab

lab = Lab.from_bytes(decode("my_lab.pkt").xml)
print(len(lab.devices), "devices,", len(lab.links), "links")
for dev in lab.devices:
    print(dev.name, dev.kind, dev.model)
```

## Building labs offline

`pkt_core.Lab` bundles a seed document and 137 device templates, so you can build `.pkt` files right after `pip install`:

```python
from pkt_core import Lab

lab = Lab()
lab.prune_seed_devices()
r  = lab.add_device("2911", "R1", 250, 350, install="HWIC-2T",
                    ios_config=["interface GigabitEthernet0/0",
                                " ip address 192.168.1.1 255.255.255.0", " no shutdown", "end"])
sw = lab.add_device("2960-24TT", "SW1", 450, 350)
pc = lab.add_device("PC-PT", "PC1", 650, 350,
                    pc_ip=("192.168.1.10", "255.255.255.0", "192.168.1.1"))
lab.link(r, "GigabitEthernet0/0", sw, "GigabitEthernet0/1")
lab.link(sw, "FastEthernet0/1", pc, "FastEthernet0")
lab.save("my_lab.pkt")
```

From a repo checkout, you can also generate scored `.pka` activities from a JSON topology spec using [`tools/`](tools):

```console
$ python3 tools/make_scored_lab.py --out mylab.pka --spec topology.json --password hunter2
```

## Container format overview

Modern `.pkt`/`.pka` files have no magic header and are encrypted end to end:

```text
.pkt -> [ byte reverse + XOR ] -> [ Twofish-EAX, key=0x89*16, iv=0x10*16 ] ->
        [ XOR (len - i) ] -> [ Qt qCompress (4-byte BE len + zlib) ] -> UTF-8 XML
```

- **Cipher**: Twofish in Crypto++ EAX mode (128-bit key `0x89 * 16`, IV `0x10 * 16`, 16-byte trailing tag).
- **Outer obfuscation (layer A)**: reverse bytes and XOR with `(n * (1 - i)) & 0xff`.
- **Inner obfuscation (layer B)**: XOR each byte with `(len - i) & 0xff`.
- **Payload**: Qt `qCompress` wrapping UTF-8 XML (`<PACKETTRACER5>` or `<PACKETTRACER5_ACTIVITY>`).

See [FORMAT.md](FORMAT.md) for the key table and reverse-engineering notes, and [docs/FORMAT_SPECIFICATION.md](docs/FORMAT_SPECIFICATION.md) for the full spec covering both modern and legacy containers.

## Python API (`pkt_core`)

```python
from pkt_core import decode, encode_bytes

container = decode("lab.pkt")          # format detected via EAX tag / legacy probe
print(container.root_tag)              # 'PACKETTRACER5'
print(container.is_activity)           # False (.pka -> PACKETTRACER5_ACTIVITY)

rebuilt = encode_bytes(container.xml, container.format_name)
```

| Module | What it does |
| --- | --- |
| `pkt_core.crypto.primitives` | CMAC (RFC 4493), big-endian CTR, Crypto++ EAX |
| `pkt_core.crypto.keys` | Per-format cipher, key byte, and IV byte definitions |
| `pkt_core.crypto.stream` | Layer A and Layer B obfuscation |
| `pkt_core.crypto.ciphers_pure` | Pure-Python Twofish, Serpent, and CAST-256 |
| `pkt_core.codec.qcompress` | Qt `qCompress` / `qUncompress` framing |
| `pkt_core.codec.container` | Format detection, decode, and encode |
| `pkt_core.xml` | Lazy, byte-preserving XML parser (tolerates PT quirks and embedded HTML) |
| `pkt_core.models` | Typed views (`Lab`, `Device`, `Port`, `Link`, `Cluster`, `RunningConfig`, services) |
| `pkt_core.builder` | Offline lab builder (`Lab`, `Layout`) |
| `pkt_core.resources` | Bundled device/module template library and seed XML |
| `pkt_core.audit` | Service inventory, duplicate detection, and template-leftover sanitizer |
| `pkt_core.diff` | Semantic device, link, and running-config diff |
| `pkt_core.export` | Graphviz DOT, NetBox JSON, and containerlab YAML export |
| `pkt_core.errors` | Package exception hierarchy |

Models wrap the underlying `XmlElement` nodes directly, so untouched sections serialize back verbatim and unknown tags remain accessible via `extra_fields`. IOS `<LINE>` entries stay as `bytes` to preserve raw control characters (like `\x03` in `banner motd ^C...^C`).

Sample containers generated by this repo live in [`corpus/samples/`](corpus/samples/) for out-of-the-box testing. Third-party corpus files used during analysis are not committed; see [`corpus/README.md`](corpus/README.md) and [`corpus/fetch_corpus.py`](corpus/fetch_corpus.py).

## CLI usage

```console
$ pkt info    my_lab.pkt                      # container metadata, size, root tag
$ pkt unpack  my_lab.pkt -o out/              # XML, per-device IOS configs, topology
$ pkt pack    out/my_lab.xml -o rebuilt.pkt   # repack XML into a container
$ pkt diff    before.pkt after.pkt            # semantic diff
$ pkt export  my_lab.pkt --format graphviz    # graphviz / netbox / containerlab
$ pkt audit   my_lab.pkt --templates tools/device_templates.json
```

From a repo checkout, the standalone `pt9.py` script (which binds `libgcrypt` directly and is not part of the PyPI package) is also available:

```console
$ python3 pt9.py info   my_lab.pkt
$ python3 pt9.py decode my_lab.pkt -o my_lab.xml
$ python3 pt9.py encode my_lab.xml -o my_lab.pkt
$ pytest tests/
```

### Auditing generated labs (`pkt audit`)

Harvested device templates carry leftover service records (such as default AAA clients, `serverPool` DHCP pools, or default FTP accounts). `pkt audit` reports raw vs. distinct counts for devices, IPs, config lines, and services, flags template leftovers when `--templates` is provided, and exits non-zero on duplicates:

```console
$ pkt audit JASDF_AEWC_JADGE.pkt --templates tools/device_templates.json
device_names: 290 raw, 290 distinct
config lines  : min=78 median=143 max=250 total=22,648 (143 IOS/ASA devices,
                by model); 22,896 <LINE> elements in 205 RUNNINGCONFIG blocks
services      : 496 DNS records (248 distinct x 2 servers)
  aaa_clients: 202 raw, 140 distinct, 62 duplicate instances
               (e.g. 192.168.10.1 x63), 63 template leftovers -> 139 authored
  dhcp_pools : 259 raw, 133 distinct, 126 duplicate instances
               (e.g. serverPool / 0.0.0.0 / 0.0.0.0 x65), 128 template leftovers
  ...
RESULT: FAILED (15 failures, 0 warnings)
```

## Format support

Verified byte-for-byte (`encode(decode(f)) == f`) on 1,058 real containers spanning PT 4.1 through 9.0.1 (see [`docs/CORPUS_VERIFICATION.md`](docs/CORPUS_VERIFICATION.md)):

| Family | PT versions | Transform | Verified files |
| --- | --- | --- | ---: |
| Modern | 5.3.3 – 9.0.1 | layer A → Crypto++ EAX (Twofish) → layer B → qCompress | 865 |
| Legacy | 4.1 – 5.3.2 | layer B → qCompress (unencrypted) | 193 |

- Format detection uses the EAX tag for modern files and a 6-byte `qCompress`/zlib probe for legacy files.
- Inner XML is not strictly XML 1.0 compliant (raw `\x03` banner bytes, trailing NUL in PT 4.1 files, embedded HTML in `.pka` instructions), so standard validating parsers will fail on real files.
- Root elements are `PACKETTRACER5`, `PACKETTRACER5_ACTIVITY`, and `PACKETTRACER_ACTIVITY` (PT 4.x).
- `pkt_core` supports `.pkt`/`.pka` (Twofish), `.pta`/`.pkc` (Serpent), and `sm`/`userapp` (CAST-256) via its pure-Python ciphers and optional Rust extension. `pt9.py` uses `libgcrypt`, which covers Twofish and Serpent but not CAST-256.

## Reverse-engineering notes

Static analysis of the symbolized Linux `PacketTracer` binary located `CNetworkFile::openFile`, `Util::encrypt*`/`decrypt*`, `Util::cipher/decipher<Cipher>`, and Crypto++'s `EAX_Base` / `AuthenticatedDecryptionFilter`. Running Packet Tracer under `Xvfb` with `gdb` breakpoints captured exact intermediate buffers to verify the CTR counter layout and both obfuscation layers.

## Scripts and large topologies

Additional authoring scripts live in [`tools/`](tools) (see [`docs/SCENE_GRAPH.md`](docs/SCENE_GRAPH.md), [`docs/CONFIGURATION.md`](docs/CONFIGURATION.md), [`docs/ACTIVITY.md`](docs/ACTIVITY.md), and [`docs/CAPABILITIES.md`](docs/CAPABILITIES.md)):

- `tools/harvest_merge.py` — harvest one device per model from existing `.pkt` files into one canvas with physical-workspace remapping.
- `tools/build_wired_lab.py` — harvest and auto-wire ethernet devices to core switches.
- `tools/build_configured_lab.py` — build a configured multi-router lab (`PC1-SW1-R1=R2-SW2-PC2`).
- `tools/activity.py` + `tools/scoring.py` — author `.pka` activities (HTML instructions, wizard password, permissions, initial/answer networks, scoring tree).
- `tools/make_scored_lab.py` — build a scored `.pka` from a JSON topology spec using the bundled 137 device templates, 78 module templates, and 14 scoring shapes.
- `tools/harvest_library.py` — extend the template library from your own `.pkt`/`.pka` files.
- `demo/build_demo.py` — small 6-device OSPF walkthrough that runs from a plain `pip install`.

Two larger networks built with this toolchain and opened in PT 9.0.1 live in [`large-scale-packet-tracer`](https://github.com/aacanadaa/large-scale-packet-tracer):

| Network | Devices | Links | Config lines | Size |
| --- | ---: | ---: | ---: | ---: |
| Y-AMLT (Yokohama maritime terminal) | 386 | 380 | 15,345 | 1.33 MB |
| IRUMA-AB (JASDF air base) | 392 | 372 | 13,728 | 1.40 MB |

Full format specs, schema docs, and verification reports are published at [aacanadaa.github.io/packet-tracer-pkt-format](https://aacanadaa.github.io/packet-tracer-pkt-format/).

## Legal and ethical use

- Built for interoperability, format documentation, tooling, and archival using a locally licensed Packet Tracer installation and the author's own files.
- No DRM or license protection is bypassed; container keys are fixed and there is no user encryption password.
- Do not use this tool to extract, modify, or submit answers for exams, assessments, or competitions.

## License

**GNU General Public License v3.0 or later** ([LICENSE](LICENSE)). Commercial use, modification, and redistribution are permitted under the GPLv3 terms.

## Star history

<a href="https://www.star-history.com/?repos=aacanadaa%2Fpacket-tracer-pkt-format&type=date&legend=top-left">
  <picture>
    <source media="(prefers-color-scheme: dark)" srcset="https://api.star-history.com/chart?repos=aacanadaa/packet-tracer-pkt-format&type=date&theme=dark&legend=top-left" />
    <source media="(prefers-color-scheme: light)" srcset="https://api.star-history.com/chart?repos=aacanadaa/packet-tracer-pkt-format&type=date&legend=top-left" />
    <img alt="Star history chart" src="https://api.star-history.com/chart?repos=aacanadaa/packet-tracer-pkt-format&type=date&legend=top-left" />
  </picture>
</a>
