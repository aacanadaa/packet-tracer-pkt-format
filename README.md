# Build Packet Tracer labs — without Packet Tracer

> **Create Packet Tracer `.pkt` labs and scored `.pka` activities entirely offline,
> with no Packet Tracer installed.**  This repo reverse-engineers the Packet Tracer
> file format — both container families, PT 4.1 through 9.0.1 — and ships a byte-exact
> codec plus a generator that writes devices,
> modules, cabling, IOS config, PC IPs, instructions, the activity-wizard password,
> and the scoring tree — straight to a file PT opens.

[![License: GPL v3](https://img.shields.io/badge/license-GPLv3-blue.svg)](LICENSE)
[![Ko-fi](https://img.shields.io/badge/Ko--fi-Support%20me-ff5e5b?logo=kofi&logoColor=white)](https://ko-fi.com/suoim)
[![Python 3.10+](https://img.shields.io/badge/python-3.10%2B-blue.svg)](https://www.python.org/)
[![No Packet Tracer needed](https://img.shields.io/badge/Packet_Tracer-not_required-32d74b.svg)](#quickstart)
[![Cisco Packet Tracer](https://img.shields.io/badge/Cisco_Packet_Tracer-1BA0D7?style=flat&logo=cisco&logoColor=white)](#status--scope)

**Languages:** English | [简体中文](README.zh-CN.md)

## Create a Packet Tracer, without Packet Tracer

Packet Tracer is only needed to *open* the result — the lab itself is authored here:

```python
import lab_api
models, modules = lab_api.load_templates("tools/device_templates.json")
lab = lab_api.Lab("tools/network_seed.xml", models, modules)
r  = lab.add_device("2911", "R1", 250, 350, install="HWIC-2T",
                    ios_config=["interface GigabitEthernet0/0",
                                " ip address 192.168.1.1 255.255.255.0", " no shutdown", "end"])
sw = lab.add_device("2960-24TT", "SW1", 450, 350)
pc = lab.add_device("PC-PT", "PC1", 650, 350,
                    pc_ip=("192.168.1.10", "255.255.255.0", "192.168.1.1"))
lab.link(r, "GigabitEthernet0/0", sw, "GigabitEthernet0/1")
lab.link(sw, "FastEthernet0/1", pc, "FastEthernet0")
lab.save("my_lab.pkt")            # open in Packet Tracer — no Packet Tracer used to build it
```

...or one-shot from a topology spec (devices + links → a scored, password-protected activity):

```console
$ python3 tools/make_scored_lab.py --out mylab.pka --spec topology.json --password hunter2
```

---


Modern Packet Tracer files have **no magic header** and are fully encrypted, so
`file`, `strings`, and hex dumps show nothing but noise.  This project documents
the container and ships a small reader that turns a `.pkt`/`.pka` back into the
plain XML Packet Tracer stores internally.

## TL;DR

```
.pkt  ..  [ scramble ] -> [ Twofish-EAX, key=0x89*16, iv=0x10*16 ] ->
          [ XOR (len-i) ] -> [ qCompress/zlib ] -> "<?xml ... <PACKETTRACER5>"
```

* Cipher: **Twofish in EAX (AEAD) mode**, 128-bit key = `0x89` repeated, IV =
  `0x10` repeated, 16-byte tag appended.
* Pre-encryption wrapper: byte reversal + position XOR.
* Post-decryption wrapper: XOR every byte with `(len - i)`.
* Payload: Qt `qCompress` (zlib) of a UTF-8 XML document.

Full details, evidence and the per-format key table are in **[FORMAT.md](FORMAT.md)**.

## The `pkt_core` library

`pt9.py` is a self-contained reference codec. Alongside it, `src/pkt_core/` is the
**type-safe library** (`mypy --strict`, Python 3.10+) intended for embedding — the
CLI is a thin consumer of it and is never imported back into the package.

```python
from pkt_core import decode, encode_bytes

container = decode("lab.pkt")          # format is detected by the AEAD tag,
                                       # not by a magic prefix — there isn't one
print(container.root_tag)              # 'PACKETTRACER5'
print(container.is_activity)           # False  (.pka -> PACKETTRACER5_ACTIVITY)
xml = container.xml                    # the inner XML document

rebuilt = encode_bytes(xml, container.format_name)
```

```python
from pkt_core import decode
from pkt_core.models import Lab

lab = Lab.from_bytes(decode("lab.pkt").xml)
for dev in lab.devices:
    print(dev.name, dev.kind, dev.model, dev.position)
for link in lab.links:
    print(link.port_names, link.cable_type)
```

| Module | Responsibility |
| --- | --- |
| `pkt_core.crypto.primitives` | CMAC (RFC 4493), big-endian CTR, and the Crypto++ EAX variant |
| `pkt_core.crypto.keys` | Per-format key schedule (`twofish`/`serpent128`/`cast256`, key & IV bytes) |
| `pkt_core.crypto.stream` | The two positional-XOR obfuscation layers |
| `pkt_core.crypto.ciphers_pure` | Pure-Python Twofish, Serpent and CAST-256 |
| `pkt_core.codec.qcompress` | Qt `qCompress` framing |
| `pkt_core.codec.container` | Detect / decode / encode the whole container |
| `pkt_core.xml` | Lossless byte-level XML layer (lazy, HTML-tolerant) |
| `pkt_core.models` | Typed views: `Lab`, `Device`, `Port`, `Link`, `Cluster`, `RunningConfig` |
| `pkt_core.diff` | Semantic device/link/config comparison |
| `pkt_core.export` | `graphviz`, `netbox`, `containerlab` topology export |
| `pkt_core.errors` | Typed exceptions — never a bare `Exception` |

The models are **views over the lossless XML tree**, not a parallel data
structure: writing a document out again emits the original source bytes for
anything you did not touch, so data loss is impossible by construction.
Unrecognised elements are surfaced in each model's ``extra_fields`` rather than
dropped. IOS ``<LINE>`` config is exposed as ``bytes`` on purpose — it carries
raw ``^C`` banner delimiters that decoding would normalise away.

The AEAD is **deterministic**: key and IV are fixed per format, so the keystream
is file-independent and identical XML always produces identical bytes. That is
also what makes the EAX tag usable as a format-detection oracle (false-positive
rate 2^-128) instead of a magic number.

Sample containers generated by this project are committed under
[`corpus/samples/`](corpus/samples/) so the tests run out of the box. The 1,026
third-party files used for the reverse engineering are **not** committed — see
[`corpus/README.md`](corpus/README.md) for the policy and
[`corpus/fetch_corpus.py`](corpus/fetch_corpus.py) to reproduce them.

## Usage

```console
$ sudo apt install libgcrypt20            # only dependency (block cipher primitive)
$ python3 pt9.py info   my_lab.pkt
root tag  : PACKETTRACER5
xml bytes : 1045755

$ python3 pt9.py decode my_lab.pkt -o my_lab.xml
$ python3 pt9.py decode course_activity.pka -o activity.xml      # .pka uses the same container
$ python3 pt9.py encode my_lab.xml -o my_lab.pkt                 # write it back
$ python3 -m unittest discover -s tests -v                       # self-tests
```

Example decrypted root elements:

```
<PACKETTRACER5>
  <VERSION>9.0.1.0858</VERSION>
  <PIXMAPBANK>…</PIXMAPBANK>
  <DEVICES>…</DEVICES>
  <LINKS>…</LINKS>
  …
```

## Status / scope

**Both container families are fully decoded, both directions.**
`encode(decode(f)) == f` **byte-for-byte on 1058 of 1058 real containers** — see
[`docs/CORPUS_VERIFICATION.md`](docs/CORPUS_VERIFICATION.md).

| Family | Written by | Transform | Files verified |
| --- | --- | --- | --- |
| **modern** | PT **5.3.3** → 9.0.1 | layer A → Crypto++ EAX (Twofish) → layer B → qCompress | 865 |
| **legacy** | PT **4.1** → 5.3.2 | layer B → qCompress *(no AEAD, no reversal)* | 193 |

* The AEAD authentication tag is reproduced exactly and verified on load.
* Verified against **Packet Tracer 9.0.1.0858** (Linux x86-64) and 1,058 real
  files spanning **PT 4.1 through PT 9.0.1**.
* **Neither family has a magic header.** Detection is verifier-based: the EAX tag
  for the modern family (false-positive rate 2⁻¹²⁸), a structural qCompress probe
  for the legacy one. The container switchover is exactly 5.3.2 → 5.3.3.
* Documents are **not always well-formed XML** — `<LINE>` config text carries raw
  control bytes (the Cisco `banner motd ^C…^C` delimiter is a literal `\x03`) and
  PT 4.1 documents end with a trailing NUL. Do not use a validating parser.
* Three root elements exist: `PACKETTRACER5`, `PACKETTRACER5_ACTIVITY` and
  `PACKETTRACER_ACTIVITY` (PT 4.x). Root element is **not** a container
  discriminator.
* `.pkt`/`.pka` are fully supported. The `.pta`/`.pkc` (Serpent) and internal
  `sm`/`userapp` (CAST-256) flavours are specified but need a crypto backend
  with Serpent/CAST-256 (stock `libgcrypt` has neither).

## How it was found

Static analysis of the fully-symbolized `PacketTracer` binary located
`CNetworkFile::openFile`, the `Util::encrypt*/decrypt*` family, the generic
`Util::cipher/decipher<Cipher>` templates, and Crypto++'s `EAX_Base` /
`AuthenticatedDecryptionFilter`.  Packet Tracer was then run headless under
`Xvfb` with `gdb` breakpoints to capture the exact ciphertext and plaintext,
which pinned the CTR counter and both obfuscation layers with byte-accurate
certainty.

## Generating files

Because encoding is byte-exact, the same codec **writes** `.pkt` files.  Tools in
[`tools/`](tools) and notes in [`docs/SCENE_GRAPH.md`](docs/SCENE_GRAPH.md):

* `tools/harvest_merge.py` — harvest one complete device of every model from a
  tree of existing `.pkt` files and merge them into one canvas, handling the
  physical-workspace remapping PT requires.
* `tools/build_wired_lab.py` — the same, **plus auto-wiring**: cables every
  ethernet-capable device to a backbone of core switches and chains the cores.
* `tools/build_configured_lab.py` — a full **working, configured** lab
  (`PC1－SW1－R1＝R2－SW2－PC2` with IPs, gateways, static routes, and an optional
  long running-config).  IOS config is written as `<RUNNINGCONFIG><LINE>…`
  commands and applied on load; PCs get `<IP>/<SUBNET>/<PORT_GATEWAY>`.  See
  [`docs/CONFIGURATION.md`](docs/CONFIGURATION.md).
* `tools/activity.py` + `tools/scoring.py` — author **activity files (`.pka`)** with the Activity Wizard: instructions (HTML), the **activity-wizard password**, permissions, feedback, the **initial / answer networks**, and the **scoring tree**.  See [`docs/ACTIVITY.md`](docs/ACTIVITY.md).
* `tools/make_scored_lab.py` — **one-shot offline generator**: from a topology spec (`--spec`) it builds the initial + answer networks, derives scoring, and writes a scored `.pka`.  No Packet Tracer needed.  Ships with a library of **137 device templates, 75 module templates and 14 scoring shapes** (`tools/device_templates.json`, `tools/device_shapes.json`).
* `tools/harvest_library.py` — (re)build those libraries from your own `.pkt`/`.pka` files to extend model/shape coverage.
* `tools/lab_api.py` — a small library of the **verified authoring operations**
  (place device, power on/off, install a module, cable copper, write IOS
  `RUNNINGCONFIG`, set PC IP/DHCP).  Capability matrix + details in
  [`docs/CAPABILITIES.md`](docs/CAPABILITIES.md).
* Editing: decode → change device names/config/positions → encode → PT opens it.

Result of running the wired builder here: **147 devices, 140 distinct models,
71 cables** (routers, switches, ASAs, WLCs, APs, IP phones, PCs/laptops/tablets,
servers, and a large IoT/industrial set) in one file that Packet Tracer opens
and draws connected.

Key facts for anyone generating files (details in the scene-graph notes):

* Devices carry a *physical scene* placement that must be remapped when merging.
* A cable binds by `<FROM>`/`<TO>` ids and `<PORT>` names; the device needs an
  `<ENGINE>/<SAVE_REF_ID>` and the port must exist on that exact instance.  The
  `*_MEM_ADDR` fields are not validated — PT rebinds.

## Legal / ethical

* Interoperability research on a file format, using a locally licensed copy of
  Packet Tracer and the author's own files.
* No DRM or licence protection is bypassed; there is no encryption password.
* Intended for reading *your own* files, format documentation, tooling and
  archival.
* **Do not** use this to obtain, alter, or submit assessment/competition answer
  keys.  That is cheating and is out of scope.

## License

**GNU General Public License v3.0 or later** — see [LICENSE](LICENSE).

Free for non-commercial use. If you want to use this commercially, open an
issue and we will talk about a commercial licence.

