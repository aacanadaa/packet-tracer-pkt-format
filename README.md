# Build Packet Tracer labs — without Packet Tracer

> **Create Packet Tracer `.pkt` labs and scored `.pka` activities entirely offline,
> with no Packet Tracer installed.**  This repo reverse-engineers the Packet Tracer 9
> file format and ships a byte-exact codec plus a generator that writes devices,
> modules, cabling, IOS config, PC IPs, instructions, the activity-wizard password,
> and the scoring tree — straight to a file PT opens.

[![License: GPL v3](https://img.shields.io/badge/license-GPLv3-blue.svg)](LICENSE)
[![Python 3.8+](https://img.shields.io/badge/python-3.8%2B-blue.svg)](https://www.python.org/)
[![No Packet Tracer needed](https://img.shields.io/badge/Packet_Tracer-not_required-32d74b.svg)](#quickstart)
[![Cisco Packet Tracer](https://img.shields.io/badge/Cisco_Packet_Tracer-1BA0D7?style=flat&logo=cisco&logoColor=white)](#status--scope)

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

* **Fully decoded, both directions.** `decode(encode(xml)) == xml` and
  `encode(decode(file)) == file` **byte-for-byte** on every sample tested
  (`.pkt` and `.pka`, including 20 MB+ activity files).
* The AEAD authentication tag is reproduced exactly and verified on load.
* Verified against **Packet Tracer 9.0.1.0858**, Linux x86-64.
* `.pkt`/`.pka` (Twofish) are fully supported.  The `.pta`/`.pkc` (Serpent) and
  internal `sm`/`userapp` (CAST256) formats are documented but need a crypto
  backend with Serpent/CAST6 (stock `libgcrypt` has no CAST6; some builds also
  omit Serpent).

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

GNU General Public License v3.0 or later (GPL-3.0-or-later) — see [LICENSE](LICENSE).
