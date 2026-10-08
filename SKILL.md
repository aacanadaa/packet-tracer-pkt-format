---
name: packet-tracer-pkt-format
description: >-
  Build Packet Tracer labs WITHOUT Packet Tracer: read/write Cisco Packet Tracer 9
  `.pkt` / `.pka` files and generate complete, scored activities offline. Use when decoding a `.pkt`/`.pka`
  to XML, building a lab (place devices, install modules, power on/off, cable
  copper/serial, write IOS config and PC IPs), authoring an activity (`.pka`)
  with instructions, the activity-wizard password, permissions and a scoring
  tree, or extending the shipped device/module/scoring libraries.
license: GPL-3.0-or-later
---

# packet-tracer-pkt-format

A Python toolkit that **fully decodes and re-encodes** the Cisco Packet Tracer 9
`.pkt`/`.pka` container and lets you **generate complete labs and scored
activities without opening Packet Tracer**.

Repository: <https://github.com/aacanadaa/packet-tracer-pkt-format>

## When to use this skill

Use it whenever the task involves Packet Tracer *files* rather than the GUI:

- Decode a `.pkt`/`.pka` to its XML (inspect, diff, grep, archive, grade).
- Generate or modify a lab: devices, modules, power, cabling, IOS config, PC IPs.
- Author an **activity** (`.pka`): instructions, password, permissions, scoring,
  initial + answer networks — offline.
- Extend the shipped device/module/scoring libraries from your own files.

Do **not** use it to tamper with someone else's assessment/answer keys.

## The container (what a `.pkt` is)

```
file bytes
  -> reverse + XOR (n*(1-i))            # outer scramble
  -> Twofish-EAX (key 0x89*16, iv 0x10*16) + 16-byte tag   # Util::decryptPTSave
  -> XOR (len-i)                        # Util::deobfuscateBytes
  -> qCompress (4-byte BE length + zlib)
  -> UTF-8 XML  "<PACKETTRACER5>…"  (or "<PACKETTRACER5_ACTIVITY>…" for .pka)
```

Read/write is **byte-exact** (`encode(decode(f)) == f`). Other formats use
Serpent/CAST256 with different key/IV bytes. Full spec in `FORMAT.md`.

## Requirements

- Python 3.8+
- `libgcrypt` (block-cipher primitive only): `apt install libgcrypt20`
- No Packet Tracer required.

## Quickstart

```console
$ pip install .                       # gives the `pt9` CLI (optional)
$ python3 pt9.py info   lab.pkt       # decrypt + summarise
$ python3 pt9.py decode lab.pkt -o lab.xml
$ python3 pt9.py encode lab.xml -o lab.pkt
```

## Tools

| Tool | Purpose |
| --- | --- |
| `pt9.py` | decode/encode `.pkt`/`.pka` ↔ XML (byte-exact) |
| `tools/lab_api.py` | `Lab()`: `add_device` (config, pc_ip, power, `install` module), `install_module`, `link` (copper/serial), `set_os`, `set_config_register`, `save`; `load_templates` |
| `tools/build_configured_lab.py` | `PC-SW-R-R-SW-PC` with IPs, gateways, static routes, long configs |
| `tools/build_wired_lab.py` | merge one device/model + auto-cable to a switch backbone |
| `tools/harvest_merge.py` | merge devices from many `.pkt` into one canvas |
| `tools/activity.py` | author `.pka`: instructions, password, timer, permissions, feedback, initial/answer networks, scoring |
| `tools/scoring.py` | build `INITIALSETUP`/`COMPARISONS`; `from_shapes`, `from_template`, `derive_values` |
| `tools/make_scored_lab.py` | **one-shot offline** generator: topology spec → scored `.pka` |
| `tools/harvest_library.py` | (re)build `device_templates.json` / `device_shapes.json` |

Shipped libraries: `tools/device_templates.json` (137 models, 75 modules),
`tools/device_shapes.json` (14 scoring shapes), `tools/network_seed.xml`,
`tools/activity_skeleton.xml`.

## Workflow A — decode / inspect

```python
import pt9
xml = pt9.decode("lab.pkt", "pkt")          # -> bytes of XML
open("lab.xml","wb").write(xml)
pt9.encode("out.pkt", xml, "pkt")           # byte-exact round-trip
```

## Workflow B — build a network (offline)

```python
import lab_api
models, modules = lab_api.load_templates("tools/device_templates.json")
lab = lab_api.Lab("tools/network_seed.xml", models, modules)
r  = lab.add_device("2911", "R1", 250, 350, install="HWIC-2T",
                    ios_config=["interface GigabitEthernet0/0",
                                " ip address 192.168.1.1 255.255.255.0", " no shutdown", "end"])
sw = lab.add_device("2960-24TT", "SW1", 450, 350)
pc = lab.add_device("PC-PT", "PC1", 650, 350, pc_ip=("192.168.1.10","255.255.255.0","192.168.1.1"))
lab.link(r, "GigabitEthernet0/0", sw, "GigabitEthernet0/1")
lab.link(sw, "FastEthernet0/1", pc, "FastEthernet0")
lab.save("lab.pkt")
```

## Workflow C — a full scored activity, no Packet Tracer

```console
$ python3 tools/make_scored_lab.py --out mylab.pka --password hunter2 \
      --spec topology.json --instructions "<h3>Task</h3><p>…</p>"
```

`topology.json`:
```json
{"devices":[{"model":"2911","name":"R9","x":250,"y":350,"install":"HWIC-2T",
             "config":["interface GigabitEthernet0/0"," ip address 192.168.9.1 255.255.255.0"," no shutdown"]},
            {"model":"2960-24TT","name":"SW9","x":450,"y":350},
            {"model":"PC-PT","name":"PC9","x":650,"y":350,
             "pc_ip":["192.168.9.10","255.255.255.0","192.168.9.1"]}],
 "links":[{"a":"R9","aport":"GigabitEthernet0/0","b":"SW9","bport":"GigabitEthernet0/1"},
          {"a":"SW9","aport":"FastEthernet0/1","b":"PC9","bport":"FastEthernet0"}]}
```

Or assemble it piecewise with `activity.Activity` + `scoring.from_shapes`.

## Key facts (learned by RE — do not relearn)

- **Load requirements**: unique `<ENGINE>/<SAVE_REF_ID>` per device; unique
  `MACADDRESS`/`BIA` per port; a valid `<PHYSICAL>` scene placement; every link
  endpoint resolves (id + an existing port name).
- **IOS config** = `<ENGINE><RUNNINGCONFIG><LINE>cmd</LINE>…`, applied on load.
  Long configs (hundreds of lines) are fine.
- **PC/Server IP** = NIC `<PORT><IP>/<SUBNET>/<PORT_GATEWAY>/<PORT_DHCP_ENABLE>`.
- **Modules**: fill an empty `<SLOT><TYPE>eInterfaceCard</TYPE>` with a
  `<MODULE><TYPE>eInterfaceCard</TYPE><MODEL>…</MODEL><PORT>…` subtree; interface
  names follow the bay (HWIC-2T in bay `0/0` → `Serial0/0/0`).
- **Cables**: `<LINK><TYPE>` (before `<CABLE>`); copper = `eCopper` +
  `eStraightThrough`; serial = `eSerial` + `DCEDEV`/`DCEPORT`. The `*_MEM_ADDR`
  values are **not** validated (PT rebinds by id + port).
- **Power**: `<ENGINE><POWER>true|false>`.
- **Activity (`.pka`)** root is `<PACKETTRACER5_ACTIVITY>` and embeds three
  networks: [0] current, [1] initial, [2] answer. `<ACTIVITY PASS="…">` is the
  activity-wizard password; `<INSTRUCTIONS>` holds HTML pages; scoring lives in
  parallel `<INITIALSETUP>` / `<COMPARISONS>` node trees.
- **Scoring** must be **complete** device nodes cloned from a real activity
  (minimal hand-made nodes are rejected) — use `scoring.from_shapes` /
  `from_template`.

## Extending the libraries

```console
$ python3 tools/harvest_library.py --saves /opt/pt/saves --activities ./my_labs \
      --out-models tools/device_templates.json --out-shapes tools/device_shapes.json
```

## Limitations

- Scoring shapes cover 14 models (only activities contain scoring trees); models
  without a shape are ungraded, not fatal.
- Scoring correctness is spot-verified, not exhaustively validated.
- Wireless/AP/SSID, clusters, connectivity tests and scripted custom grading are
  not authored yet. Serial cables load; line-up needs matching clock/DCE config.

## License

GPL-3.0-or-later. Interoperability tooling for your own files.
