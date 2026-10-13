---
name: packet-tracer-pkt-format
description: Read, author, modify and re-serialise Cisco Packet Tracer .pkt labs and scored .pka activities entirely offline. Covers both container families (PT 4.1 through 9.0.1), a byte-exact codec, a typed Python model, and generators for full topologies and graded activities. Use when a task involves opening, inspecting, diffing, editing or creating Packet Tracer files.
---

# packet-tracer-pkt-format

Everything here is **offline**. Packet Tracer is only needed to *open* a result,
never to build one.

## When to use this skill

- Build a network lab (`.pkt`) from code or a JSON spec
- Build a **scored activity** (`.pka`) with instructions, grading and a wizard password
- Read / inspect / diff / edit existing Packet Tracer files
- Convert a topology to graphviz, netbox or containerlab
- Reverse-engineer something about the file format

## Bootstrap — you may have only this file

Clone, install, and confirm the toolchain works before authoring anything:

```console
$ git clone https://github.com/aacanadaa/packet-tracer-pkt-format.git
$ cd packet-tracer-pkt-format
$ python3 -m venv .venv && . .venv/bin/activate
$ pip install -e . pytest hypothesis pydantic
$ python -m pytest tests/ -q            # expect 245 passed, 49 skipped
                                        #   (the 49 are the optional Rust tests;
                                        #    with pkt_core_native: 293 passed, 1 skipped)
```

Optional but faster: `pip install pkt_core_native` gives the Rust cipher
accelerator (~100x). `libgcrypt` is a further optional accelerator. **Neither is
required** — the pure-Python path is complete.

Sanity check that you are ready to author:

```python
from pkt_core import decode_bytes, encode_bytes        # codec works
import sys; sys.path.insert(0, "tools"); sys.path.insert(0, ".")
import lab_api                                          # authoring works
models, modules = lab_api.load_templates("tools/device_templates.json")
lab = lab_api.Lab("tools/network_seed.xml", models, modules)
print(lab.device_names())   # 7 seed names - see the PITFALL section
```

If `decode_bytes` raises `UnsupportedCipherError`, you are missing `libgcrypt`
and the pure-Python backends; reinstall with `pip install -e .` and check
`python -c "from pkt_core.crypto.ciphers import available_ciphers; print(available_ciphers())"`
which must include `twofish`.

## The container — know this before touching any file

There is **no magic header**. Detection is verifier-based (an AEAD tag), never a
prefix match. Two families:

| Family | Written by | Transform | Verified |
| --- | --- | --- | --- |
| modern | PT **5.3.3** → 9.0.1 | layer A → Crypto++ EAX (Twofish) → layer B → qCompress | 865 files |
| legacy | PT **4.1** → 5.3.2 | layer B → qCompress *(no AEAD, no reversal)* | 193 files |

The switchover is **5.3.2 → 5.3.3**, not 5.x → 6.0. `encode(decode(f)) == f`
byte-for-byte on **1058/1058** real containers.

Three root elements exist — `PACKETTRACER5` (lab), `PACKETTRACER5_ACTIVITY`
(scored activity), `PACKETTRACER_ACTIVITY` (PT 4.x scored). **The root element is
not a container discriminator.**

**Documents are not always well-formed XML.** `<LINE>` IOS config carries raw
control bytes (the Cisco `banner motd ^C…^C` delimiter is a literal `0x03`),
PT 4.1 docs end with a trailing NUL, and activity instructions are **CDATA HTML**
that contains `>`. Do not use a validating parser.

## Requirements

Python 3.10+. Optional: `libgcrypt` (faster), Rust accelerator (fastest).
Nothing is required to author a file.

## The two APIs — pick by task

### 1. `src/pkt_core/` — read, inspect, modify

```python
from pkt_core import decode, decode_bytes, encode_bytes, Lab   # Lab re-exported below
from pkt_core.models import Lab

lab = Lab.from_bytes(decode("lab.pkt").xml)     # format auto-detected
lab.version, lab.root_tag, lab.is_activity
lab.devices, lab.links, lab.clusters, lab.options
lab.activity_password                          # <ACTIVITY PASS="..."> attribute!
lab.activity_sections                          # COMPARISONS/INITIALSETUP/LOCKINGTREE/INSTRUCTIONS

for d in lab.devices:
    d.name, d.kind, d.model, d.position, d.cluster_id
    d.ports                                     # flattened across modules/slots
    d.details                                   # sys contact/location, serial, coords
    d.port_configs                              # IP/DHCP/DNS/VLAN
    d.wireless, d.files

lab.set_activity_password("newpass")
lab.devices[0].set_name("CORE-R1")             # writes to ENGINE/NAME, correctly
lab.devices[0].set_position(123, 456)

out = encode_bytes(lab.to_xml(), "pkt")        # byte-exact for unmodified docs
```

CLI: `pkt info | unpack | pack | diff | export`.
`pkt unpack` emits XML + container metadata + per-device IOS configs + a topology graph.

Models are **views over a lossless tree**: untouched bytes are emitted verbatim,
so data loss is impossible. Unrecognised elements surface in `extra_fields`.

### 2. `tools/lab_api.py` — author from scratch

```python
import sys; sys.path.insert(0, "tools"); sys.path.insert(0, ".")
import lab_api

models, modules = lab_api.load_templates("tools/device_templates.json")
lab = lab_api.Lab("tools/network_seed.xml", models, modules)

lab.prune_seed_devices()        # <-- DO THIS unless you want the seed devices
r  = lab.add_device("2911", "R1", 250, 350, install="HWIC-2T",
                    ios_config=["hostname R1",
                                "interface GigabitEthernet0/0",
                                " ip address 192.168.1.1 255.255.255.0",
                                " no shutdown", "end"])
sw = lab.add_device("2960-24TT", "SW1", 450, 350)
pc = lab.add_device("PC-PT", "PC1", 650, 350,
                    pc_ip=("192.168.1.10", "255.255.255.0", "192.168.1.1"))
lab.link(r, "GigabitEthernet0/0", sw, "GigabitEthernet0/1")
lab.link(sw, "FastEthernet0/1", pc, "FastEthernet0")
lab.save("lab.pkt")
```

## PITFALL — device names collide with the seed

`network_seed.xml` ships **7 pre-existing devices**:

```
Server   Power Distribution Device0   PC-B   PC-A   SW1   R2   R1
```

`add_device("2960-24TT", "SW1", …)` **raises ValueError** by default. This is
deliberate — silently renaming hides authoring bugs. Either:

- `lab.prune_seed_devices()` first (returns the removed names, idempotent), or
- pick names outside that set, or
- `on_name_conflict="suffix"` to opt into `SW1` → `SW1(1)`.

`lab.device_names()` lists what is taken. Note: device `<NAME>` lives under
`<ENGINE>`, not as a direct child of `<DEVICE>`.

## Workflow — a full scored activity (`.pka`)

```console
$ python3 tools/make_scored_lab.py --out mylab.pka --spec topology.json \\
      --password hunter2 --prune-seed --feedback "Lab complete - well done!"
```

Spec is JSON: `{"devices":[{"model","name","x","y","install","config":[...],"pc_ip":[...]}],
"links":[{"a","aport","b","bport"}], "instructions": "<h3>Task</h3>..."}`.
`instructions` accepts a string or a list of pages.

It builds an **initial** network (topology, no config) and an **answer** network
(config applied), and derives the scoring tree from the answer. Output verified
in Packet Tracer 9.0.1: opens as a real activity, timer runs, `Check Results`
runs the grading engine.

**The wizard password is the `PASS` attribute of `<ACTIVITY>`, not
`<OPTIONS><PASS>`.** `pkt_core.models.Lab.activity_password` reads the right one.

## Other tools

| Tool | Use |
| --- | --- |
| `tools/build_large_topology.py` | 3-tier campus: core/distribution/access/servers/wireless/IoT, real IOS configs. `--clients N`, `--prune-seed` |
| `tools/build_configured_lab.py` | PC-SW-R-R-SW-PC with IPs, static routes |
| `tools/build_wired_lab.py` | auto-cable devices to a switch backbone |
| `tools/activity.py` | lower-level `.pka` authoring (instructions, timer, permissions, feedback) |
| `tools/scoring.py` | `INITIALSETUP`/`COMPARISONS`, `from_shapes`, `derive_values` |
| `tools/harvest_library.py` | rebuild `device_templates.json` / `device_shapes.json` from saves |
| `tools/legacy_probe.py` | standalone legacy-container probe |
| `tools/bench_crypto_backends.py` | compare Rust / libgcrypt / pure Python |

Shipped libraries: `tools/device_templates.json` (137 models, 78 modules),
`tools/device_shapes.json`, `tools/network_seed.xml`, `tools/activity_skeleton.xml`.

## Crypto backends

`pkt_core.crypto.ciphers.get_cipher(name, key)` tries **Rust → libgcrypt → pure
Python**. Names: `twofish`, `serpent128/192/256`, `cast256`, `aes`.
Knobs: `PKT_CORE_BACKEND=rust|gcrypt|pure`, `PKT_CORE_DISABLE_RUST=1`.
CAST-256 is only available via Rust or pure Python — libgcrypt has no CAST-256.
Per-format key/IV bytes are in `pkt_core.crypto.keys.FORMATS`.

## Key facts learned by reverse engineering — do not relearn

* No magic header in any generation. Detection is try-and-verify.
* Layer A is `C[i] = F[n-1-i] ^ ((n*(1-i)) & 0xFF)`; layer B is `P[i] ^= (m-i)`.
* Crypto++ EAX nonce is `CMAC_K(0^128 || IV)`, **not** `CMAC_K(IV)`; CTR is
  big-endian full-width from `N`; the 16-byte tag is appended.
* The key and IV are one byte repeated ×16, so the keystream is file-independent
  and the container is deterministic.
* libgcrypt 1.12 **renumbered** its cipher ids (Serpent = 304/305/306, not
  12/13/14). Never hard-code them — use `gcry_cipher_map_name`.
* Twofish `h()` applies the q-permutation **before** the per-word XOR; round keys
  split the key into `M_e`/`M_o`. Both are invisible in zero-key test vectors.
* Activities nest ~3 `<PACKETTRACER5>` children (live/initial/comparison copies).
* `NODE` is overloaded: the activity grading tree **and** the physical-workspace
  location tree share the name.

## Documentation

| File | Contents |
| --- | --- |
| `docs/FORMAT_SPECIFICATION.md` | both container families, full binary spec |
| `docs/SCHEMA_REFERENCE.md` | all 1,285 XML element names |
| `docs/LEGACY_FORMAT.md` | the PT 5.x reverse-engineering writeup |
| `docs/CORPUS_VERIFICATION.md` | 1058/1058 byte-exact evidence |
| `docs/PKA_GENERATION.md` | authoring scored activities |
| `docs/LARGE_TOPOLOGY_TEST.md` | 77-device topology, generated and opened |
| `docs/PACKET_TRACER_VALIDATION.md` | verified in PT 7.3.1 and 9.0.1 |

Corpus: `corpus/CORPUS_INDEX.tsv` (SHA-256 manifest), `corpus/fetch_corpus.py`
(rebuilds it), `corpus/samples/` (self-authored, shipped).

## Limitations

`.pta` / `.pkc` / `sm` / `userapp` container flavours are specified
(`pkt_core.crypto.keys.FORMATS`) but untested — no real samples exist.
`pkt export` output has not been validated against live netbox/containerlab.

## License

GNU General Public License v3.0 or later.
