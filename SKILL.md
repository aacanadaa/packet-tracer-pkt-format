---
name: packet-tracer-pkt-format
description: Read, author, modify and re-serialise Cisco Packet Tracer .pkt labs and scored .pka activities entirely offline. Covers both container families (PT 4.1 through 9.0.1), a byte-exact codec, a typed Python model, and generators for full topologies and graded activities. Use when a task involves opening, inspecting, diffing, editing or creating Packet Tracer files.
---

# packet-tracer-pkt-format

Everything here is **offline**. Packet Tracer is only needed to *open* a result,
never to build one — but you can and should open the result, because a file can
be byte-perfect and still render wrong.

Packet Tracer 9.0.1 is installed on this machine and starts headless:

```console
$ xvfb-run -a /usr/local/bin/packettracer /tmp/verify/lab.pkt
```

It needs a **one-time** Cisco NetAcad sign-in on first ever launch
(`~/.local/.packettracer/`). After that it goes straight to the workspace with
no network at all — it does *not* ask every time. Check the **Physical**
workspace tab too: that view is what validates the braced `<PHYSICAL>` UUID
plumbing, and it is the one that reports "corrupted Physical Workspace data".

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

CLI: `pkt info | unpack | pack | diff | export | audit`.
`pkt unpack` emits XML + container metadata + per-device IOS configs + a topology graph.
`pkt audit lab.pkt --templates tools/device_templates.json` prints raw **and**
distinct counts for every service family and exits non-zero on any duplicate —
see the "if the validator prints a count" rule below. Run it on anything you
generate from harvested templates.

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

## Authoring at scale — five rules, learned by shipping a broken 290-device lab

A 290-device enterprise model was generated, structurally validated, and shipped
with `RESULT: PASSED (0 warnings)` — and it was still wrong. The validator was
checking *presence*, never *uniqueness*; nothing checked position or power at
all; and the headline figures could not be reproduced from the file. These five
rules are the generalisation. They are not style advice — each one corresponds to
a defect that reached a delivered file.

All five are now repaired in the delivered file, and the repair is gated:

| | shipped | after repair |
| --- | --- | --- |
| `pkt audit` | **FAILED** (15 failures) while claiming PASSED | **PASSED** (0 failures) |
| AAA clients | 202 counted / **140** distinct | 139 / 139 |
| DHCP pools | 259 counted / **133** distinct | 131 / 131 |
| AAA users, FTP accounts | 65 / **3**, 64 / **3** | 2 / 2, 2 / 2 |
| devices off, links dark | 10 off → **76 of 326 links (23.3%)** dark | 290/290 on, ports 2454/2454 |
| device pairs ≤ 40 u | 12 (nearest 30.4 u) | 0 (nearest 114.0 u) |
| **label** boxes overlapping | ~111 | **0** |
| devices off the page | 60 | **0** |
| build reproducible? | **no** — random UUIDs per run | yes, byte-identical |

### Rule 1 — inherit template state; never write a constant over it

`add_device()` wrote `<POWER>false</POWER>` unconditionally. But the device
template already carries a `POWER` value, and **exactly 1 of 137 templates ships
`POWER=false`** — the template default is *on*. The hard-coded constant silently
overrode it.

Result: the entire aggregation layer (`MultiLayerSwitch 3650-24PS`) shipped dark
— **10 of 290 devices off**, which took out **76 of 326 links (23.3%)** and left
**134 of 290 devices (46.2%)** within two hops of an unpowered switch.

Corpus evidence settles what the default must be: across 443 real Packet Tracer
files, **5,813 `<POWER>true</POWER>`, 6 `false`, 0 absent.** Devices are on
unless something says otherwise.

```python
# WRONG - clobbers whatever the template chose
node.append(f"<POWER>{str(power).lower()}</POWER>")

# RIGHT - the template is the source of truth; only override when asked
power = template_value if requested_power is None else requested_power
```

This generalises: **any field the template supplies is data you did not author.**
If you find yourself emitting a literal for such a field, you are discarding
information. The same bug class produced leftover service records (Rule 4).

`tools/lab_api.py` now exposes `add_device(..., power=None)` and
`normalise_device_power()` to repair an existing file in place, and
`tools/device_templates.json` records `"power_normalised": ["3650-24PS"]`.

### Rule 2 — compute coordinates; never place a device by hand

Coordinates were passed in by the caller with no collision detection, so devices
and their labels overlapped. Measured on the shipped file:

| Metric | Shipped lab | Real human-authored labs (167 devices) |
| --- | --- | --- |
| device pairs ≤ 40 units apart | **12** | **0** |
| pairs ≤ 80 units | 21 | — |
| pairs ≤ 120 units | 84 | — |
| nearest-neighbour minimum | **30.4 u** | 50.2 u |
| nearest-neighbour median | 135.0 u | 125.7 u |
| devices with a **label box** overlapping another | ~111 | — |
| devices whose centre is **off the 3900×3900 page** | **60** | 0 |
| workspace bounding box | X[60,3700] Y[130,**5140**] | fits the ~3900×3900 page |

Two separate failures are visible there. Devices were too close (30 u where a
human never goes below 50), and the layout **ran off the page** — 5140 in Y on a
3900-tall workspace, so 60 devices past y≈3900 (the whole `AB-HAMAMATSU` site,
at y=4200–4580) are off-screen and effectively invisible.

Note the gap between the 12 icon-level pairs and the ~111 label-box overlaps:
**counting icons instead of labels understates the problem by roughly 9×.** That
is the measurement error that let the bug ship.

**1 coordinate unit = 1 px at 100% zoom** (calibrated against a screenshot). The
stock logical workspace is ≈ 3900×3900.

The rule: **the collision box must include the label, not just the icon.** Device
labels are drawn *below* the icon, so two icons 90 u apart can still have
overlapping text — text overlap is exactly as unreadable as icon overlap, and the
user reported both as one symptom. The packing must therefore:

- use a label-inclusive axis-aligned bounding box
- choose the column pitch from the **name length** (200 / 260 / 320 u) — a long
  hostname needs a wider column than `R1`
- use a row pitch of 150 u
- enforce a **hard floor of 80 u** between label-inclusive boxes, and refuse to
  emit any placement that violates it
- wrap to a second page column at `x + 3900` rather than running off the page

The missing primitive is a per-kind **sizing model** — a uniform grid cannot work,
because a router with a 23-character name needs about twice the cell of `PC1`:

```python
CHAR_W, GUTTER = 7, 28              # 7 u/char (6.3 measured, +margin); gutter
ICON_W = {                          # icon artwork, default zoom
    "router": (52, 44), "switch": (50, 42), "multilayer-switch": (50, 42),
    "access-point": (50, 36), "pc": (36, 42), "laptop": (36, 42),
    "server": (30, 48), "iot": (40, 40), "sniffer": (50, 40),
    "firewall": (52, 42), "pdd": (40, 40), "default": (52, 44),
}

def device_box(kind, name, model_caption):
    w = max(ICON_W[kind][0], CHAR_W * len(name) + 16,
            CHAR_W * len(model_caption) + 16)
    h = ICON_W[kind][1] + 2 * 18    # model caption above + name below
    return w + GUTTER, h + GUTTER
```

Worked: `PC-PT`/`E767-01-WC-PC` → 100×108; `ISR4331`/`CRC-CENTRAL-RTR-01` →
154×100; `Server-PT`/`CRC-CENTRAL-DISPLAY-SVR` → 189×112.

Greedy row-major packing is sufficient and deterministic. The tooling is
`tools/check_layout.py` (measures and fails), `tools/repack_layout.py` (migrates
an existing file, idempotent) and the `Layout` helper in `tools/lab_api.py`.

**Never trust a coordinate you did not check.** `check_layout.py` is the
reproducer: it prints every pair closer than the floor plus the bounding box, and
exits non-zero. Run it on every artefact before shipping.

Exact paths, because guessing them wastes time — note there is **no network-level
workspace**; `WORKSPACE` exists only per device:

```
NETWORK/DEVICES/DEVICE                      the devices (290 of them)
NETWORK/DEVICES/DEVICE/ENGINE/NAME          the device name
NETWORK/DEVICES/DEVICE/ENGINE/TYPE          the model, e.g. "2911"
NETWORK/DEVICES/DEVICE/ENGINE/POWER         "true" / "false"
NETWORK/DEVICES/DEVICE/WORKSPACE/LOGICAL/X  logical canvas X   <-- 1 unit = 1 px
NETWORK/DEVICES/DEVICE/WORKSPACE/LOGICAL/Y  logical canvas Y
NETWORK/LINKS/LINK                          the cables
PACKETTRACER5/PHYSICALWORKSPACE             physical rack view - a DIFFERENT X/Y.
                                            This is what lab_api's `_pos` tracks,
                                            and it is not the logical canvas.
```

A layout checker must also consider the **root-level drawing layers**, which sit
outside `NETWORK` and can be drawn over devices: `CLUSTERS` (labelled group
boxes), `LINES`, `RECTANGLES`, `ELLIPSES`, `POLYGONS`. The JADGE model uses none
of them — only the single `ROOTCLUSTER` background — so device-and-label overlap
is the live mechanism there, but a general checker must not assume that.

### Rule 3 — if the validator prints a count, the count must be of *distinct* things

This is the rule that would have caught both bugs above, and it is one sentence:

> **If the validator prints a count, it must prove those items are distinct.**

`validate.py` asserted that AAA clients *existed* and printed `202`. There were
**140** distinct ones — the other 63 were the same phantom `192.168.10.1` copied
out of the device template onto every device. DHCP printed `259` against **131**
distinct, including 65 copies of a `serverPool 0.0.0.0/0.0.0.0` that no one
authored. Every count was inflated by exactly the amount of leftover template
data, and the validator reported **zero warnings**.

A presence check cannot fail this way and cannot catch it. So every reported
figure must be accompanied by its distinct count, and the validator must assert
they agree with what was *requested*:

```python
raw      = count_all(lab, family)          # 202
distinct = count_distinct(lab, family)     # 140
assert distinct == requested[family]       # the only assertion that means anything
assert raw == distinct                     # no silent duplication
```

`src/pkt_core/audit.py` implements this as deduplicating inventory
(`DedupCount` with `items`, `leftover_instances`, `leftover_identities`); the CLI
exposes it as `pkt audit`. If you add a counter anywhere, add its distinct
counter at the same time.

### Rule 4 — sanitise every field you did not author

**Sanitise every field you did not author.** Device templates are captured from
real saves, so they carry that save's live state — AAA client lists, DHCP pools,
DNS entries, NIC addresses — as *example* data, not as a blank form. Copying a
template into a new device copies all of it.

The generator now provisions each device from a **blank service slate** and then
writes only the services that were explicitly requested. `sanitize()` must reach
server service blocks (`ACS_CLIENTS`, `DHCP_SERVERS`, `DNS`), not just the
obvious per-device fields — the original `sanitize()` missed them entirely, which
is the root cause of the inflated counts above.

Related traps in the same family:

- **Name-keyed collisions.** Two sites both labelled "IRUMA" produced the same
  DHCP pool name for different subnets (`IRUMA-VLAN10` for both `10.11.10.0` and
  `10.29.10.0`). Packet Tracer pools are name-keyed, so one shadows the other.
  Include the site *number* in any generated key, not just the site label.
- **`<NAME translate="true">` is not the device name.** The physical-workspace
  location tree contains its own `<NAME translate="true">` elements, so a naive
  `/DEVICE/NAME` count double-reports (587 found against 297 real devices).
  Device names live under `<ENGINE>`.

### Rule 5 — a documented number is a claim; make it reproducible

`README.md` and `DESIGN.md` stated **22,579** config lines; counting `<LINE>`
elements in the shipped artefact gives **22,827**. Both figures were printed by
the same project. The block count (205) agreed exactly, so this was a
counting-method difference rather than data loss — but a published number that
cannot be reproduced by the obvious method is worse than no number.

**State the method alongside the figure** (`22,827 <LINE> elements across 205
RUNNINGCONFIG blocks`), and make the validator recompute it from the artefact
rather than from the generator's internal bookkeeping.

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
| `tools/check_layout.py` | **run this before shipping.** Device/label overlap, off-page devices, NN stats. Exits non-zero on any violation |
| `tools/repack_layout.py` | migrate an existing lab's coordinates to a clean layout (idempotent) |
| `tools/audit_ios_commands.py` | cross-check every emitted IOS line against what real Packet Tracer saves attest |
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
| `docs/ENTERPRISE_PROBLEMS.md` | 30 problems from a 290-device build, with status |
| `docs/POWER_INVESTIGATION.md` | the unpowered-device bug: cause, corpus evidence, fix |
| `docs/LAYOUT_INVESTIGATION.md` | overlap measurements vs. 167 human-authored devices |

Corpus: `corpus/CORPUS_INDEX.tsv` (SHA-256 manifest), `corpus/fetch_corpus.py`
(rebuilds it), `corpus/samples/` (self-authored, shipped).

## Limitations

`.pta` / `.pkc` / `sm` / `userapp` container flavours are specified
(`pkt_core.crypto.keys.FORMATS`) but untested — no real samples exist.
`pkt export` output has not been validated against live netbox/containerlab.

## License

GNU General Public License v3.0 or later.
