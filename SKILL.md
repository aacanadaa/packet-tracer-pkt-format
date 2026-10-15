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
$ python -m pytest tests/               # the bar is 0 failures
```

Do **not** pass `-q`: `pyproject.toml` already sets
`addopts = "-q --strict-markers -m 'not corpus'"`, so a second `-q` makes it `-qq`
and suppresses the summary line entirely — you get dots and no count. The default
run deselects the slow corpus tests; opt into those with `-m corpus`.

Observed with `pkt_core_native` installed, at this commit:

```
542 passed, 1 skipped, 35 deselected
```

The exact totals grow as tests are added — treat **0 failures** as the invariant and
the skip count as environmental: the Rust-accelerator tests skip when
`pkt_core_native` is absent, so a large skip count means a missing optional
accelerator, not a broken checkout.

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
from pkt_core import decode, decode_bytes, encode_bytes   # container level
from pkt_core.models import Lab                           # not re-exported by pkt_core

container = decode("lab.pkt")                   # verifier-based format detection
container.root_tag, container.is_activity       # 'PACKETTRACER5', False
lab = Lab.from_bytes(container.xml)

lab.version                                     # '9.0.1.0858'
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

out = encode_bytes(lab.to_xml(), container.format_name)   # byte-exact if unmodified
```

`root_tag` / `is_activity` live on the **container**; `version` lives on the **lab**.
`Lab` is not exported from the `pkt_core` package root — import it from `pkt_core.models`.

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

**Two ways to name a bay, and they are not the same thing.** `install=` / the default
`bay=0` means *the next empty bay* — the right choice when you are filling bays in order,
which is why the example above needs no bay number. `install_module(..., slot=N)` means
*absolute bay N*, counting occupied ones, and does not shift as other bays fill. Use
`slot=` only when a specific bay matters. `bay=N` for N > 0 **raises** on purpose: it used
to index the list of *currently empty* bays, which renumbers as they fill, so `bay=1`
silently skipped a bay after `bay=0` was used (problem 7). One module fills one bay.

**A cable is not a configuration.** `lab.link()` draws the cable and sets the port's
electrical properties; it does not give an interface an address. If your config emitter is
driven by a registry of routed interfaces, then a bearer that was never registered gets no
`interface` block, no `ip address`, no `no shutdown` — and the cable renders **dead** while
every structural gate still passes. This is exactly how the 36 serial bearers in the
enterprise lab shipped unaddressed (problem 8), and it was found only by opening the file
in Packet Tracer.

The gap is visible if you look: after a bare `link(kind="serial", dce=r1)`, the DCE's
config ends with

```
interface Serial0/0/0
 clock rate 2000000        <- the cable's timing
end                        <- and nothing else: no ip address, no no shutdown
```

That is a live interface with no identity. Both ends need a `/30` and `no shutdown`:

```python
# schematic — this is the shape of JASDF.slink() in the enterprise generator,
# not runnable lab_api; alloc_p2p/routed/M30 are the generator's own helpers.
ia, ib = alloc_p2p()                       # e.g. 10.99.6.0/30
routed += [(r1, "Serial0/0/0", ia, M30), (r2, "Serial0/0/0", ib, M30)]
lab.link(r1, "Serial0/0/0", r2, "Serial0/0/0",
         kind="serial", dce=r1, clock=2_000_000)
```

For serial, pass `kind="serial"` and name the **DCE** end with `dce=`; `link()` then writes
`CLOCKRATE`, `CLOCKRATEFLAG=true` and `POWER=true` on that port itself, and appends an
`interface … / clock rate …` fragment to that device's config.

Note the interaction: because `link()` *appends* to `RUNNINGCONFIG`, a later wholesale
config rewrite (delete the `RUNNINGCONFIG` and re-emit it) silently discards that fragment.
That is why the generator registers both ends in its `routed` list first and lets
`router_config()` emit the address, `no shutdown` **and** `clock rate` together — so the
interface block survives the rewrite and the port-level timing from `link()` backs it up.

Without timing from exactly one end the line stays down and the cable draws red (see the
false-alarm section below — red alone is not proof of a fault, but red *with no address*
is).

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

## Authoring at scale — six rules, learned by shipping a broken 290-device lab

A 290-device enterprise model was generated, structurally validated, and shipped
with `RESULT: PASSED (0 warnings)` — and it was still wrong. The validator was
checking *presence*, never *uniqueness* or *authorship*; nothing checked position
or power at all; and the headline figures could not be reproduced from the file.
These six rules are the generalisation. They are not style advice — each one corresponds to
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

**But power has two levels, and only the device level is inherited for you.**
`<ENGINE><POWER>` is the device's on/off switch; `<PORT><POWER>` is the
interface's. `normalise_device_power()` deliberately rewrites *only* the engine
element — `<PORT><POWER>` is left exactly as harvested (problem 9). That is
correct, because port power is a statement about **your** cabling, not the
donor's state: a port you cabled is by definition powered.

So a harvested template whose ports ship off produces dead links on a device
that is itself switched on. `AccessPoint-PT` is the real case: it carries
`<POWER>false</POWER>` on its ports, so every WLAN link rendered down until the
generator raised `POWER` on each cabled port (`ports_powered_on: 178`). If you
cable a port, set its `POWER` to true — and note that `<PORT><POWER>` sits after
`<TYPE>`, so a regex written for the engine-level element will silently miss it.

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

**State the method alongside the figure** (`22,896 <LINE>` elements across 205
`RUNNINGCONFIG` blocks; 22,648 of them on the 143 IOS/ASA devices), and make the
validator recompute it from the artefact rather than from the generator's
internal bookkeeping.

Two further lessons came out of this one:

* **A statistic two tools derive differently is not a statistic.** The audit
  counted IOS devices by the presence of a `<STARTUPCONFIG>` element and
  `validate.py` counted them by model. Both said 143 — by coincidence, and for
  opposite reasons. Give the definition one home (`NETWORK_DEVICE_MODELS`) and
  have both key off it.
* **When the number moves, say why.** These figures went 22,579/22,827 →
  22,648/22,896 because an unconfigured device was found and configured. Because
  the method is printed with the figure, the change is visible and explicable
  instead of silent.

### Rule 6 — a presence check is not an authorship check

Every defect in this section shares one root cause, and it is worth stating on
its own because it is the easiest mistake to make and the hardest to notice:

> **A harvested template always supplies an answer.** "Has a value" therefore
> passes on a device nobody configured.

`validate.py` asserted that all 143 network devices "carry a config" — and a
factory default *is* a config. So it passed while the file shipped:

* 20 devices whose startup config came from another lab (`hostname Router`,
  `hostname ciscoasa`, ASA Version 8.4(2), dated Mar 1993);
* 16 of them carrying `enable secret 5 $1$mERr$…` — the type-5 hash of `cisco`,
  the publicly known default — while their *running* config carried the intended
  secret, so the file disagreed with itself about how to log in;
* `COALITION-GW-01` completely unconfigured, while `PARTNER-RTR-01` was set up to
  peer with its address, so the documented eBGP path could not come up.

All three passed a check that only asked "is there a config?".

The fix is to assert something a template default cannot satisfy. Here that is
identity:

```python
misnamed = [devs[s] for s in netdev if f"hostname {devs[s]}" not in cfgs[s]]
```

Before → after, on the real file:

```
FAIL  1 network devices carry a config that does not name them
      (template default or wrong device): ['COALITION-GW-01']    exit 1
ok    config identity: all 143 configs set 'hostname <device>'
```

Where identity is not available, use **distinctness** (Rule 3) or **derivation**:
a value the generator computed from the device's own name or address cannot be a
leftover. Never a bare presence test.

This also explains Rule 1. The template's `POWER` is an answer; writing a
constant over it *lost* the template's authorship, and then a presence check that
saw `POWER` at all was satisfied.

## Before you ship — run the gates, in this order

Rules 1–6 are disciplines; these are the commands that *enforce* them. Each exits
non-zero on failure, so they compose in a script: `generators/jasdf_aewc/run_all.sh`
chains gates 1–3 (plus its own `validate.py`, which adds the `hostname <name>`
identity check from Rule 6) and then builds the diagrams, docs and checksums. Gates 4
and 5 are heavier and were run separately as evidence, not on every build. Run from
the repo root with the venv active.

| # | Command | Proves | Non-zero when |
|---|---|---|---|
| 1 | `python3 tools/finalise_lab.py lab.pkt --templates tools/device_templates.json` | the single writer: sanitises un-authored fields, repacks, then **re-gates the bytes actually written** — layout, audit, and byte-exact decode round-trip | layout violation, audit finding, or round-trip DIFFERS (exit 1) |
| 2 | `python3 tools/check_layout.py lab.pkt` | geometry — label boxes, on-page, coincidence, NN spacing | any overlap, off-page icon, coincident pair, unreadable file (exit 1) |
| 3 | `pkt audit lab.pkt --templates tools/device_templates.json` | raw **and** distinct counts per service family, template leftovers | any duplicate — i.e. a count that was never distinct (exit 1) |
| 4 | `python3 tools/audit_ios_commands.py --artifact lab.pkt --corpus <corpus>` | every config line against the attested corpus | a **suspicious** signature (exit **2**). Unattested-but-plausible lines are reported and do *not* fail — 136 of 235 signatures are normally UNATTESTED, so exit 0 here is the expected state |
| 5 | `python3 tools/pt_runtime_verify.py --artifact lab.pkt` | Packet Tracer actually loads it: renders, converges, pings | load failure, unreachable host |

Gate 1's round-trip check is the library's core promise tested on real output, not on a
fixture: the bytes written are decoded again and compared. If that line says `DIFFERS`, the
artifact is not shippable no matter what else passed.

Gate 4 needs the reference corpus, which is *not* committed (see `corpus/README.md`;
`python3 corpus/fetch_corpus.py` reproduces it). Point `--corpus` at wherever that put the
files — the decoded result is cached in `build/ios_attestation.json`, which records the
`corpus_dir` it used, so a re-run is fast. On the shipped lab it decodes 1,058 files and
reports 0 suspicious.

Gates 1–3 are static and fast. Gate 4 needs a cold-cache corpus decode first
(~1–3 min for 1,058 files), then it is cached. **Gate 5 is the only one that can catch
problem 8** (a bearer that is structurally perfect and functionally dead) and problem 24
(structure ≠ function). If you can only run one, run gate 5 — it needs PT under Xvfb, which
works offline here:

```console
$ xvfb-run -a python3 tools/pt_runtime_verify.py --artifact lab.pkt \\
      --username admin --password cisco --outdir build/verify
```

Then the checks no tool can make for you:

- **Can anyone log in?** Device credentials (`username`/`enable secret`, line vty) must be
  documented in the README or derivable from the file — a lab nobody can enter is not a lab
  (problem 36). Gate 5 needs these too, which is why it takes `--username/--password`.
- **Does the published number match the gate's number?** Rule 5. Re-run `--update-report`
  after any edit; a figure typed from memory is a claim, not a measurement.
- **Would it run on someone else's machine?** No absolute paths in anything you ship
  (problem 32):

  ```console
  $ grep -rn '/home/\|/Users/' --include='*.py' --include='*.sh' <shipped tree>
  ```

  This is not hypothetical — a sweep of this repo found **seven** scripts that hardcoded
  `/home/saoria/testing/packet-tracer-pkt-format`, a *different, stale checkout*. They
  worked on the author's box (the path existed) and silently imported old code, and would
  have died with `ModuleNotFoundError` anywhere else. Two of them were called by
  `run_all.sh`. Resolve the toolchain instead of pinning it:

  ```python
  def _find_toolkit() -> Path:
      env = os.environ.get("PKT_TOOLKIT")          # explicit override wins
      if env:
          return Path(env)
      for cand in Path(__file__).resolve().parent.parents:   # else search upward
          if (cand / "tools" / "lab_api.py").is_file() and (cand / "src" / "pkt_core").is_dir():
              return cand
      raise SystemExit("error: cannot find the pkt-core toolkit; set PKT_TOOLKIT")
  ```

  An env-var default like `os.environ.get("PKT_TOOLKIT", "/home/you/...")` is not enough on
  its own: it still breaks for anyone who does not set the variable. Search upward and fail
  with a message that says how to fix it.

  The same sweep caught a second-order version: `docs/CORPUS_REPORT.md` cited
  `tools/phase1_inventory.py` for its numbers, but that script lived outside the repo — so
  the report was not reproducible from what shipped. Cite only what you ship, and ship what
  you cite.

## False alarms — what Packet Tracer's rendering does *not* mean

Four things look like failures and are not. Chasing them wastes a cycle; "fixing" them
breaks a correct lab. Each is recorded with its probe in `docs/ENTERPRISE_PROBLEMS.md`.

- **Amber link lights after opening.** Packet Tracer runs spanning-tree convergence on load,
  so access ports show amber for the first ~30 s (problem 14). Toggling Realtime⇄Simulation
  3–4 times clears it. Amber is STP *state*, not a broken link — on a topology with
  redundant paths, some ports are *supposed* to be amber, and all-green would mean you had
  accidentally built a loop-free tree.
- **Convergence taking longer than 75 s on a large lab.** At 290 devices/31 switches the
  convergence time is unbounded and **run-dependent** — the same file converged fully on an
  earlier run (problem 15). Verified via
  `generators/jasdf_aewc/tools/stp_probe.py`: the same switch config is green in
  isolation. Re-run rather than redesign.
- **Red serial cables.** Packet Tracer draws serial cables red *regardless of link state*; a
  minimal 2911↔2911 probe shows a red cable with **green** indicators at both ends
  (problem 28). With 36 serial bearers this is very easy to misread as mass link failure.
  Red is only meaningful together with evidence — e.g. red *and* no address on the interface.
- **A duplicate `<NAME>` in the XML.** `<NAME translate="true">` appears in the physical
  workspace tree as well as at `ENGINE/NAME` (problem 30), so a naive "find every NAME and
  check uniqueness" sweep reports collisions that are not real. Resolve names at
  `ENGINE/NAME`.

- **An empty sanitiser report.** This one is not Packet Tracer's fault, and it is the most
  dangerous entry here because it looks like success. `audit._engine_views()` resolves a
  *direct child* named `ENGINE`, so it returns `[]` for anything else — **including a
  whole-document root** — and `sanitize_template_leftovers(root)` then returns an empty
  report that reads exactly like "nothing to clean" while removing nothing (problem 33).
  Measured on the shipped lab, whose root tag is `PACKETTRACER5`:

  ```
  _engine_views(root)   -> 0 engine(s)     <- silent no-op
  _engine_views(DEVICE) -> 1 engine(s)
  but the document holds 290 DEVICE elements
  ```

  Callers must pass `DEVICE` elements. More generally: when a cleaning or checking helper
  reports "no findings", confirm it examined something before you believe it — pass a target
  that *should* produce findings, or assert how many things it looked at. An empty result
  and an empty scope are indistinguishable from the outside.

Corollary: a gate that fails is not automatically a defect in your lab, and a gate that
passes is not proof of correctness. Check *which* gate and *what* it actually measured
before reacting to either.

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
