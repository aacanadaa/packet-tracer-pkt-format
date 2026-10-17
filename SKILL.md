---
name: packet-tracer-pkt-format
description: Read, author, modify and re-serialise Cisco Packet Tracer .pkt labs and scored .pka activities entirely offline. Covers both container families (PT 4.1 through 9.0.1), a byte-exact codec, a typed Python model, generators for full topologies and graded activities, and the fourteen rules for authoring large labs that actually work. Use when a task involves opening, inspecting, diffing, editing or creating Packet Tracer files, or building a lab at scale.
---

# packet-tracer-pkt-format

Everything here is **offline**. Packet Tracer is only needed to *open* a result,
never to build one — but you can and should open the result, because a file can
be byte-perfect and still render wrong.

Two failure modes are worth knowing before you write a line, because neither is
visible in the XML and both have shipped:

- **A cable is not a configuration.** `link()` draws the cable and sets the
  port's electrical properties; it does not give the interface a state. A lab can
  pass every structural gate with 87 cabled ports that nothing configures.
  → **Rule 7**, and gate 0.
- **A port name Packet Tracer cannot resolve makes the whole file unopenable** —
  not one dead cable, the entire document, with a message that names no device.
  → **Rule 8**, and gate 5.

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
- Build a lab at **scale** — see the fourteen rules and the gate chain below
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

## Authoring at scale — fourteen rules, learned by shipping broken labs

A 290-device enterprise model was generated, structurally validated, and shipped
with `RESULT: PASSED (0 warnings)` — and it was still wrong. The validator was
checking *presence*, never *uniqueness* or *authorship*; nothing checked position
or power at all; and the headline figures could not be reproduced from the file.

Then a 386-device one was built, passed **every** gate in the table below, and
shipped with **87 cabled ports that nothing configured**, five firewalls whose
own outside port was shut, and three port names that made the entire file refuse
to open. Rules 7 and 8 come from that second build.

These fourteen rules are the generalisation. They are not style advice — each one
corresponds to a defect that reached a delivered file. Rules 1–8 come from the
first two large builds; rules 9–12 come from a third, a 392-device air base,
where the layout itself was the defect; rules 13–14 come from
reorganising that lab into labelled sections.

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

And the second build, before and after rules 7 and 8:

| | shipped | after repair |
| --- | --- | --- |
| cabled ports with no `interface` block | **87** | 0 |
| ports administratively shut | **5** | 0 |
| links whose ends disagreed on trunk/access | **45** | 0 |
| red link-indicator pixels in the render | 4538 | **300** (all device artwork) |
| port names Packet Tracer rejects | **3** | 0 |


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

#### How many devices fit on a page — and why tier count decides it

The page is usually the binding constraint on scale, not the device count, and
the arithmetic is worth doing before choosing a size.

`check_layout.analyse()` calls `on_page(x, y)` with `allow_wrap=False`, and
`finalise_lab.py` gates on `off_page` being empty. **The packer's page-column
overflow is therefore not something the gates accept** — every device, plus its
label box, must be on the primary 3900×3900 page. At `ROW_PITCH = 150` that is
about **26 rows**.

`lab_api.Layout` gives each semantic tier its own band and stacks bands
vertically, so **each tier costs a row before a single device is placed**. A
model with 18 tiers has 8 rows left for devices; the same devices in 12 tiers
have 14. Measured: a 386-device model fits only because related zones share a
band, and an earlier 415-device arrangement of the same terminal did not.

The levers, in order of effect:

1. **Fewer tiers** — merge related zones into one band. This is free: it changes
   the picture's grouping, not the network.
2. **Shorter device names** — `column_pitch()` is 200 units for names up to 16
   characters, 260 for 17–24, 320 beyond. A 17-character hostname costs 30% more
   horizontal space than a 16-character one, for one character.
3. **Fewer devices**, last, because it costs scope.

Estimate before you build: `rows ≈ Σ ceil(n_tier / (3900 / pitch)) + n_tiers`,
and if that exceeds 26 the model will not fit however clean the cabling is.

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

#### Replication is not duplication — and Packet Tracer does not know that

Some identities are **document-wide** and some are **per device**, and the
difference decides how many servers you may run.

`duplicate-dhcp-pool` and `duplicate-aaa-client` are document-wide because
Packet Tracer keys DHCP pools and AAA clients by identity across the whole file.
A second DHCP server holding the same pools is therefore indistinguishable from
duplication, and the gate fails. **One authoritative server per service**, or the
count is a lie either way.

DNS is the exception the audit models explicitly: a zone is a *set per server*,
so two DNS servers holding the same records is replication and is reported as
`768 records (384 distinct × 2 servers)`. Do not "fix" that by deleting one.

If you want a standby node for realism, give it an address and no records, and
say so in the design document rather than leaving a passing gate to imply the
estate is redundant when it is not.

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
- **It is whole *blocks*, not just records.** Stripping leftover records is not
  enough: a harvested template ships the entire service block already marked
  `<ENABLED>1</ENABLED>`. On a 386-device build that meant **52 devices
  advertising themselves as NTP servers and 52 as HTTP servers**, none of which
  anyone authored — the audit's record-level check sees nothing wrong, because
  the records were correctly removed and the empty shell still says "enabled".

  Two passes are needed, and they are different jobs:

  ```python
  # 1. on a device we DO configure: clear every block, then write only what was asked
  def configure_server(dev_el, **requested):
      eng = dev_el.find("ENGINE")
      _strip_service_blocks(eng)          # DNS_SERVER, DHCP_SERVERS, ACS_SERVER, ...
      ...                                 # now write `requested`

  # 2. on a device we do NOT configure: remove the blocks entirely
  for key, sid in devices.items():
      if key not in configured_with_a_service:
          _strip_service_blocks(engine_of(sid))
  ```

  Measured effect on the published figures: `ntp/http/syslog servers` **52 → 1**.
- **Count a server only when it holds something.** Once the shells are gone,
  `findtext("ENABLED")` is not the test — count devices with an actual
  `RESOURCE-RECORD` / `POOL` / `CLIENT`. An empty shell is not a service.
- **Beware generic element names when counting.** `<USER>` is also an empty child
  of every device's inert `<EMAIL_CLIENT>`, so a document-wide `iter("USER")`
  reported **248 AAA servers** on a model that has one. Scope the search to the
  subtree that owns the concept (`ACS_SERVER`), not the whole device.

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

### Rule 7 — a cable is not a configuration

> **`lab_api.link()` draws a cable and sets the port's electrical properties. It
> does not give the interface a state.**

This is the same lesson as the serial-bearer warning above, generalised — and it
is the single largest defect class a generated lab ships with, because *nothing
in the existing gates can see it*. Layout passes (the devices are placed), the
audit passes (the services are distinct), the round-trip passes (the bytes are
valid). The links simply never come up.

Measured on a 386-device build that passed every gate:

| Defect | Count | Cause |
| --- | ---: | --- |
| `no-interface-block` | **87** | L3-to-L3 links drawn with `link()` instead of `rlink()`, so the generator's "routed interfaces" registry never learned about them. One core router had **no interface blocks at all** for either uplink — pure dead cables |
| `shutdown` | **5** | a firewall config ending in a blanket `interface Ethernet0/0` / `shutdown` also shuts the **outside** port. Never shut a port a zone depends on; shut only the ports nothing claims |
| `trunk-facing-access` | **45** | declaring *all* 24 ports of a collapsed-core switch as trunks, including the ones holding routed `/30`s — the later block reverts them to Layer 2, and every routed neighbour dies |

Two more ways it bites that are easy to miss:

- **A routed port written twice.** If a port appears as both a routed port
  (`no switchport` + `ip address`) and a trunk, the parser applies the *later*
  block. Emit each port's mode exactly once.
- **Router-on-a-stick parents.** Subinterfaces inherit the physical interface's
  state. `interface GigabitEthernet0/0/1.10 / no shutdown` does nothing if
  `interface GigabitEthernet0/0/1` was never brought up — and a subinterface-only
  config never mentions the parent.

**The fix is structural, not a longer list.** Derive each port's role from the
peer it is cabled to, so the two cannot disagree:

```python
for port, peer in cabled_ports(key).items():
    if port in routed_ports(key):     continue            # gets ip + no shutdown
    if peer in l3_keys:               trunks.append(port)  # peer terminates L3
    elif peer_model in NETWORK_MODELS: trunks.append(port) # switch-to-switch
    else:                             access[port] = default_vlan
```

and then **gate it**, because the discipline will drift:

```console
$ python3 tools/audit_links.py lab.pkt        # exit 1 on any finding
```

`tools/audit_links.py` reads the written artefact and asks one question per
cable — *would this port come up?* It needs no cooperation from the generator,
which is what makes it a real check. Measured on the repaired build: **380 links,
0 findings**, and sabotaging a single `no shutdown` makes it name the device,
port and peer.

### Rule 8 — a port name Packet Tracer cannot resolve makes the *whole file* unopenable

This is the most expensive lesson in this document, because the failure mode
looks nothing like its cause:

```
Unable to open file. The file ... is not compatible with this version of
Cisco Packet Tracer
```

One bad port name does **not** kill one cable. Packet Tracer refuses the entire
document — 386 devices, 1.3 MB — with a message that names no device, no port and
no reason. Every structural gate passes, because the XML is perfectly valid.

Measured, on Packet Tracer 9.0.1, from names the reference corpus "attested":

| Model | Corpus says | PT 9.0.1 accepts |
| --- | --- | --- |
| `7960` (IP phone) | `FastEthernet0` | **`Switch`** (uplink), `PC` (passthrough) |
| `Cloud-PT` | `GigabitEthernet0` | **`Port 0`** |
| `WLC-3504` | `GigabitEthernet0/1` | **`GigabitEthernet1`** |

Every `Ethernet0/1/2`, `GigabitEthernet0/0..0/5`, `Serial0/0/0` and `Coaxial1`
name was also tried on those three models and rejected.

**Corpus frequency is evidence of what some older Packet Tracer wrote, not of
what this one accepts.** Treat a port name as a fact you have not checked until
you have checked it:

1. **Template tier —** the model's own harvested factory config lists
   `interface <NAME>` lines. Strongest evidence; covers 29 of 137 models.
2. **Module tier —** ports a fitted module adds (`2911` + HWIC-2T →
   `Serial0/0/0`). A base inventory alone calls every serial bearer unattested.
3. **Attested tier —** a `<LINK><CABLE><PORT>` string naming that model in a real
   save.
4. **Convention tier —** **inference.** No factory config, so fall back to the
   module type: a lone `eCopperFastEthernet` is `FastEthernet0`, a lone
   `eCopperGigabitEthernet` is `GigabitEthernet0`. Verify before use.

Record the tier of every name, and **remove** names you measured as rejected
rather than annotating them — a table that still permits a rejected name will
pass a link the artefact cannot carry.

#### What cannot attest port names

- **The reference corpus has none of the industrial/IoT models.** A full mine of
  952 files found **zero** instances of `IE-9320`, `IE-3400`, `IE-2000`,
  `IR1101`, `CGR1240`, `ISA-3000`, `PLC-PT`, `HMI-PT`, `RFID Reader` or any
  sensor family. It is CCNA-era lab gear: 28 device classes in total.
- **Packet Tracer's own palette templates carry no port names.** The 89 `.ptd`
  files inside the AppImage decode cleanly with `pt9.decode(..., "pkt")`, but
  they describe modules and slots (`PT-IOT-NM-1CFE`), not instantiated names.
- **A model loading alone proves nothing about a cable.** All 46 candidate models
  load fine in a two-device file; that says nothing about whether a name resolves.

#### Reading `ENGINE/TYPE` — get this wrong and every lookup silently misses

```xml
<ENGINE><TYPE model="3650-24PS">MultiLayerSwitch</TYPE></ENGINE>
```

The element **text** is the device *class*; the **`model=` attribute** is the
model. `d.findtext("ENGINE/TYPE")` returns `"MultiLayerSwitch"`, which no port
table is keyed by — so a miner keyed on the text reports "28 models of interest,
all zero" and looks like it ran successfully. Use:

```python
t = dev.find("ENGINE/TYPE")
model = (t.get("model") or (t.text or "")).strip()
```

#### Verifying a rejection, without being fooled

- **Read the verdict from the window title**, not from a screenshot:
  `Incompatible File -- Cisco Packet Tracer`. OCR of the modal dialog reports
  *rejected* files as accepted — that mistake cost two blind alleys.
  `tools/pt_accept.py` does it correctly.
- **Reproduce before believing.** Several Packet Tracer instances launched in
  quick succession can show the dialog for a file that is fine. Always batch a
  **known-good control** alongside the suspect file; if the control also fails,
  the harness is at fault, not the lab.
- **Bisect, do not guess.** `pt_bisect.py` removes devices (and their physical
  workspace node and CPUR, so the document stays self-consistent) and halves on
  the failing subset. Note that a failure may need devices from both halves —
  "neither half fails alone" is a real outcome, not a bug in the tool.

### Rule 9 — the single writer's tier rules are one lab's naming convention

`finalise_lab.py` is the single writer, and its repack is not optional in
practice: it re-gates the bytes actually written. The repack groups devices into
horizontal bands by calling `lab_api.tier_for_name(name)`, whose built-in rules
are a **name-prefix table for one particular lab**:

```python
_TIER_RULES = (("airborne", r"^(E767|E2D|E2C|RC2)-\d\d-"), ("crc", r"^CRC-"),
               ("backbone", r"^(JADGE-BB-|CORE-RTR-|WAN-EDGE-|...)"), ...)
```

A second lab with its own hostnames matches none of them, so `tier_for_name`
returns `"misc"` for almost everything. **Every device collapses into one band**,
and the repack packs that band row-major — so a switch and its access devices end
up at opposite ends of the page. Measured on a 392-device lab: **361 of 392
devices matched no rule**, and a tenant switch sat **3,538 units** from its own
workstation.

Nothing fails. The repack succeeds, the audit passes, the round-trip is
byte-exact, and the picture is a tangle. It is the same shape as Rule 6 — a
check that asks "did the step run?" cannot see that the step did the wrong
thing.

The fix is to make the rules overridable and have each lab ship its own:

```python
lab_api.load_tier_map("build/tier_map.json")   # tried before the built-ins
```
```console
$ tools/finalise_lab.py --templates .../device_templates.json \
      --tiers build/tier_map.json lab.pkt
```

Both shapes are accepted: `{"rules": [{"tier": ..., "patterns": [...]}]}` or
`{"tier": ["pattern", ...]}`. Generate the map from the same table your diagram
uses, so the two can never disagree — three separate lists (generator grouping,
repack grouping, diagram grouping) is how this goes wrong.

### Rule 10 — a blank workspace is not proof that a lab failed to render

Three separate things look identical from outside, and only one of them is a
defect in your lab.

| What you see | What it actually is |
| --- | --- |
| `load-timeout` after 300 s, progress dialog still listed | **normal at scale.** A ~390-device lab takes **8–10 minutes** to parse and draw (RSS ≈ 4.2–5.0 GB), and up to ~25 minutes if another Packet Tracer is running |
| the progress dialog never clears | Packet Tracer raises a modal prompt while it is still up, so "the dialog went away" is not a completion signal. The workspace draws *behind* the prompt |
| an empty untitled window, no prompt | **the document was closed** — see below |

The prompt reads *"This file contains N device(s) that have outdated run-time
scripts"* and offers **Yes** / **No** / Update and Make a Copy. **Return activates
the default, Yes**, which rewrites every affected device's run-time script — on a
392-device lab that closes the document and leaves an empty 541 MB process.
**Escape selects No** and the loaded topology survives.

Two more ways to break a load that are not about the file:

* **Do not resize the document window before the load finishes.** Packet Tracer
  restores its own geometry when a load completes; a tool that resizes first and
  waits second ends up driving a window that has already been replaced.
* **Wait for evidence, not for a dialog.** The usable signal is "is anything
  drawn on the canvas" — saturated pixels inside a canvas rectangle that is
  derived from the window geometry in **both axes**. A fixed rectangle samples
  the device palette on Packet Tracer's default 950×700 window (whose icons are
  highly saturated) and reports a blank workspace as loaded.

And the control that settles it: with **no interaction at all**, at 10.5 minutes
the title still carried the file path, the prompt was up, RSS was 4.95 GB and the
canvas had 4,578 saturated pixels — loaded, drawn and stable. Batch a known-good
control with every capture; if the control renders and your lab does not, then
you have a lab problem, and if neither renders you have a harness problem.

### Rule 11 — the packer packs in *document order*, so the document order is the layout

`Layout.place()` is called in the order the `<DEVICE>` elements appear, and each
band is filled row-major. So the order you *create* devices in is the order they
are packed in, and that is the difference between a readable model and spaghetti:

* **Emit each band as a breadth-first walk of its own cable graph.** A band whose
  devices are created "switch, then everything else" packs its switch at one end
  and its access devices at the other.
* **Size the chunks to one packing row.** A cluster that straddles a row boundary
  gets its switch at one end of the page and its children at the other; a chunk
  that *is* a row cannot straddle.
* **Centre the hub in its row.** A hub at one end is ~3,400 units from the child
  at the other; in the middle it is at most half that, and its fan is symmetric.
* **Order the bands by the cable graph, not the narrative.** A fan is shortest
  when its source sits at the centroid of its destinations. Measured on the
  392-device lab, **70% of all crossings involved a core-band cable** with the
  core at the top; moving it to the middle of the band order cut crossings.

Measured effect of all four, on one lab: crossings **1,645 → 1,321 (−20%)**,
95th-percentile cable length **2,916 → 2,408 (−17%)**, mean **1,142 → 992
(−13%)**. Reordering is free — it changes nothing about the network.

**At ~390 devices the page is saturated, and that is the binding constraint.**
392 label-inclusive boxes at a 200-unit pitch need about 11.8 M units² of a
14.4 M unit² page. Cluster-block placement *with gaps* does not fit — measured,
it overflows to y≈4,265 — which is exactly why the row-major packer wraps
clusters. If a model must be genuinely tidy, that is an argument for fewer
devices per page, not for a cleverer packer.

**Measure it, do not eyeball it.** `tools/check_readability.py` reports crossings,
crossings per cable, and cable-length min/median/p95/max, plus which band each
cable belongs to:

```console
$ python3 tools/check_readability.py lab.pkt --max-crossings-per-cable 4.0
```

A lab can pass `check_layout.py` — no overlap, nothing off-page, no coincident
pair — and still measure 4.4 crossings per cable. Geometry and legibility are
different properties, and only one of them has a stock gate.

### Rule 12 — derive a port's VLAN from its peer, not from a table beside it

The same discipline as Rule 7, applied to Layer 2. A hand-maintained
port-to-VLAN map drifts from the cabling, and it drifts silently: the port still
comes up, it is just in the wrong VLAN, or it is written once as a trunk and once
as an access port and the parser applies whichever came last.

Three of the defects found on a 392-device build were exactly this — uplinks that
were *also* declared as access ports, tank and level monitors sharing one port
range (two cables on one port), and a zone router that was placed, cabled and
addressed but never configured at all.

The rule: **a port's access VLAN is the VLAN of the device plugged into it**,
taken from that device's own default gateway (`10.<site>.<vlan>.1` → `<vlan>`),
and anything the explicit map did not mention is completed from the cabling and
recorded in the build report. The explicit map then only has to name the
uplinks — and a table that short is a table that stays correct.

### Rule 13 — a band of loose icons is still a chain: give the model *sections*

A band of 60 icons on one row tells a reader that there are 60 devices and
nothing else. They cannot find the fuel farm. Rows are a packing strategy, not an
organisation.

The fix is to place each **section** — a place a reader looks for — as its own
compact block with space around it, and draw a boundary round it. Two warnings
first, because the obvious approach is wrong in a way that is easy to miss.

#### A cluster is a container, not a group box — it hides what it contains

Packet Tracer's cluster looks like the right feature, and its XML is easy to
find in Cisco's own labs:

```xml
<CLUSTER>
  <NAME translate="true">Internet</NAME>
  <X>1223</X><Y>292</Y>
  <CLOUDID>1-1</CLOUDID>
  <CLUSTERID>2-{356f3541-68b0-4eea-a043-3eab794b0192}#2</CLUSTERID>
  <MEM_ADDR>2569540347280</MEM_ADDR>
  <CLUSTER_BG_IMAGE isanim="false" />
  <CLUSTER_EMBEDDED_BG_IMAGE />
  <CLUSTER_ICON_IMAGE>../art/Workspace/Logical/iCluster.png</CLUSTER_ICON_IMAGE>
  <TILED_BG>false</TILED_BG>
</CLUSTER>
```

at `PACKETTRACER5/CLUSTERS/ROOTCLUSTER/CLUSTER`, with membership on the device:

```xml
<WORKSPACE><LOGICAL>
  <X>948.5</X><Y>225</Y>
  <DEVCLUSTERID>2-{356f3541-...}#2</DEVCLUSTERID>
```

**But a cluster is a collapsible container.** Packet Tracer renders it as a
single icon carrying the cluster's name, and its member devices are *inside* it —
invisible until someone expands it by hand. Measured on a three-device probe:

```
3 PCs, one of them in a cluster named "Section A"
  -> renders as: PC-PT A1 --- PC-PT A2 ... and ONE icon captioned "Section A"
```

Scale that to a 392-device lab in 16 clusters and the entire model appears to
vanish: sixteen icons on an empty page. That is what "the render never finished"
looked like for two days of captures — the file was fine and the devices were
simply collapsed. **Do not use a cluster to draw a labelled box around devices
you want to see.**

#### Draw a rectangle instead

A `RECTANGLE` is a plain drawing-layer element: no grouping, no collapsing,
devices stay visible. Same provenance, `PACKETTRACER5/RECTANGLES/RECTANGLE`:

```xml
<RECTANGLE uuid="{...}">
  <TopLeftX>353</TopLeftX><TopLeftY>1001</TopLeftY>
  <BottomRightX>764</BottomRightX><BottomRightY>1375</BottomRightY>
  <Color><Red>21</Red><Green>101</Green><Blue>192</Blue></Color>
  <Filled OUTLINED="true" OUTLINECOLOR="#1565c0">0</Filled>   <!-- 0 = hollow -->
  <RECTCLUSTERID>1-1</RECTCLUSTERID>
  <MEM_ADDR>...</MEM_ADDR>
</RECTANGLE>
```

(`LINES`, `ELLIPSES` and `POLYGONS` are siblings with the same geometry idiom.)

#### You cannot put a name on the logical canvas

There is **no logical-canvas text element**. `NOTE` exists, but every instance
across 293 shipped labs sits under
`PHYSICALWORKSPACE/.../NOTES/NOTE`, i.e. it annotates the *physical* view; there
is no root-level `NOTES` and no "note" device type. So a section boundary can be
drawn on the canvas, but its *name* has to live in the diagram and the documents.
Plan for that rather than discovering it after wiring up a naming scheme.

**Choose section granularity to fit.** Measured on a 392-device model, per-cluster
blocks (a switch plus its own access devices) do **not** fit: 392 boxes at a
200-unit pitch need 11.8 M units² of a 14.4 M unit² page, and the blocks overflow
to y≈4,265. Sixteen sections fit comfortably. Sections are coarse enough to be
places; clusters are too fine to be page units.

Effect on that model, same network throughout:

| | before | after |
| --- | ---: | ---: |
| cable crossings | 1,645 | **1,079** (−34%) |
| crossings per cable | 4.43 | **2.90** |
| median cable | 888 u | **410 u** (−54%) |
| mean cable | 1,142 u | **515 u** (−55%) |

Cables get short because a section is a compact block, so most cables are
intra-section. The boundaries also make the picture *navigable*, which no metric
captures.

#### A corpus you already have — 299 Cisco-authored labs in the AppImage

`corpus/fetch_corpus.py` is not the only way to get real Packet Tracer files.
Packet Tracer ships its own example labs:

```console
$ cd /tmp && /opt/pt/packettracer.AppImage --appimage-extract >/dev/null
$ find squashfs-root/opt/pt/saves -name '*.pkt' | wc -l
293
```

They are current-version, Cisco-authored, and cover switching, IPv6, IoT, OT,
cyber and automation — including files that use the drawing layers this document
otherwise cannot show you an example of. `pt9.decode_bytes(open(f,'rb').read(),
"pkt")` reads them directly. Mine them before downloading anything:

```console
$ python3 - <<'EOF'
import glob, xml.etree.ElementTree as ET
from pkt_core import decode_bytes
for f in glob.glob("/tmp/squashfs-root/opt/pt/saves/**/*.pkt", recursive=True):
    root = ET.fromstring(decode_bytes(open(f,'rb').read()).xml)
    if list(root.iter("CLUSTER")):
        print("has clusters:", f)
EOF
```

### Rule 14 — three things that make a build non-reproducible, all invisible

A published SHA-256 that cannot be re-derived is worse than no hash. All three of
these produce a *successful* build whose bytes differ between runs:

| Source | Why | Fix |
| --- | --- | --- |
| `uuid.uuid4()` for generated ids (cluster ids, synthetic refs) | random per run | `uuid.uuid5(NAMESPACE_URL, stable_string)` |
| `hash(some_string)` for a synthetic numeric field | Python randomises string hashing **per process** (`PYTHONHASHSEED`) | derive from the stable id, e.g. `uuid5(...).int % 10**12` |
| seeding a walk from a `set` | set iteration order varies between processes, so the *device order* changes — and with it the whole layout | keep an ordered list, or break ties on the creation index |

The third is the expensive one: on a 392-device model it changed **84,658 lines**
of XML between two runs. Verify by building twice and comparing digests, not by
reading the code — and note that a diff of two builds is the fastest way to find
which of the three you have.

## Before you ship — run the gates, in this order

Rules 1–8 are disciplines; these are the commands that *enforce* them. Each exits
non-zero on failure, so they compose in a script: `generators/jasdf_aewc/run_all.sh`
chains gates 1–3 (plus its own `validate.py`, which adds the `hostname <name>`
identity check from Rule 6) and then builds the diagrams, docs and checksums. Gates 4
and 5 are heavier and were run separately as evidence, not on every build. Run from
the repo root with the venv active.

| # | Command | Proves | Non-zero when |
|---|---|---|---|
| 0 | `python3 tools/audit_links.py lab.pkt` | **every cabled port is brought up by the configuration that ships with it** — no missing interface block, no shutdown, no routed-and-trunk port, no trunk facing an access port | any link endpoint would not come up (exit 1) |
| 1 | `python3 tools/finalise_lab.py lab.pkt --templates tools/device_templates.json --tiers build/tier_map.json` | the single writer: sanitises un-authored fields, repacks, then **re-gates the bytes actually written** — layout, audit, and byte-exact decode round-trip | layout violation, audit finding, or round-trip DIFFERS (exit 1) |
| 2 | `python3 tools/check_layout.py lab.pkt` | geometry — label boxes, on-page, coincidence, NN spacing | any overlap, off-page icon, coincident pair, unreadable file (exit 1) |
| 3 | `python3 tools/check_readability.py lab.pkt` | **the model is legible** — crossings per cable and cable-length percentiles, exiting non-zero above a threshold. Geometry and legibility are different properties and `check_layout.py` only measures the first |
| 4 | `pkt audit lab.pkt --templates tools/device_templates.json` | raw **and** distinct counts per service family, template leftovers | any duplicate — i.e. a count that was never distinct (exit 1) |
| 5 | `python3 tools/audit_ios_commands.py --artifact lab.pkt --corpus <corpus>` | every config line against the attested corpus | a **suspicious** signature (exit **2**). Unattested-but-plausible lines are reported and do *not* fail — 136 of 235 signatures are normally UNATTESTED, so exit 0 here is the expected state |
| 6 | `python3 tools/pt_accept.py lab.pkt control.pkt` | Packet Tracer actually opens it — verdict read from the window title | `Incompatible File` for the lab but not the control (exit 1) |
| 7 | `python3 tools/pt_runtime_verify.py --artifact lab.pkt` | it renders, converges and passes traffic | load failure, unreachable host |

Gate 1's round-trip check is the library's core promise tested on real output, not on a
fixture: the bytes written are decoded again and compared. If that line says `DIFFERS`, the
artifact is not shippable no matter what else passed.

**Gate 0 is the one that catches Rule 7**, and it is cheap — a static XML read, no
Packet Tracer. It is worth running before gate 1, because a lab full of dead links
otherwise passes everything and looks finished.

**Gate 6 is the only one that can catch Rule 8** — a port name Packet Tracer refuses.
Gate 7 subsumes it, but gate 6 returns in seconds where gate 7 takes minutes, so run it
first when iterating on cabling.

Gate 5 needs the reference corpus, which is *not* committed (see `corpus/README.md`;
`python3 corpus/fetch_corpus.py` reproduces it). Point `--corpus` at wherever that put the
files — the decoded result is cached in `build/ios_attestation.json`, which records the
`corpus_dir` it used, so a re-run is fast. On the shipped lab it decodes 1,058 files and
reports 0 suspicious.

Gates 0–4 are static and fast. Gate 5 needs a cold-cache corpus decode first
(~1–3 min for 1,058 files), then it is cached. **Gate 6 is the only one that can catch
problem 8** (a bearer that is structurally perfect and functionally dead) and problem 24
(structure ≠ function). If you can only run one, run gate 6 — it needs PT under Xvfb, which
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

Things that look like failures and are not. Chasing them wastes a cycle; "fixing" them
breaks a correct lab. Each is recorded with its probe in `docs/ENTERPRISE_PROBLEMS.md` (JASDF build) or
`docs/ENTERPRISE_PROBLEMS_YAMLT.md` (container-terminal build).

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

- **Red pixels in the render that are not links.** Before concluding a lab is full of dead
  cables, identify the red. Two device icons draw red *by design*: the **Trip Sensor** is a
  trip wire rendered as a red line between two posts, and the **ASA 5505** has a red front
  panel. On a 386-device model, an automated red-pixel count fell to 300 after the cabling
  was fixed — and **all 300 were these icons**. A red pixel is only evidence once you have
  cropped it and looked.

- **A screenshot at the wrong moment.** Pixel-counting a render is a good objective measure
  only if both images frame the same thing: a layout shift between builds moves devices out
  of the crop, and the counts stop being comparable while still looking like data. Crop the
  same canvas region from both and sanity-check the totals.

- **"Incompatible File" on a file that then loads.** Several Packet Tracer instances launched
  in quick succession can raise the dialog for a perfectly good file. Since the message is
  Packet Tracer's *only* parse error, this is indistinguishable from Rule 8 by eye. Reproduce
  a rejection, and always batch a known-good control with the suspect file.

- **A load that "times out" but actually succeeded.** Packet Tracer raises two informational
  prompts on opening a lab built from many templates — `Update Devices?` and
  `Network Controller External Access`. A verifier that waits for the *"Please wait. Opening
  file..."* window to clear never sees it clear, and reports a load timeout on a file that is
  already open. The window list tells the two apart at a glance:

  ```
  ['Cisco Packet Tracer - /tmp/lab.pkt -', 'Please wait. Opening file...']      <- still loading
  ['Cisco Packet Tracer - /tmp/lab.pkt -', 'Update Devices? -- Cisco P...']     <- loaded, asking
  ```

  Dismiss the prompts and screenshot what is drawn.

Corollary: a gate that fails is not automatically a defect in your lab, and a gate that
passes is not proof of correctness. Check *which* gate and *what* it actually measured
before reacting to either.

## Driving Packet Tracer's GUI under Xvfb

Gate 5 and gate 6 need a real Packet Tracer, and the automation has sharp edges.

- **Keyboard accelerators do not work.** With no window manager there is nothing to deliver
  the accelerator, so `Alt+v` never opens the View menu and `ctrl+minus` only scrolls. Use
  `xdotool` clicks on the toolbar.
- **Know which toolbar button you are clicking.** A 4× crop of the toolbar is the only
  reliable way to identify the icons. At 1600×1000 the zoom controls sit at y=38:
  **zoom-in (`+` magnifier) x=382**, `R` (reset) x=416, **zoom-out (`−`) x=450**.
  Clicking 384 repeatedly *zooms in* and produces a blank white workspace that reads exactly
  like a render failure. It is not.
- **Resize the window before zooming out.** A 3900×3900 page cannot fit a 950×460 viewport
  at any readable zoom, so "the whole topology" is either one corner or a handful of specks.
  `xdotool windowsize` to nearly fill the virtual screen first — Packet Tracer accepts about
  1400×1840 under a 1400×1900 Xvfb screen.
- **`xdotool mousemove --sync` can hang forever** without a window manager (it waits for a
  pointer-motion event that never arrives). Drop `--sync`, and pass a timeout.
- **Saving is unreliable.** `ctrl+s` is a keyboard accelerator, so it usually does nothing;
  do not build a check that depends on Packet Tracer writing the file back. Read the verdict
  from window titles and screenshots instead.


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
| `tools/audit_links.py` | **run this before shipping.** Every cabled port against the config that should bring it up — missing interface block, shutdown, routed-and-trunk, trunk facing access. Exits non-zero on any finding (Rule 7) |
| `tools/pt_accept.py` | **does Packet Tracer open it?** Verdict read from the window title, not from OCR. Batch a known-good control (Rule 8) |
| `tools/check_layout.py` | **run this before shipping.** Device/label overlap, off-page devices, NN stats. Exits non-zero on any violation |
| `tools/check_readability.py` | **run this before shipping too.** Crossings, crossings per cable, cable-length percentiles, per band. A lab can pass `check_layout.py` and still measure 4.4 crossings per cable |
| `tools/repack_layout.py` | migrate an existing lab's coordinates to a clean layout (idempotent) |
| `tools/audit_ios_commands.py` | cross-check every emitted IOS line against what real Packet Tracer saves attest |
| `tools/pt_runtime_verify.py` | open a lab in a real Packet Tracer under Xvfb and collect rendering, convergence and traffic evidence |
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

## A worked example of all fourteen rules

`generators/jasdf_aewc/` is the 290-device lab that rules 1–6 came from. A second,
386-device lab — an automated container terminal with 12 ship-to-shore cranes, 16
yard blocks, an AGV fleet, a customs enclave and an industrial OT estate — was
built on the same toolkit and is published with its full gate history at
[`aacanadaa/large-scale-packet-tracer`](https://github.com/aacanadaa/large-scale-packet-tracer).
Rules 7 and 8 come from it, and it is the reference for:

- deriving each port's role from its peer instead of a hand-maintained list;
- a four-tier port-name table with the rejected names recorded;
- `pt_bisect.py`, `pt_render_check.py` and `pt_fullview.py` in practice;
- what "all links are up" actually looks like once measured rather than eyeballed.


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
| `docs/ENTERPRISE_PROBLEMS.md` | 38 problems from the 290-device JASDF build, with status — produced rules 1–6 |
| `docs/ENTERPRISE_PROBLEMS_YAMLT.md` | 21 problems from the 386-device container-terminal build, with status — produced rules 7–8 |
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
