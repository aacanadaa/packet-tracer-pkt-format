---
description: Generate a Cisco Packet Tracer .pkt lab from Python — devices, modules, cabling, IOS configuration and PC addressing — without installing Packet Tracer.
---

# Generate a Packet Tracer lab from Python

Because the container can be written byte-exactly, it can also be **authored**.
You do not need Packet Tracer to build the file; you need it only to open the
result.

```console
pip install packet-tracer-pkt-format
```

The template library (137 device models, 78 modules) and a seed document ship
inside the package, so there is nothing to clone and no paths to configure.

## A working lab in ten lines

```python
from pkt_core import Lab

lab = Lab()                     # bundled seed + template library
lab.prune_seed_devices()        # start from an empty canvas

router = lab.add_device("2911", "R1", 250, 350, install="HWIC-2T",
                        ios_config=["interface GigabitEthernet0/0",
                                    " ip address 192.168.1.1 255.255.255.0",
                                    " no shutdown", "end"])
switch = lab.add_device("2960-24TT", "SW1", 450, 350)
pc = lab.add_device("PC-PT", "PC1", 650, 350,
                    pc_ip=("192.168.1.10", "255.255.255.0", "192.168.1.1"))

lab.link(router, "GigabitEthernet0/0", switch, "GigabitEthernet0/1")
lab.link(switch, "FastEthernet0/1", pc, "FastEthernet0")

lab.save("my_lab.pkt")
```

Open `my_lab.pkt` in Packet Tracer and the topology is drawn, cabled, and the
router is already configured.

## What you can set

| Operation | How |
| --- | --- |
| Place any harvested model | `add_device("2960-24TT", "SW1", x, y)` |
| Power state | `power=False` writes `<POWER>false</POWER>` explicitly, so a stale template state cannot leak in |
| Install a module | `add_device(..., install="HWIC-2T")` or `install_module(dev, name, bay=0)` |
| IOS running-config | `ios_config=[...]` — written as `<RUNNINGCONFIG><LINE>` and applied when PT loads the file |
| End-device addressing | `pc_ip=(ip, mask, gateway)` |
| Copper or serial cabling | `lab.link(a, aport, b, bport)`, or `kind="serial", clock=128000` for a DCE end |
| Clean canvas | `prune_seed_devices()` drops the inherited seed devices, their workspace leaves and any links referencing them |

Device names must be unique by default — `add_device` raises rather than silently
creating `SW1` twice. Pass `on_name_conflict="suffix"` to auto-rename instead.

## Choosing positions

The two coordinates map to the logical workspace, in the same units the Packet
Tracer canvas uses. For anything beyond a handful of devices, place them
programmatically rather than by hand:

```python
for i, model in enumerate(["2911", "2911", "2960-24TT"]):
    lab.add_device(model, f"N{i+1}", x=200 + i * 220, y=350)
```

`Layout` handles row wrapping and page boundaries if you are generating
enterprise-scale topologies.

## Why the file opens

Packet Tracer validates more than well-formed XML on load. Two details are
load-critical and were found empirically:

- the physical-workspace leaf UUID must be **braced** (`{uuid}`) to match
  `<UUID_STR>`; an unbraced one produces *"corrupted Physical Workspace data"*;
- every device needs a `<PHYSICAL_CPUR>` block.

The builder handles both. If you are writing this yourself, read
[the scene graph notes](SCENE_GRAPH.md) first — they will save you an afternoon.

## Scored activities (`.pka`)

Activity authoring — instructions, the activity-wizard password, permissions, and
the scoring tree — exists and works, but those generators still live in `tools/`
and currently need a checkout:

```console
$ python3 tools/make_scored_lab.py --out mylab.pka --spec topology.json --password hunter2
```

Porting that layer into the package is the next release. See
[activity files](ACTIVITY.md) and [scored-activity generation](PKA_GENERATION.md).

## What this cannot do

- It does not simulate anything. Packet Tracer still does that.
- It does not convert between Packet Tracer versions; the container format is
  written as the version the seed document came from.
- Not every device model is in the library. `tools/harvest_library.py` extends it
  from your own `.pkt` files.

## Next

- [Capabilities and the verified operation matrix](CAPABILITIES.md)
- [Open or inspect an existing `.pkt`](open-pkt-without-packet-tracer.md)
