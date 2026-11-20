# Generating a full scored `.pka` lab from the repo alone

**Answer: yes.** A complete, graded Packet Tracer activity can be produced
entirely offline from this repository — no Packet Tracer needed to author it,
only to open the result.

## The command

```console
$ python3 tools/make_scored_lab.py --out mylab.pka --spec topology.json --password hunter2
```

The spec is plain JSON:

```json
{
  "devices": [
    {"model": "2911", "name": "R1", "x": 300, "y": 250,
     "install": "HWIC-2T",
     "config": ["hostname R1", "interface GigabitEthernet0/0",
                " ip address 192.168.1.1 255.255.255.0", " no shutdown", "end"]},
    {"model": "PC-PT", "name": "PC1", "x": 200, "y": 620,
     "pc_ip": ["192.168.1.10", "255.255.255.0", "192.168.1.1"]}
  ],
  "links": [
    {"a": "R1", "aport": "GigabitEthernet0/0", "b": "SW1", "bport": "GigabitEthernet0/1"}
  ]
}
```

The tool builds **two networks** — an initial one with the topology but no
configuration, and an answer network with the configuration applied — and
derives the scoring tree from the answer.

## What the generated file contains

Verified through `pkt_core` on a 5-device / 4-link lab:

| Property | Result |
| --- | --- |
| Root element | `PACKETTRACER5_ACTIVITY` |
| Scoring tree | **5,914 nodes** (device model, custom name, wattage, cost, connectivity tests, …) |
| Activity sections | `COMPARISONS`, `INITIALSETUP`, `LOCKINGTREE`, `INSTRUCTIONS` |
| Instructions | HTML in CDATA, `<h3>Task</h3>…` |
| Variable manager | present |
| Activity password | `hunter2`, at `<ACTIVITY PASS="hunter2">` |
| Container | `encode(decode(f)) == f` **byte-exact** |

## Verified in Packet Tracer 9.0.1

The file opens as a **real graded activity**, not just a topology:

| Stage | Observed |
| --- | --- |
| Open | window title `Cisco Packet Tracer - mylab.pka - Guest - <timestamp>` |
| Activity | `PT Activity: 00:00:52` timer running |
| Instructions | rendered — `Task` heading, body text, `1/1` page nav |
| Completion | `Completion: 100%` indicator live |
| **Check Results** | **runs the grading engine** |
| Grading output | *"Congratulations Guest! You completed the activity."* with tabs **Overall Feedback**, **Assessment Items**, **Connectivity Tests** |
| Feedback text | our own `Lab complete - well done!` rendered |

## What you still need to know

Three rough edges, all found by doing this for the first time:

1. **Device names can collide with the seed.** `tools/network_seed.xml`
   contributes 7 pre-existing devices (`SW1`, `R2`, `PC-A`, `PC-B`, `Server`, …).
   `add_device()` raises `ValueError` on a collision by default; pass
   `--prune-seed` to `make_scored_lab.py` (or call `lab.prune_seed_devices()`)
   to strip the seed first, or pick names outside that set.

2. **The seed devices are present unless pruned.** Without `--prune-seed`, they
   appear in the workspace at the left. Pass `--prune-seed` for a clean lab.

3. **`--password` writes to `<ACTIVITY PASS=...>`,** not `<OPTIONS><PASS>`. Those
   are different fields; `Lab.activity_password` reads the right one.

## Model API for editing the result

```python
from pkt_core import decode_bytes, encode_bytes
from pkt_core.models import Lab

raw = open("mylab.pka", "rb").read()
lab = Lab.from_bytes(decode_bytes(raw).xml)

lab.activity_password                 # -> 'hunter2'
[s.tag for s in lab.activity_sections]
# ['COMPARISONS', 'INITIALSETUP', 'LOCKINGTREE', 'INSTRUCTIONS', 'VARIABLE_MANAGER', ...]

lab.set_activity_password("newpass")
open("out.pka", "wb").write(encode_bytes(lab.to_xml(), "pkt"))
```

`INSTRUCTIONS`, `INSTRUCTION_DIALOG`, `USER_NOTES` and `VARIABLE_MANAGER` are
nested inside `<ACTIVITY>`; `COMPARISONS`/`INITIALSETUP`/`LOCKINGTREE` are root
children. `Lab.activity_sections` descends so you see all of them.

Instructions are stored as CDATA HTML and exposed as raw **bytes** on purpose —
they contain markup the XML layer must not normalise.
