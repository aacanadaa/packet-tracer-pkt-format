---
description: How to open and inspect a Cisco Packet Tracer .pkt or .pka file without Packet Tracer installed, using the pkt CLI or a few lines of Python.
---

# Open a `.pkt` file without Packet Tracer

A Packet Tracer save file is an encrypted container wrapping a plain XML
document. Nothing readable is exposed: `file` reports generic data, `strings`
returns noise, and a hex dump is indistinguishable from random bytes.

You can still get at everything inside it — devices, links, positions, IOS
running-configs, activity instructions — without Packet Tracer installed.

## Install

```console
pip install packet-tracer-pkt-format
```

Python 3.10+, one runtime dependency (`pydantic`). No Packet Tracer, no compiler,
no system crypto library.

## The fast path

```console
$ pkt info lab.pkt
```

```
file        : lab.pkt
size        : 81,474 bytes
format      : pkt
cipher      : twofish
root tag    : PACKETTRACER5
kind        : network lab (.pkt)
xml bytes   : 1,045,755
```

Then unpack it:

```console
$ pkt unpack lab.pkt -o out/
meta     -> out/lab.container.json
configs  -> out/configs/  (3 device configs)
topology -> out/topology.dot, out/topology.json
```

You get the inner XML (`out/lab.xml`), one IOS running-config per device
(`out/configs/R1.cfg`), and the topology as Graphviz and JSON.

## From Python

```python
from pkt_core import decode

container = decode("lab.pkt")
print(container.root_tag)      # 'PACKETTRACER5'
print(container.is_activity)   # True for .pka
xml = container.xml            # the inner XML document, as bytes
```

For anything more structured than raw XML, the models layer parses it:

```python
from pkt_core import decode
from pkt_core.models import Lab

lab = Lab.from_bytes(decode("lab.pkt").xml)
for device in lab.devices:
    print(device.name, device.kind, device.model, device.position)
for link in lab.links:
    print(link.port_names, link.cable_type)
```

## Activity files work the same way

A `.pka` is the same container with a different root element
(`PACKETTRACER5_ACTIVITY`). No special handling:

```console
$ pkt info course_activity.pka
$ pkt unpack course_activity.pka -o activity/
```

## What you get, and what you don't

| You can | You cannot |
| --- | --- |
| Read devices, models, ports, cables | Open or render the GUI |
| Extract every IOS running-config | Simulate traffic or run the activity |
| See physical and logical placement | Recover a password that isn't stored |
| Convert to Graphviz, netbox, containerlab | Convert to a `.pkt` for a different PT version |

If you want to **change** the file and have Packet Tracer still open it, that
works too — the codec is byte-exact in both directions, so editing the XML and
repacking produces a valid container. See
[decrypt and rebuild](decrypt-pkt-to-xml.md).

## Troubleshooting

**"No magic header" is not a problem.** Neither container family has one — not
even a `PK` prefix. Detection is verifier-based: the codec attempts to
authenticate the AEAD tag, and a false positive is a 2⁻¹²⁸ event. A file that
fails detection is either truncated or not a Packet Tracer container.

**Old files.** PT 4.1 through 5.3.2 use a simpler legacy container with no AEAD
and no outer scramble. Detection handles both automatically; the switchover is
exactly 5.3.2 → 5.3.3.

**Don't use a validating XML parser.** Documents are not always well-formed:
IOS `<LINE>` text carries raw control bytes (the `banner motd ^C` delimiter is a
literal `0x03`), and PT 4.1 documents end with a trailing NUL. Read the XML as
bytes, or use the tolerant layer the package provides.

## Next

- [Decrypt a `.pkt` to XML and rebuild it](decrypt-pkt-to-xml.md)
- [Generate a lab from Python](generate-lab-from-python.md)
- [Format specification](FORMAT_SPECIFICATION.md) — the full container layout
