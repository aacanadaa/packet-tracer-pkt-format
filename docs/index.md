---
description: Reverse-engineered documentation for the Cisco Packet Tracer .pkt and .pka container format, with a byte-exact Python codec and an offline lab generator.
---

# Cisco Packet Tracer `.pkt` / `.pka` — format documentation and toolkit

Packet Tracer save files have **no magic header** and are fully encrypted, so `file`,
`strings` and hex dumps show nothing but noise. These pages document the container —
both families, PT 4.1 through 9.0.1 — and the tooling that reads, writes and
generates it.

`encode(decode(f)) == f` **byte-for-byte on 1,058 of 1,058 real files**.

## Install

```console
pip install packet-tracer-pkt-format
```

Python 3.10+. The only runtime dependency is `pydantic`.

## Quickstart

```python
from pkt_core import decode

container = decode("my_lab.pkt")   # format detected by the AEAD tag, not a magic prefix
print(container.root_tag)          # 'PACKETTRACER5'
print(container.is_activity)       # True for '.pka'
xml = container.xml                # the inner XML document
```

```console
pkt info   my_lab.pkt                  # container metadata, size, root tag
pkt unpack my_lab.pkt -o out/          # XML + per-device IOS configs + topology
pkt pack   out/my_lab.xml -o rebuilt.pkt
pkt diff   before.pkt after.pkt
pkt export my_lab.pkt --format graphviz
```

## The container in one paragraph

`.pkt` is `[scramble] → [Twofish-EAX, key 0x89×16, IV 0x10×16] → [XOR (len-i)] →
[qCompress/zlib] → XML`. The key and IV are fixed per format, which makes the AEAD
tag usable as a format oracle with a 2⁻¹²⁸ false-positive rate — that is how the
format is detected without a magic number. The switchover from the legacy family
(no AEAD, no outer scramble) is exactly PT 5.3.2 → 5.3.3.

## Start here

<div class="grid cards" markdown>

- **[Format specification](FORMAT_SPECIFICATION.md)** — the full container spec, both
  families, with the per-format key table.
- **[Legacy format](LEGACY_FORMAT.md)** — PT 4.1 through 5.3.2, verified on 193 files.
- **[Scene graph](SCENE_GRAPH.md)** — what is inside the XML, and what Packet Tracer
  validates when it loads a file.
- **[Capabilities](CAPABILITIES.md)** — what the generators can and cannot author.
- **[Activity files](ACTIVITY.md)** — `.pka`, the Activity Wizard, scoring trees.
- **[Verification](CORPUS_VERIFICATION.md)** — how byte-exactness was measured.

</div>

## What this is for

- Reading and inspecting your **own** save files, without opening Packet Tracer.
- Documenting the format for tooling, archival and interoperability research.
- Authoring labs and scored activities programmatically, with no Packet Tracer
  installed.

It is **not** for obtaining, altering or submitting assessment or competition answer
keys. That is out of scope, and the licence does not grant it.

## Links

- Source and issues: <https://github.com/aacanadaa/packet-tracer-pkt-format>
- Package: <https://pypi.org/project/packet-tracer-pkt-format/>
- Format writeup: [`FORMAT.md`](https://github.com/aacanadaa/packet-tracer-pkt-format/blob/main/FORMAT.md)

Licensed GPL-3.0-or-later.
