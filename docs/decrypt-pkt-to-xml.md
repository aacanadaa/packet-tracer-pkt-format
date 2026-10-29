---
description: Decrypt a Cisco Packet Tracer .pkt or .pka file to its inner XML, understand the Twofish-EAX container, and rebuild it byte-for-byte.
---

# Decrypt a `.pkt` file to XML (and rebuild it byte-for-byte)

Packet Tracer save files are not merely compressed. They are sealed with an AEAD
cipher whose key and IV are **fixed constants**, which has two consequences worth
knowing before you start:

- the same XML always produces the same bytes, so a byte-exact round trip is
  testable rather than aspirational;
- the authentication tag doubles as a format oracle, which is how the format is
  detected without a magic number.

## The layers

```
.pkt  →  [ scramble ]  →  [ Twofish-EAX ]  →  [ XOR (len-i) ]  →  [ qCompress ]  →  <?xml
```

| Layer | What it is |
| --- | --- |
| outer scramble | byte reversal plus a positional XOR, applied before encryption |
| cipher | Twofish in EAX (AEAD) mode, 128-bit key = `0x89` repeated, IV = `0x10` repeated, 16-byte tag appended |
| positional XOR | every byte XORed with `(len - i)` after decryption |
| payload | Qt `qCompress` — a four-byte big-endian length followed by a zlib stream |

Nothing here is a password. There is no per-file key, no key derivation, and no
licence check.

## Decrypt to XML

```console
$ pkt unpack lab.pkt -o out/
$ head -c 200 out/lab.xml
```

The `<PACKETTRACER5>` root, `<VERSION>`, `<DEVICES>`, `<LINKS>` and the rest are
all plain XML from there on.

In Python, with no intermediate files:

```python
from pkt_core import decode

xml = decode("lab.pkt").xml     # bytes
open("lab.xml", "wb").write(xml)
```

## Rebuild it

Editing the XML and writing it back produces a container Packet Tracer opens,
because the encoder reproduces the authentication tag rather than merely skipping
verification:

```console
$ pkt pack out/lab.xml -o rebuilt.pkt
xml   : 1,045,755 bytes  (root <PACKETTRACER5>)
format: pkt
wrote -> rebuilt.pkt  (81,474 bytes)
```

```python
from pkt_core import decode, encode_bytes

container = decode("lab.pkt")
rebuilt = encode_bytes(container.xml, container.format_name)
assert rebuilt == open("lab.pkt", "rb").read()   # byte-for-byte
```

That assertion is the project's whole verification claim: it holds on **1,058 of
1,058 real files**, PT 4.1 through 9.0.1, both container families. Anything you do
not touch survives as the original bytes.

## Why the tag is the detector

Neither family has a magic header. To decide whether a file is a Packet Tracer
container, the codec tries to verify the EAX tag: successful authentication means
the key, IV and framing are all correct, and the probability of a wrong answer is
2⁻¹²⁸. That is more reliable than a four-byte prefix, which is exactly why the
format can be identified without one.

## The legacy family

PT **4.1 through 5.3.2** writes a simpler container: no AEAD, no outer scramble —
just the positional XOR over `qCompress`. The switchover is exactly 5.3.2 →
5.3.3. Detection handles both, but if you are writing your own parser, note that
"modern" and "legacy" cannot be told apart from the extension or the first bytes.

See [the legacy container](LEGACY_FORMAT.md) for the full transform.

## Three traps

**1. Not all documents are well-formed XML.** IOS configuration is stored as
`<LINE>` elements carrying raw control bytes: `banner motd ^C…^C` embeds a literal
`0x03`, and PT 4.1 documents end with a trailing NUL. A validating parser will
reject files Packet Tracer opens without complaint.

**2. Don't normalise on the way out.** Any transformation — re-indenting,
re-encoding, stripping whitespace — changes the bytes. The package keeps untouched
subtrees as original source bytes precisely so this cannot happen by accident.

**3. `.pka` is the same container.** The root element differs
(`PACKETTRACER5_ACTIVITY`, or `PACKETTRACER_ACTIVITY` on PT 4.x), but the
encryption does not. The root element is **not** a reliable container
discriminator; use the tag.

## Next

- [Open a `.pkt` without Packet Tracer](open-pkt-without-packet-tracer.md)
- [Format specification](FORMAT_SPECIFICATION.md) — the per-format key table
- [Verification report](CORPUS_VERIFICATION.md) — how byte-exactness was measured
