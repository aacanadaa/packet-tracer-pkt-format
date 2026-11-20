"""The Packet Tracer container: detection, decode and encode.

A ``.pkt``/``.pka`` file is, from the outside in::

    file bytes
      |  layer A : reverse + positional XOR
      v
      AEAD ciphertext || 16-byte tag      (Crypto++ EAX, fixed key + fixed IV)
      |  layer B : XOR (len - i)          Util::deobfuscateBytes
      v
      Qt qCompress : 4-byte BE length + zlib
      v
      UTF-8 XML

**There is no magic header.** The first bytes of a container are effectively
random in every generation of the format, so identification is *verifier-based*:
try a candidate (cipher, key, IV) and accept it only when the EAX tag verifies.
That is a cryptographic oracle with a 2^-128 false-positive rate, so detection is
both necessary and conclusive.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Final, Iterable, Sequence

from pkt_core.codec.qcompress import qcompress, quncompress
from pkt_core.crypto.keys import FORMATS, FormatName, FormatSpec, get_format
from pkt_core.crypto.primitives import eax_open, eax_seal, eax_verify
from pkt_core.crypto.stream import layer_a, layer_a_inverse, layer_b
from pkt_core.errors import (
    FormatError,
    IntegrityError,
    PacketTracerError,
    TruncatedFileError,
)

__all__ = [
    "Container",
    "decode_bytes",
    "decode",
    "encode_bytes",
    "encode",
    "detect_format",
    "root_tag",
    "DEFAULT_FORMAT",
]

DEFAULT_FORMAT: FormatName = "pkt"
_MIN_LEGACY_SIZE: Final[int] = 6
_MIN_MODERN_SIZE: Final[int] = 16


def _resolve_format(name: FormatName) -> FormatSpec:
    try:
        return get_format(name)
    except KeyError as exc:
        raise FormatError(f"unknown container format: {name!r}") from exc


@dataclass(frozen=True, slots=True)
class Container:
    """A decoded container: the bytes we started from, and what they held.

    Attributes:
        xml: The decompressed UTF-8 XML document.
        format_name: Which flavour produced it (``"pkt"``, ``"pta"``, …).
        spec: The key schedule that was used.
        raw: The original file bytes, when known (``None`` for synthesised ones).
        payload: The original Qt ``qCompress`` payload (4-byte length prefix +
            zlib stream) exactly as it was stored in the file, when known.
            Passing this container as ``original=`` to :func:`encode_bytes`
            reuses it while the XML is unchanged, so an untouched file
            re-encodes to its original bytes on any zlib build.
    """

    xml: bytes
    format_name: FormatName
    spec: FormatSpec
    raw: bytes | None = None
    payload: bytes | None = field(default=None, repr=False)

    @property
    def root_tag(self) -> str:
        """Root element name — ``PACKETTRACER5`` vs ``PACKETTRACER5_ACTIVITY``."""
        return root_tag(self.xml)

    @property
    def is_activity(self) -> bool:
        """True for scored ``.pka`` activities rather than plain ``.pkt`` labs."""
        return self.root_tag.upper().endswith("_ACTIVITY")


def root_tag(xml: bytes) -> str:
    """Extract the root element name from an XML byte string without parsing it.

    Parsing is unnecessary for this one fact and would be wasteful on the
    multi-megabyte documents real labs contain.
    """
    head = xml[:4096].decode("utf-8", "replace")
    pos = 0
    while True:
        start = head.find("<", pos)
        if start < 0:
            return "?"
        if head.startswith("<!--", start):
            end = head.find("-->", start + 4)
            if end < 0:
                return "?"
            pos = end + 3
            continue
        if head.startswith("<?", start):
            end = head.find("?>", start + 2)
            if end < 0:
                return "?"
            pos = end + 2
            continue
        if head.startswith("<!", start):
            end = head.find(">", start + 2)
            if end < 0:
                return "?"
            pos = end + 1
            continue
        end = head.find(">", start + 1)
        if end < 0:
            return "?"
        inner = head[start + 1 : end].strip()
        if not inner or inner.startswith("/"):
            return "?"
        parts = inner.split()
        if not parts:
            return "?"
        # parts[0] drops attributes; rstrip("/") drops the self-closing marker.
        # XML names cannot contain '/', so this is unambiguous.
        name = parts[0].rstrip("/")
        return name or "?"


# --------------------------------------------------------------------------
# Detection
# --------------------------------------------------------------------------
#: zlib stream signatures that can follow a qCompress length prefix.
_ZLIB_MAGICS: Final[tuple[bytes, ...]] = (
    b"\x78\x01",
    b"\x78\x5e",
    b"\x78\x9c",
    b"\x78\xda",
)


def _looks_like_legacy(raw: bytes) -> bool:
    """Cheap O(1) structural probe for the unencrypted PT 5.x family.

    Family L is ``layer_b -> qCompress -> zlib``, so deobfuscating yields a
    4-byte big-endian uncompressed length followed by a zlib stream. Two checks
    gate it: a plausible length and a real zlib magic. The length is then
    verified exactly during inflate, which is what actually proves it.
    """
    n = len(raw)
    if n < _MIN_LEGACY_SIZE:
        return False
    # Only the first 6 bytes of layer_b(raw) are needed: raw[i] ^ ((n - i) & 0xFF)
    head = bytes(raw[i] ^ ((n - i) & 0xFF) for i in range(_MIN_LEGACY_SIZE))
    declared = int.from_bytes(head[:4], "big")
    if declared == 0 or declared > _MAX_LEGACY_PLAUSIBLE:
        return False
    return head[4:6] in _ZLIB_MAGICS


#: Guard against absurd allocations from a corrupt probe.
_MAX_LEGACY_PLAUSIBLE: Final[int] = 1 << 31


def _detect_format(
    raw: bytes,
    candidates: Sequence[FormatName] | None = None,
    *,
    decoded_a: bytes | None = None,
) -> FormatName:
    if len(raw) < _MIN_LEGACY_SIZE:
        raise TruncatedFileError(
            f"file is {len(raw)} bytes; a container needs at least {_MIN_LEGACY_SIZE} bytes"
        )
    tried: list[str] = []
    if len(raw) >= _MIN_MODERN_SIZE:
        names: Iterable[FormatName] = (
            candidates
            if candidates is not None
            else tuple(n for n, s in FORMATS.items() if not s.is_legacy)
        )
        ct = decoded_a if decoded_a is not None else layer_a(raw)
        for name in names:
            spec = _resolve_format(name)
            if spec.is_legacy:
                continue
            try:
                ok = eax_verify(spec.cipher, spec.key, spec.iv, ct)
            except PacketTracerError:
                tried.append(name)
                continue
            if ok:
                return name
            tried.append(name)

    if candidates is None and _looks_like_legacy(raw):
        return "legacy"

    if len(raw) < _MIN_MODERN_SIZE:
        raise TruncatedFileError(
            f"file is {len(raw)} bytes; a modern container needs at least {_MIN_MODERN_SIZE} bytes"
        )

    raise FormatError(
        f"no known format authenticated this file (tried: {', '.join(tried)}). "
        "See docs/FORMAT_SPECIFICATION.md"
    )


def detect_format(
    raw: bytes,
    candidates: Sequence[FormatName] | None = None,
) -> FormatName:
    """Identify the container family and flavour.

    There is no magic header, so detection is *verifier-based*:

    1. Try every modern flavour and accept the first whose **EAX tag verifies**
       (false-positive rate 2^-128).
    2. Otherwise, if the bytes deobfuscate into a valid qCompress payload,
       classify as the **legacy** PT 5.x family.

    Args:
        raw: The complete file bytes.
        candidates: Modern formats to try, in order. Defaults to all of them.

    Returns:
        The name of the detected flavour.

    Raises:
        TruncatedFileError: if the buffer is too short to be a container.
        FormatError: if nothing matches — the file is corrupt or not a container.
    """
    return _detect_format(raw, candidates)


# --------------------------------------------------------------------------
# Decode
# --------------------------------------------------------------------------
def decode_bytes(
    raw: bytes,
    fmt: FormatName | None = None,
    *,
    verify_tag: bool = True,
) -> Container:
    """Open a container and return its XML payload.

    Args:
        raw: The complete file bytes.
        fmt: Force a specific flavour. When ``None`` the flavour is detected via
            the AEAD tag.
        verify_tag: When ``True`` (default) a failed tag raises. When ``False``
            the decrypted bytes are returned anyway — useful for forensics on
            damaged files, and only reachable explicitly.

    Returns:
        A :class:`Container` with the inflated XML.

    Raises:
        TruncatedFileError: input too short.
        IntegrityError: tag mismatch and ``verify_tag`` is True.
        FormatError: detection failed, or the payload is not a container.
        CompressionError: the qCompress layer would not inflate.
    """
    if len(raw) < _MIN_LEGACY_SIZE:
        raise TruncatedFileError(
            f"file is {len(raw)} bytes; a container needs at least {_MIN_LEGACY_SIZE} bytes"
        )

    decoded_a: bytes | None = layer_a(raw) if len(raw) >= _MIN_MODERN_SIZE else None
    name = fmt if fmt is not None else _detect_format(raw, decoded_a=decoded_a)
    spec = _resolve_format(name)

    if spec.is_legacy:
        # Family L: no AEAD, no byte reversal. layer_b is an involution, so the
        # same call that deobfuscates on read obfuscates on write.
        payload = layer_b(raw)
        xml = quncompress(payload)
        return Container(xml=xml, format_name=name, spec=spec, raw=raw, payload=payload)

    if decoded_a is None:
        raise TruncatedFileError(
            f"file is {len(raw)} bytes; a modern container needs at least {_MIN_MODERN_SIZE} bytes"
        )

    result = eax_open(spec.cipher, spec.key, spec.iv, decoded_a)
    if verify_tag and not result.valid:
        raise IntegrityError(
            f"EAX tag mismatch for format {name!r} — the file is corrupt or is "
            "not this flavour"
        )
    payload = layer_b(result.plaintext)
    xml = quncompress(payload)
    return Container(xml=xml, format_name=name, spec=spec, raw=raw, payload=payload)


def decode(
    path: str | Path,
    fmt: FormatName | None = None,
    *,
    verify_tag: bool = True,
) -> Container:
    """Read ``path`` from disk and :func:`decode_bytes` it."""
    data = Path(path).read_bytes()
    return decode_bytes(data, fmt, verify_tag=verify_tag)


# --------------------------------------------------------------------------
# Encode
# --------------------------------------------------------------------------
def encode_bytes(
    xml: bytes,
    fmt: FormatName = DEFAULT_FORMAT,
    *,
    level: int = -1,
    original: Container | None = None,
) -> bytes:
    """Build a container from XML bytes.

    Args:
        xml: The UTF-8 XML document.
        fmt: Which flavour to seal it as.
        level: zlib compression level (``-1`` is Qt's default). Ignored when
            the original compressed payload is reused.
        original: The :class:`Container` this XML was decoded from, if any.
            When ``xml`` is byte-identical to ``original.xml``, the original
            qCompress payload is reused instead of recompressing. Otherwise
            ``xml`` is compressed as normal.

    Returns:
        Complete file bytes.

    Note:
        Re-encoding an **unchanged** document with ``original=`` always
        reproduces the file exactly: ``encode_bytes(c.xml, c.format_name,
        original=c) == f`` for ``c = decode_bytes(f)``, whatever zlib Python is
        linked against.

        Freshly compressed output (no ``original``, or edited XML) depends on
        the zlib build. With classic zlib, ``zlib.compress(x, -1)`` matches
        Packet Tracer's qCompress stream byte for byte, so even
        ``encode_bytes(c.xml, c.format_name) == f`` holds across the corpus.
        Other deflate implementations such as zlib-ng (used by some CPython
        builds, e.g. 3.14 on Windows) emit a different but equally valid
        stream: the file decodes to the same XML and Packet Tracer opens it,
        but the bytes differ. The AEAD is deterministic (fixed key and IV per
        format), so on any one zlib build identical XML yields identical bytes.
    """
    spec = _resolve_format(fmt)
    if original is not None and original.payload is not None and original.xml == xml:
        compressed = original.payload
    else:
        compressed = qcompress(xml, level)
    payload = layer_b(compressed)
    if spec.is_legacy:
        # Family L stops here: the deobfuscated qCompress payload *is* the file.
        return payload
    sealed = eax_seal(spec.cipher, spec.key, spec.iv, payload)
    return layer_a_inverse(sealed)


def encode(
    path: str | Path,
    xml: bytes,
    fmt: FormatName = DEFAULT_FORMAT,
    *,
    level: int = -1,
    original: Container | None = None,
) -> None:
    """Build a container from XML bytes and write it to ``path``.

    See :func:`encode_bytes` for ``original``.
    """
    Path(path).write_bytes(encode_bytes(xml, fmt, level=level, original=original))
