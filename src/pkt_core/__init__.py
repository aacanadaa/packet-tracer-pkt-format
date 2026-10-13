"""pkt-core — type-safe reader/writer for Cisco Packet Tracer ``.pkt``/``.pka`` files.

Library entry point. Everything needed to open, inspect, modify and re-write a
Packet Tracer save file is re-exported here; the CLI is a separate, thin consumer
and is never imported by this package.

Quick start::

    from pkt_core import decode, encode_bytes

    container = decode("lab.pkt")          # verifier-based format detection
    print(container.root_tag)              # 'PACKETTRACER5'
    xml = container.xml                    # the inner XML document
    rebuilt = encode_bytes(xml, container.format_name)

The container is fully deterministic (fixed key + fixed IV), so re-encoding the
same XML yields the same bytes.
"""

from __future__ import annotations

from pkt_core.codec.container import (
    DEFAULT_FORMAT,
    Container,
    decode,
    decode_bytes,
    detect_format,
    encode,
    encode_bytes,
    root_tag,
)
from pkt_core.codec.qcompress import qcompress, quncompress
from pkt_core.crypto.keys import FORMATS, BLOCK_SIZE, TAG_SIZE, FormatSpec, get_format
from pkt_core.crypto.primitives import eax_open, eax_seal, eax_verify
from pkt_core.errors import (
    CompressionError,
    FormatError,
    IntegrityError,
    PacketTracerError,
    TruncatedFileError,
    UnsupportedCipherError,
)

__version__ = "0.1.0"

__all__ = [
    # container
    "Container",
    "decode",
    "decode_bytes",
    "encode",
    "encode_bytes",
    "detect_format",
    "root_tag",
    "DEFAULT_FORMAT",
    # key schedule
    "FORMATS",
    "FormatSpec",
    "get_format",
    "BLOCK_SIZE",
    "TAG_SIZE",
    # crypto primitives
    "eax_seal",
    "eax_open",
    "eax_verify",
    # framing
    "qcompress",
    "quncompress",
    # errors
    "PacketTracerError",
    "FormatError",
    "IntegrityError",
    "TruncatedFileError",
    "CompressionError",
    "UnsupportedCipherError",
    "__version__",
]
