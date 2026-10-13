"""Exception hierarchy for :mod:`pkt_core`.

Every failure mode the container can produce is a distinct type so callers can
handle them precisely; nothing in :mod:`pkt_core` ever raises a bare
:class:`Exception` or lets a :mod:`struct`/:mod:`zlib` error escape untyped.
"""

from __future__ import annotations

__all__ = [
    "PacketTracerError",
    "FormatError",
    "IntegrityError",
    "UnsupportedCipherError",
    "TruncatedFileError",
    "CompressionError",
]


class PacketTracerError(Exception):
    """Base class for every error raised by :mod:`pkt_core`."""


class FormatError(PacketTracerError):
    """The bytes are not a container of the format that was assumed."""


class IntegrityError(PacketTracerError):
    """The authenticated-encryption tag did not match: data is corrupt or the
    wrong key/format was used. This is the strongest negative signal the
    container offers, and doubles as the format-detection oracle."""


class UnsupportedCipherError(PacketTracerError):
    """The requested block cipher is unavailable in the current backend."""


class TruncatedFileError(FormatError):
    """The input ends before a complete container could be read."""


class CompressionError(PacketTracerError):
    """The qCompress/zlib layer could not be inflated, or its length header lied."""
