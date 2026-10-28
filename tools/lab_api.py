#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 aacanadaa
# This file is part of packet-tracer-pkt-format (GPL-3.0-or-later).
"""lab_api.py -- compatibility shim for :mod:`pkt_core.builder`.

The authoring code used to live here. It now ships inside the package, so that a
plain ``pip install packet-tracer-pkt-format`` can build labs without a checkout.

This module exists so that the scripts in ``tools/`` and anyone doing
``import lab_api`` from a checkout keep working. New code should import from the
package::

    from pkt_core import Lab
    from pkt_core.builder import Lab, Layout, load_templates
"""

from __future__ import annotations

import sys
from pathlib import Path

# Running from a checkout: make ``src/`` importable without installing the
# package. When the package is installed this is a no-op.
_SRC = Path(__file__).resolve().parent.parent / "src"
if _SRC.is_dir() and str(_SRC) not in sys.path:
    sys.path.insert(0, str(_SRC))

from pkt_core.builder import lab as _impl  # noqa: E402

# Re-export the whole module, including the private helpers and the ElementTree
# module, because the tools reach for names like ``_det_uuid`` and ``ET``.
# A static __all__ would drift from the implementation the first time either side
# changed, and a shim that silently misses an attribute is worse than no shim.
for _name in dir(_impl):
    if not _name.startswith("__"):
        globals()[_name] = getattr(_impl, _name)

# Codec helpers the tools used to reach through ``lab_api.pt9``. Exposed directly
# here so those call sites do not have to know which module the codec lives in.
from pkt_core.codec.container import decode_bytes, encode_bytes  # noqa: E402,F401

del _name, _impl, _SRC
