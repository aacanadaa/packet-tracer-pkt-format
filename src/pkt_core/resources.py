# SPDX-License-Identifier: GPL-3.0-or-later
"""Access to the data files shipped inside the package.

Two files make offline authoring possible without a source checkout:

* the **template library** — one harvesting of every device model and module
  (``tools/device_templates.json``), gzip+base64 encoded inside a JSON wrapper;
* the **seed document** — a real Packet Tracer save used as a structural donor for
  the physical workspace, the canvas and the ``<PHYSICAL_CPUR>`` block.

Both are cached: a single lab build reads them once, and callers have no reason to
pay for that twice. The loaders go through :mod:`importlib.resources`, so they work
even when the package is imported from a zip.
"""

from __future__ import annotations

import base64
import functools
import gzip
import json
from importlib import resources

__all__ = [
    "device_templates_path",
    "load_device_templates",
    "load_network_seed",
]


def _read(name: str) -> bytes:
    """Read one bundled data file as bytes."""
    return resources.files(__package__).joinpath(f"data/{name}").read_bytes()


def device_templates_path() -> str:
    """Filesystem path of the bundled template library.

    Convenience for callers that want to pass a path to
    :func:`pkt_core.builder.lab.load_templates`. Prefer
    :func:`load_device_templates`, which also works inside a zip.
    """
    return str(resources.files(__package__).joinpath("data/device_templates.json"))


@functools.cache
def load_device_templates() -> tuple[dict[str, bytes], dict[str, str]]:
    """Return ``(models, modules)`` from the bundled template library.

    ``models`` maps a model name (``"2911"``, ``"2960-24TT"``) to the ``<DEVICE>``
    element bytes for it; ``modules`` maps a module name (``"HWIC-2T"``) to its
    ``<SLOT>`` element as text.

    Entries are stored gzip+base64 encoded inside the JSON wrapper, which is why an
    829 KB file expands to several megabytes of XML.
    """
    raw = json.loads(_read("device_templates.json"))
    gzipped = bool(raw.get("gz", False))

    def decode(value: str) -> bytes:
        blob = base64.b64decode(value)
        return gzip.decompress(blob) if gzipped else blob

    models = {k: decode(v) for k, v in raw["models"].items()}
    modules = {k: decode(v).decode("utf-8") for k, v in raw.get("modules", {}).items()}
    return models, modules


@functools.cache
def load_network_seed() -> bytes:
    """Return the seed Packet Tracer document as XML bytes.

    The seed supplies the scaffolding every generated lab inherits: the physical
    workspace, the default canvas, and the device whose ``<PHYSICAL_CPUR>`` block
    the placement code copies.
    """
    return _read("network_seed.xml")
