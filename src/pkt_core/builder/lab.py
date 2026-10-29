#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 aacanadaa
# This file is part of packet-tracer-pkt-format (GPL-3.0-or-later).
"""
pkt_core.builder.lab -- a small, verified library for building Packet Tracer 9 labs
programmatically (device placement, power, modules, cabling, IOS config,
end-device IPs).  Built on the in-package codec, so it works from a plain
``pip install`` with no source checkout.

Verified capabilities
---------------------
* add_device(model, name, ...)          place any harvested device model
*   power=True/False                    <ENGINE><POWER>, written explicitly in
                                        both directions (off => ports down; a
                                        stale template state can no longer leak)
*   ios_config=[...]                    <ENGINE><RUNNINGCONFIG><LINE>…  applied on load
*   pc_ip=(ip,mask,gw)                  NIC <IP>/<SUBNET>/<PORT_GATEWAY>
* install_module(dev, module, bay=0)    fill an empty <SLOT> with a <MODULE>
* link(a, aport, b, bport, kind=…)      copper eCopper/eStraightThrough, serial eSerial
* device_names()                        names in use (seed + added); see Naming below
* prune_seed_devices()                  drop the devices inherited from the seed
* save(path)

Physical placement
------------------
Every added device gets a freshly synthesized leaf in the PHYSICALWORKSPACE
rack (a `<NODE><TYPE>6</TYPE>` with a new `<UUID_STR>`), and a matching
`<WORKSPACE><PHYSICAL>` GUID path plus a `<PHYSICAL_CPUR>` block.  Two details
are load-critical and were found empirically:
  * the leaf UUID must be **braced** (`{uuid}`) in `<PHYSICAL>`, matching
    `<UUID_STR>`; an unbraced UUID => "corrupted Physical Workspace data".
  * a `<PHYSICAL_CPUR>` element must be present on the device.
The seed's devices can be removed with `prune_seed_devices()` (=
`drop_initial()`); that also removes their workspace leaves and any links that
referenced them, so no orphan leaves remain (orphans also corrupt the
workspace).

Naming
------
The seed already contributes devices (SW1, R1, R2, PC-A, PC-B, Server, ...),
so `add_device()` refuses to reuse an existing device name by default and
raises ValueError.  Pass `on_name_conflict="suffix"` to auto-rename instead
(SW1 -> SW1(1)); `device_names()` lists every name currently in use and
`prune_seed_devices()` (alias `drop_seed_devices`) drops the inherited seed
devices for a clean workspace.

See docs/CAPABILITIES.md for the full documented model.
"""
from __future__ import annotations

import copy
import hashlib
import json
import math
import os
import re
import sys
import uuid
import xml.etree.ElementTree as ET
from collections.abc import Iterable, Sequence
from typing import Any, NamedTuple

from pkt_core.codec.container import decode, decode_bytes, encode
from pkt_core.resources import load_device_templates, load_network_seed


# --------------------------------------------------------------------------- #
# harvesting device / module templates from existing .pkt files
# --------------------------------------------------------------------------- #
def _iter_devices(xml):
    return re.finditer(rb"<DEVICE>.*?</DEVICE>", xml, re.S)


# engine-level <POWER> sits directly after <NAME> (child index 2 of <ENGINE>);
# per-port <PORT><POWER> follows <TYPE> and must never be touched here.
_ENG_POWER_RE = re.compile(
    rb"(<NAME[^>]*>.*?</NAME>\s*)<POWER>([^<]*)</POWER>", re.S)
_ENG_NAME_RE = re.compile(rb"(<NAME[^>]*>.*?</NAME>)", re.S)


def normalise_device_power(blk):
    """Force a harvested <DEVICE> block's <ENGINE><POWER> to "true".

    Harvested templates are taken verbatim from donor saves, so a device that
    happened to be switched off in the donor poisons every lab built from that
    model (see docs/POWER_INVESTIGATION.md: the 3650-24PS template shipped
    <POWER>false</POWER> and took the whole aggregation layer down with it).
    Returns (block, was_off) where was_off records that the donor save had the
    device off (absent counts as off too -- PT never omits the element).  Only
    the device-level element is rewritten; <PORT><POWER> is left as harvested.
    """
    state = {"off": False}

    def repl(m):
        if m.group(2).strip().lower() != b"true":
            state["off"] = True
        return m.group(1) + b"<POWER>true</POWER>"

    new, n = _ENG_POWER_RE.subn(repl, blk, count=1)
    if n == 0:
        new = _ENG_NAME_RE.sub(rb"\1\n     <POWER>true</POWER>", blk, count=1)
        if new != blk:
            state["off"] = True   # PT never omits <POWER>: absent is a defect
    return new, state["off"]


def load_templates(
    path: str | os.PathLike[str] | None = None,
) -> tuple[dict[str, bytes], dict[str, str]]:
    """Load a device/module template library.

    With no argument this returns the library bundled in the package, so a plain
    ``pip install`` can build labs without a checkout. Pass a path to read another
    library instead — the format is the gzip+base64 JSON used by
    ``tools/device_templates.json``, which is what ``tools/harvest_library.py``
    writes when extending model coverage.

    Returns ``(models, modules)``: ``models`` maps a model name to its ``<DEVICE>``
    element bytes, ``modules`` maps a module name to its ``<SLOT>`` element text.
    """
    if path is None:
        return load_device_templates()

    import base64
    import gzip

    with open(path) as fh:
        t = json.load(fh)
    gz = t.get("gz", False)

    def dec(v: str) -> bytes:
        b = base64.b64decode(v)
        return gzip.decompress(b) if gz else b

    return ({k: dec(v) for k, v in t["models"].items()},
            {k: dec(v).decode("utf-8") for k, v in t.get("modules", {}).items()})


def harvest_models(saves_dir, wanted=None):
    """Return {model: <DEVICE> bytes} taking the first instance of each model.

    Device-level <ENGINE><POWER> is normalised to "true" on the way in (see
    normalise_device_power): a donor save is just whichever save happened to be
    on disk, and its per-device power state is not part of a model definition.
    Models whose donor block was off/absent are reported on stderr so the
    artefact is recorded rather than silently shipped."""
    import glob
    out = {}
    files = sorted(glob.glob(os.path.join(saves_dir, "**", "*.pkt"), recursive=True),
                   key=os.path.getsize)
    for f in files:
        if wanted and wanted <= set(out):
            break
        try:
            xml = decode(f, "pkt", verify_tag=False).xml
        except Exception:
            continue
        for m in _iter_devices(xml):
            mm = re.search(rb'<TYPE[^>]*model="([^"]*)"', m.group(0))
            if not mm:
                continue
            model = mm.group(1).decode()
            if (wanted is None or model in wanted) and model not in out:
                blk, was_off = normalise_device_power(m.group(0))
                if was_off:
                    print("harvest_models: %s was off in donor save %s "
                          "-- normalised <ENGINE><POWER> to true"
                          % (model, os.path.basename(f)), file=sys.stderr)
                out[model] = blk
    return out


def harvest_modules(saves_dir, wanted):
    """Return {module_model: <SLOT> xml bytes} for modules found in devices."""
    import glob
    out = {}
    for f in sorted(glob.glob(os.path.join(saves_dir, "**", "*.pkt"), recursive=True),
                   key=os.path.getsize):
        if wanted <= set(out):
            break
        try:
            xml = decode(f, "pkt", verify_tag=False).xml.decode("utf-8", "replace")
        except Exception:
            continue
        for model in set(re.findall(r"<MODEL>([^<]+)</MODEL>", xml)) & wanted:
            if model in out:
                continue
            i = xml.find("<MODEL>%s</MODEL>" % model)
            a = xml.rfind("<SLOT>", 0, i)
            b = xml.find("</SLOT>", i) + len("</SLOT>")
            if a >= 0 and b > a:
                out[model] = xml[a:b]
    return out


# --------------------------------------------------------------------------- #
# layout: label-inclusive sizing + greedy row-major packing
# --------------------------------------------------------------------------- #
# Geometry (docs/LAYOUT_INVESTIGATION.md): 1 workspace unit = 1 screen pixel at
# Packet Tracer's default 100 % zoom; icon artwork measures 28-52 units wide;
# PT draws the model caption above and the device name below the icon at
# ~6.3 px/char (CHAR_W leaves a safety margin); human-authored corpus labs keep
# device centres 50-180 units apart with a hard floor of ~80.
CHAR_W: int = 7
GUTTER: int = 28
LABEL_LINE: int = 18
ROW_PITCH: int = 150
FLOOR: int = 80
CANVAS_MIN: int = 60
CANVAS_MAX: int = 3860
PAGE_WIDTH: int = 3900
SKIP_STEP: int = 20

ICON_W: dict[str, tuple[int, int]] = {
    "router": (52, 44), "switch": (50, 42), "multilayer-switch": (50, 42),
    "access-point": (50, 36), "pc": (36, 42), "laptop": (36, 42),
    "server": (30, 48), "iot": (40, 40), "sniffer": (50, 40),
    "firewall": (52, 42), "pdd": (40, 40), "default": (52, 44),
}

# order matters: the first matching rule wins
_KIND_RULES: tuple[tuple[str, str], ...] = (
    (r"power distribution", "pdd"),
    (r"sniffer|cyberobserver", "sniffer"),
    (r"server|historian", "server"),
    (r"accesspoint|access point|wireless.?ap", "access-point"),
    (r"laptop|^lap-", "laptop"),
    (r"tablet|smartphone|^pc-|-pc$|home-pc", "pc"),
    (r"5505|asa|firewall|meraki-mx", "firewall"),
    (r"^(2960|2950|2900|ie-|switch-pt|hub-pt)", "switch"),
    (r"^(3560|3650|3550)-", "multilayer-switch"),
    (r"^(2911|2901|1941|1841|2811|26\d\d|isr|ir\d|cgr|8[12]\d|router-pt"
     r"|linksys|homerouter|dsl-modem|cloud-pt)", "router"),
    (r"thing|sensor|monitor|motor|button|switch\(|\bled\b|fan|door|meter"
     r"|panel|turbine|speaker|siren|webcam|rfid|thermostat|humid|sprinkler"
     r"|furnace|heating|battery|beacon|light|window|garage|smoke|water"
     r"|sound|photo|piezo|servo|potentiometer|rocker|toggle|push|relay"
     r"|pressure|wind|solar|lcd|hmi|plc", "iot"),
)
_KIND_RE: tuple[tuple[re.Pattern[str], str], ...] = tuple(
    (re.compile(p), k) for p, k in _KIND_RULES)

# tallest icon + both label lines + gutter; keeps every packed box inside the
# canvas while rows advance by ROW_PITCH
_MAX_CELL_H = max(h for _w, h in ICON_W.values()) + 2 * LABEL_LINE + GUTTER
_MAX_HALF_H = (_MAX_CELL_H + 1) // 2


def kind_for_model(model: str) -> str:
    """Map a PT device *model* string onto an icon-size class."""
    m = (model or "").lower()
    for rx, kind in _KIND_RE:
        if rx.search(m):
            return kind
    return "default"


def device_box(kind: str, name: str, model_caption: str) -> tuple[int, int]:
    """Return the label-inclusive cell (width, height) of one device.

    The box spans the icon plus the two label lines PT draws (model caption
    above, device name below) plus a GUTTER of clearance on every side, so two
    cells never overlap even when their labels are long.  ``model_caption`` is
    the text PT prints above the icon (the model name)."""
    icon_w, icon_h = ICON_W.get(kind, ICON_W["default"])
    w = max(icon_w, CHAR_W * len(name) + 16, CHAR_W * len(model_caption) + 16)
    h = icon_h + 2 * LABEL_LINE
    return w + GUTTER, h + GUTTER


def label_box(kind: str, name: str, model_caption: str) -> tuple[int, int]:
    """Return the icon+label box *without* the packing gutter (w, h)."""
    w, h = device_box(kind, name, model_caption)
    return w - GUTTER, h - GUTTER


def column_pitch(name: str) -> int:
    """Minimum centre-to-centre advance for a device called ``name``.

    Long device names draw long labels, so they need a wider column:
    200 units for names up to 16 characters, 260 for 17-24, 320 beyond."""
    n = len(name)
    return 200 if n <= 16 else 260 if n <= 24 else 320


# semantic tiers of a generated lab, derived from device names so that packing
# keeps each tier in its own horizontal band.  Order matters: first rule wins.
_TIER_RULES: tuple[tuple[str, re.Pattern[str]], ...] = (
    ("airborne", re.compile(r"^(E767|E2D|E2C|RC2)-\d\d-")),
    ("radar", re.compile(r"^RDR-")),
    ("airbase", re.compile(r"^AB-")),
    ("crc", re.compile(r"^CRC-")),
    ("nosc", re.compile(r"^NOSC-")),
    ("hq", re.compile(r"^ADC-")),
    ("backbone", re.compile(r"^(JADGE-BB-|CORE-RTR-|WAN-EDGE-|REG-HUB-"
                            r"|DATALINK-AGG-|TDL-GW-|SATCOM-GW-|COALITION-GW-"
                            r"|MGMT-GW-)")),
    ("coalition", re.compile(r"^PARTNER-")),
    ("dc", re.compile(r"^(JADGE-|FW-)|-(SVR|SERVER)$|^DATA-HISTORIAN$")),
)


# Caller-supplied tier rules, tried before the built-in ones.  The built-in
# rules are one lab's naming convention; a second lab with its own hostnames
# matches none of them, and every device collapses into ``misc`` -- one enormous
# band, which repacks into exactly the tangle the bands existed to prevent.
# Silently, because the repack itself still succeeds.
_EXTRA_TIER_RULES: list[tuple[str, re.Pattern[str]]] = []


def load_tier_map(path: "str | os.PathLike[str] | None") -> int:
    """Load caller tier rules, tried before the built-in ones.

    Accepts either shape, so a lab can ship whatever it already has:

        {"rules": [{"tier": "T1-edge", "patterns": ["^CARRIER-", "^FW-"]}]}
        {"T1-edge": ["^CARRIER-", "^FW-"]}

    Patterns are regular expressions matched with ``search``, exactly like the
    built-in rules.  Returns the number of rules loaded.
    """
    global _EXTRA_TIER_RULES
    if path is None:
        _EXTRA_TIER_RULES = []
        return 0
    with open(path, encoding="utf-8") as fh:
        blob = json.load(fh)
    rows: list[tuple[str, list[str]]] = []
    if isinstance(blob, dict) and "rules" in blob:
        for entry in blob["rules"]:
            rows.append((entry["tier"], list(entry["patterns"])))
    elif isinstance(blob, dict):
        for tier, pats in blob.items():
            rows.append((tier, list(pats)))
    else:
        raise ValueError(f"tier map {path}: expected an object")
    _EXTRA_TIER_RULES = [(t, re.compile("|".join(f"(?:{p})" for p in pats)))
                         for t, pats in rows]
    return len(_EXTRA_TIER_RULES)


def tier_for_name(name: str) -> str:
    """Map a device name onto its semantic tier band (see :class:`Layout`).

    Caller rules from :func:`load_tier_map` win; the built-in rules are one
    lab's naming convention and are only a fallback.
    """
    for tier, rx in _EXTRA_TIER_RULES:
        if rx.search(name):
            return tier
    for tier, rx in _TIER_RULES:
        if rx.search(name):
            return tier
    return "misc"


class Device(NamedTuple):
    """One device as read back from a decoded lab."""
    name: str
    model: str
    kind: str
    x: float
    y: float


class Placement(NamedTuple):
    """One device as placed (or reserved) by :class:`Layout`."""
    name: str
    model: str
    kind: str
    group: str
    x: int
    y: int
    w: int
    h: int
    page: int


def parse_devices(xml: str | bytes) -> list[Device]:
    """Return every NETWORK device of a decoded lab, in document order."""
    if isinstance(xml, bytes):
        xml = xml.decode("utf-8", "replace")
    root = ET.fromstring(xml)
    devs = root.find("NETWORK/DEVICES")
    out: list[Device] = []
    if devs is None:
        return out
    for d in devs.findall("DEVICE"):
        eng = d.find("ENGINE")
        if eng is None:
            continue
        name = eng.findtext("NAME") or ""
        ty = eng.find("TYPE")
        model = (ty.get("model") or "") if ty is not None else ""
        lg = d.find("WORKSPACE/LOGICAL")
        if lg is None:
            continue
        xs, ys = lg.findtext("X"), lg.findtext("Y")
        if xs is None or ys is None:
            continue
        out.append(Device(name, model, kind_for_model(model),
                          float(xs), float(ys)))
    return out


class _Band:
    """Row-major cursor state of one semantic group."""
    __slots__ = ("x0", "cy", "left", "row_h", "page", "prev")

    def __init__(self, x0: int, cy: int, page: int) -> None:
        self.x0 = x0
        self.cy = cy
        self.left = x0
        self.row_h = 0
        self.page = page
        self.prev: tuple[int, int, str] | None = None   # (cx, w, name)


class Layout:
    """Label-inclusive greedy row-major packer with an occupancy test.

    Devices are placed by :meth:`place`, which sizes each device with
    :func:`device_box` -- the icon *plus* both label lines PT draws (model
    caption above, device name below) plus a gutter -- so packed devices never
    have overlapping text.  Each semantic *group* is a horizontal band: its
    first device starts at the group's anchor (see :meth:`anchor`) or, without
    an anchor, on the next row below everything already placed; the rest of the
    band packs row-major.  A candidate position is AABB-tested against every
    already-placed or explicitly reserved box and skipped forward while
    occupied ("skip-occupied-cells"), and an 80-unit centre-to-centre floor is
    enforced as a hard invariant.

    Canvas containment: X, Y stay inside [CANVAS_MIN, CANVAS_MAX]; when a band
    runs out of vertical room it wraps to a second page column at x + PAGE_WIDTH
    (3900 units to the right).  Spacing is never shrunk to force a fit.

    Placement is deterministic: the same call sequence always yields the same
    coordinates."""

    def __init__(self, x_min: int = CANVAS_MIN, y_min: int = CANVAS_MIN,
                 x_max: int = CANVAS_MAX, y_max: int = CANVAS_MAX,
                 page_width: int = PAGE_WIDTH) -> None:
        if not (x_min < x_max and y_min < y_max):
            raise ValueError("canvas bounds must satisfy min < max")
        self.x_min = x_min
        self.y_min = y_min
        self.x_max = x_max
        self.y_max = y_max
        self.page_width = page_width
        self._placed: list[Placement] = []
        self._anchors: dict[str, tuple[int, int]] = {}
        self._bands: dict[str, _Band] = {}

    # -- canvas helpers --------------------------------------------------- #
    def _page_x_min(self, page: int) -> int:
        return self.x_min + page * self.page_width

    def _page_x_max(self, page: int) -> int:
        return self.x_max + page * self.page_width

    # -- registration ----------------------------------------------------- #
    @property
    def placements(self) -> list[Placement]:
        """Every placed/reserved device, in the order they were added."""
        return list(self._placed)

    def anchor(self, group: str, x: float, y: float) -> None:
        """Pin where a group's band starts: the first device's centre is placed
        near (x, y).  The rest of the band still packs row-major and is still
        collision-checked.  Anchors outside the canvas are clamped inside."""
        self._anchors[group] = (int(round(x)), int(round(y)))

    def reserve(self, name: str, model: str, x: float, y: float,
                kind: str | None = None) -> Placement:
        """Record an explicitly positioned device at exactly (x, y).

        Used for callers that pass x/y themselves: the device sits where asked
        and merely occupies space for later placements."""
        k = kind or kind_for_model(model)
        w, h = device_box(k, name, model)
        p = Placement(name, model, k, "", int(round(x)), int(round(y)),
                      w, h, int(round(x)) // self.page_width)
        self._placed.append(p)
        return p

    def forget(self, name: str) -> None:
        """Drop reserved/placed boxes called ``name`` (e.g. pruned seed)."""
        self._placed = [p for p in self._placed if p.name != name]

    # -- packing ---------------------------------------------------------- #
    def _band_for(self, group: str, w: int, h: int) -> _Band:
        band = self._bands.get(group)
        if band is not None:
            return band
        page = 0
        if group in self._anchors:
            ax, ay = self._anchors[group]
            cy = min(max(ay, self.y_min + _MAX_HALF_H), self.y_max - _MAX_HALF_H)
            left = min(max(ax - w // 2, self.x_min), self.x_max - w)
        else:
            cy = self.y_min + _MAX_HALF_H
            if self._placed:
                bottom = max(p.y + (p.h + 1) // 2 for p in self._placed)
                low = max(p.y for p in self._placed)
                cy = max(bottom + GUTTER // 2 + _MAX_HALF_H, low + ROW_PITCH)
                if cy + _MAX_HALF_H > self.y_max:   # wrap to page column 2
                    page = 1
                    cy = self.y_min + _MAX_HALF_H
            left = self._page_x_min(page)
        band = _Band(left, cy, page)
        self._bands[group] = band
        return band

    def _wrap_row(self, band: _Band) -> None:
        band.cy += max(ROW_PITCH, band.row_h)
        if band.cy + _MAX_HALF_H > self.y_max:
            band.page += 1
            band.cy = self.y_min + _MAX_HALF_H
        band.left = self._page_x_min(band.page)
        band.prev = None
        band.row_h = 0

    def _min_left_clear(self, cx: int, cy: int, w: int, h: int,
                        band: _Band) -> int | None:
        """Smallest cursor at which the cell clears every placed box, or None
        when the candidate (cx, cy) is already clear."""
        need: int | None = None
        for p in self._placed:
            dx = cx - p.x
            dy = cy - p.y
            overlap = abs(dx) * 2 < w + p.w and abs(dy) * 2 < h + p.h
            close = dx * dx + dy * dy < FLOOR * FLOOR
            if not overlap and not close:
                continue
            cand = band.left
            if abs(dy) * 2 < h + p.h:
                # moving right must lift the AABB overlap in x
                cand = max(cand, p.x + (p.w + w + 1) // 2 - w // 2)
            if dy * dy < FLOOR * FLOOR:
                need_dx = math.isqrt(FLOOR * FLOOR - dy * dy)
                if need_dx * need_dx < FLOOR * FLOOR - dy * dy:
                    need_dx += 1
                cand = max(cand, p.x + need_dx - w // 2)
            need = cand if need is None else max(need, cand)
        return need

    def place(self, name: str, model: str, group: str = "",
              kind: str | None = None) -> Placement:
        """Place one device and return its :class:`Placement`.

        The device is sized with :func:`device_box`, laid out row-major inside
        its group's band, and shifted right (wrapping to the next row / page
        column as needed) until it clears every already-placed box and honours
        the 80-unit floor."""
        k = kind or kind_for_model(model)
        w, h = device_box(k, name, model)
        if w > self.x_max - self.x_min or h > self.y_max - self.y_min:
            raise ValueError("device %r does not fit the canvas" % (name,))
        band = self._band_for(group, w, h)
        for _ in range(100_000):
            if band.left + w > self._page_x_max(band.page):
                self._wrap_row(band)
                continue
            cx = band.left + w // 2
            cy = band.cy
            if band.prev is not None:
                pcx, pw, pname = band.prev
                step = max(column_pitch(pname), column_pitch(name),
                           (pw + w + 1) // 2, FLOOR)
                if band.left < pcx + step - w // 2:
                    band.left = pcx + step - w // 2
                    continue
            need = self._min_left_clear(cx, cy, w, h, band)
            if need is not None:
                band.left = max(band.left + SKIP_STEP, need)
                continue
            p = Placement(name, model, k, group, cx, cy, w, h, band.page)
            self._placed.append(p)
            band.prev = (cx, w, name)
            band.left = cx + w - w // 2
            band.row_h = max(band.row_h, h)
            return p
        raise RuntimeError("layout: cannot place %r" % (name,))


# --------------------------------------------------------------------------- #
# builder
# --------------------------------------------------------------------------- #
def _det_uuid(*parts: object) -> str:
    """Return a *deterministic* UUID for a physical-workspace node.

    Packet Tracer allocates these with a CSPRNG at author time, and a generator
    that copies that behaviour is not reproducible: two runs of the same model
    produce different bytes, so the SHA-256 published next to a build cannot be
    re-derived by anyone, and a "rebuild and compare" integrity check becomes a
    permanent false alarm.  Measured on the 290-device JASDF model, *every*
    byte difference between two runs traced to these two call sites -- the XML
    was otherwise byte-identical.

    The value is derived from stable inputs and then stamped with the v4
    version/variant bits, so it is indistinguishable in form from a real one
    while being reproducible.  Uniqueness only has to hold within one file,
    which the caller guarantees by keying on the device's document index.
    """
    digest = hashlib.sha256(
        "\x00".join(str(p) for p in parts).encode("utf-8")
    ).digest()
    b = bytearray(digest[:16])
    b[6] = (b[6] & 0x0F) | 0x40          # version 4
    b[8] = (b[8] & 0x3F) | 0x80          # RFC 4122 variant
    return str(uuid.UUID(bytes=bytes(b)))


class Lab:
    def __init__(
        self,
        seed: str | os.PathLike[str] | bytes | None = None,
        models: dict[str, bytes] | None = None,
        modules: dict[str, str] | None = None,
    ) -> None:
        if seed is None:
            xml = load_network_seed()
        elif isinstance(seed, bytes):
            xml = seed
        else:
            raw = open(seed, "rb").read()
            xml = decode_bytes(raw, "pkt").xml if str(seed).lower().endswith(".pkt") else raw
        if models is None:
            models, bundled_modules = load_device_templates()
            if modules is None:
                modules = bundled_modules
        self.base = ET.fromstring(xml)
        self.net = self.base.find("NETWORK")
        self.devs = self.net.find("DEVICES")
        self.models = models
        self.modules = modules or {}
        self._pw = self.base.find("PHYSICALWORKSPACE")
        self._wsroot = self._pw.find("NODE") if self._pw is not None else None

        existing = self.devs.findall("DEVICE")
        # donor <PHYSICAL_CPUR> (structure template) from the seed's first device
        self._donor_cpur = None
        donor_pp = donor_cid = None
        if existing:
            dc = existing[0].find("WORKSPACE/PHYSICAL_CPUR")
            if dc is not None:
                self._donor_cpur = copy.deepcopy(dc)
                donor_pp = dc.findtext("PARENT_PATH")
                donor_cid = dc.findtext("CONTAINER_ID")
        self._PP = donor_pp or (self._pw.findtext("HOMERACK") if self._pw is not None else None)
        self._rack = self._find_container(donor_cid)
        if self._rack is None or not self._PP or not self._CID:
            raise ValueError("seed has no usable physical workspace (need HOMERACK + a Rack container)")

        self._initial_devs = list(existing)
        self._n = 0
        self._pos = 4
        self._mac = 0x2000
        self._els = {}

    # -- physical workspace helpers ---------------------------------------- #
    def _find_container(self, cid):
        """Find the container NODE (the Rack) and set self._CID to its UUID."""
        root = self._wsroot
        if root is None:
            return None
        rack = None
        for n in root.iter("NODE"):
            u = n.findtext("UUID_STR")
            if cid and u == cid:
                self._CID = cid
                return n
            if rack is None and (n.findtext("TYPE") == "4"
                                 or "rack" in (n.findtext("NAME") or "").lower()):
                rack = n
        if rack is not None:
            self._CID = rack.findtext("UUID_STR")
        return rack

    def _add_leaf(self, name, leaf, x=0):
        ch = self._rack.find("CHILDREN")
        if ch is None:
            ch = ET.SubElement(self._rack, "CHILDREN")
        el = ET.fromstring(
            "<NODE><X>{x}</X><Y>0</Y><TYPE>6</TYPE><NAME translate=\"true\">{name}</NAME>"
            "<SX>1</SX><SY>1</SY><W>0</W><H>0</H><D>0</D>"
            "<PATH isanim=\"false\">../art/Background/grid_100x100.png</PATH><CHILDREN/>"
            "<MANUAL_SCALING>false</MANUAL_SCALING><SCALED_PIXMAP_WIDTH>0</SCALED_PIXMAP_WIDTH>"
            "<SCALED_PIXMAP_HEIGHT>0</SCALED_PIXMAP_HEIGHT><INIT_WIDTH>0</INIT_WIDTH><INIT_HEIGHT>0</INIT_HEIGHT>"
            "<INIT_DEPTH>0</INIT_DEPTH><INIT_SX>1</INIT_SX><INIT_SY>1</INIT_SY><INIT_SZ>1</INIT_SZ>"
            "<BG_TILED>false</BG_TILED><CUSTOM_IMAGE_WIDTH>-1</CUSTOM_IMAGE_WIDTH>"
            "<CUSTOM_IMAGE_HEIGHT>-1</CUSTOM_IMAGE_HEIGHT><SCALE_FACTOR>1</SCALE_FACTOR>"
            "<UUID_STR>{{{u}}}</UUID_STR><SLOT>0</SLOT><SUB_SLOT>0</SUB_SLOT>"
            "<ICP_CSX>0</ICP_CSX><ICP_CSY>0</ICP_CSY></NODE>".format(x=x, name=name, u=leaf))
        ch.append(el)

    def _make_cpur(self, x, leaf):
        """Return a <PHYSICAL_CPUR> string placed in the rack at position x.

        ``leaf`` is the physical leaf's UUID; ORIGINAL_DEVICE_UUID is derived
        from it so the whole document is reproducible (see :func:`_det_uuid`).
        """
        c = copy.deepcopy(self._donor_cpur) if self._donor_cpur is not None else ET.fromstring(
            "<PHYSICAL_CPUR><X_PN>0.03175</X_PN><Y_PN>0.134</Y_PN><X>0</X><Y>0</Y>"
            "<SLOT>0</SLOT><SUBSLOT>0</SUBSLOT><PARENT_PATH></PARENT_PATH>"
            "<CONTAINER_ID></CONTAINER_ID><ICP_CONTAINER_SCENE_X>0</ICP_CONTAINER_SCENE_X>"
            "<ICP_CONTAINER_SCENE_Y>0</ICP_CONTAINER_SCENE_Y>"
            "<ORIGINAL_DEVICE_UUID></ORIGINAL_DEVICE_UUID></PHYSICAL_CPUR>")

        def set_(tag, val):
            e = c.find(tag)
            if e is None:
                e = ET.SubElement(c, tag)
            e.text = val
        set_("PARENT_PATH", self._PP)
        set_("CONTAINER_ID", self._CID)
        set_("X", str(x))
        set_("Y", "0")
        set_("SLOT", "0")
        set_("SUBSLOT", "0")
        set_("ORIGINAL_DEVICE_UUID", "{%s}" % _det_uuid("cpur", leaf))
        return ET.tostring(c, encoding="unicode")

    # -- devices ----------------------------------------------------------- #
    def _next_mac(self) -> str:
        self._mac += 1
        n = self._mac
        return "%04X.%04X.%04X" % (0x0212, (n >> 16) & 0xFFFF, n & 0xFFFF)

    def device_names(self) -> list[str]:
        """Return the names of every device currently in the lab, in document
        order.  This includes the devices inherited from the seed network
        (e.g. SW1, R1, R2, PC-A, PC-B, Server) -- see prune_seed_devices()."""
        return [d.findtext("ENGINE/NAME") or "" for d in self.devs.findall("DEVICE")]

    def _resolve_name(self, name: str, on_name_conflict: str) -> str:
        """Resolve `name` against the names already in use.

        on_name_conflict="raise"  -> ValueError on collision (the default; silent
                                     renaming hides authoring bugs).
        on_name_conflict="suffix" -> auto-rename: SW1 -> SW1(1) -> SW1(2) ...
        """
        if on_name_conflict not in ("raise", "suffix"):
            raise ValueError("on_name_conflict must be 'raise' or 'suffix', got %r"
                             % (on_name_conflict,))
        taken = set(self.device_names())
        if name not in taken:
            return name
        if on_name_conflict == "raise":
            raise ValueError(
                "device name %r is already in use (the seed contributes devices "
                "named SW1, R1, R2, PC-A, PC-B, Server, ...); pick another name, "
                "call prune_seed_devices() first, or pass on_name_conflict='suffix'"
                % (name,))
        n = 1
        while "%s(%d)" % (name, n) in taken:
            n += 1
        return "%s(%d)" % (name, n)

    def add_device(self, model: str, name: str, x: int = 100, y: int = 100,
                   power: bool = True, ios_config: Sequence[str] | None = None,
                   pc_ip: Sequence[str] | None = None, install: str | None = None,
                   bay: int = 0, on_name_conflict: str = "raise") -> str:
        # unique-name check first: a collision must not leave half-added state
        name = self._resolve_name(name, on_name_conflict)
        i = self._n
        self._n += 1
        # fresh physical leaf.  Deterministic: keyed on the document index, so
        # rebuilding the same model produces the same bytes (see _det_uuid).
        leaf = _det_uuid("leaf", self._CID or "", i, name, model)
        px = self._pos
        self._pos += 6
        self._add_leaf(name, leaf, x=px)
        phys = "%s,%s,{%s}" % (self._PP, self._CID, leaf)

        blk = self.models[model].decode("utf-8", "replace")
        s = re.sub(r"save-ref-id:\d+", lambda m: "save-ref-id:%d" % (9_900_000_000_000_000_000 + i), blk)
        s = re.sub(r"<NAME[^>]*>.*?</NAME>", '<NAME translate="true">%s</NAME>' % name, s, count=1, flags=re.S)
        s = re.sub(r"(<WORKSPACE>\s*<LOGICAL>\s*<X>)[^<]*(</X>\s*<Y>)[^<]*(</Y>)",
                   lambda m: m.group(1) + str(x) + m.group(2) + str(y) + m.group(3), s, count=1, flags=re.S)
        # replace PHYSICAL and rebuild PHYSICAL_CPUR
        s = re.sub(r"<PHYSICAL[^>]*>[^<]*</PHYSICAL>", "<PHYSICAL>%s</PHYSICAL>" % phys, s)
        s = re.sub(r"<PHYSICAL_CPUR>.*?</PHYSICAL_CPUR>", "", s, flags=re.S)
        cpur = self._make_cpur(px, leaf)
        s = re.sub(r"(<PHYSICAL>[^<]*</PHYSICAL>)", lambda m: m.group(1) + cpur, s, count=1)
        el = ET.fromstring(s)
        for tag in ("MACADDRESS", "BIA"):
            for e in el.iter(tag):
                e.text = self._next_mac()
        eng = el.find("ENGINE")
        for e in list(eng.findall("SAVE_REF_ID")):
            eng.remove(e)
        sid = "save-ref-id:%d" % (9_900_000_000_000_000_000 + i)
        ET.SubElement(eng, "SAVE_REF_ID").text = sid
        # <ENGINE><POWER> is written explicitly in BOTH directions.  A harvested
        # template may carry a stale state (e.g. a model harvested from a save
        # where that device was switched off), and both PT and pkt_core read a
        # missing element as "off" -- so inheriting the template's text (or
        # leaving the element absent when power=True) is never correct.  See
        # docs/POWER_INVESTIGATION.md.  Only the device-level element is written
        # here; per-port <PORT><POWER> keeps its own semantics and is untouched.
        p = eng.find("POWER")
        if p is None:
            p = ET.Element("POWER")
            kids = list(eng)
            anchor = eng.find("NAME")
            # canonical slot: TYPE, NAME, POWER, ... (child index 2, after NAME)
            at = kids.index(anchor) + 1 if anchor is not None else min(2, len(kids))
            eng.insert(at, p)
        p.text = "true" if power else "false"
        if ios_config:
            for rc in list(eng.findall("RUNNINGCONFIG")):
                eng.remove(rc)
            rc = ET.SubElement(eng, "RUNNINGCONFIG")
            for L in ios_config:
                ET.SubElement(rc, "LINE").text = L
        if pc_ip:
            port = el.find(".//PORT")
            for tag, val in (("IP", pc_ip[0]), ("SUBNET", pc_ip[1]),
                             ("PORT_GATEWAY", pc_ip[2]), ("PORT_DHCP_ENABLE", "false")):
                e = port.find(tag)
                if e is None:
                    e = ET.SubElement(port, tag)
                e.text = val
            # PT reads an end device's default gateway from <ENGINE><GATEWAY>,
            # not from <PORT><PORT_GATEWAY>.  Writing only the port leaves the
            # harvested template's gateway in place, so `ipconfig` shows the
            # donor's address (1.1.1.2 on the shipped PC template) and the device
            # cannot route off-link even though the NIC address looks right.
            gate = eng.find("GATEWAY")
            if gate is None:
                gate = ET.SubElement(eng, "GATEWAY")
            gate.text = pc_ip[2]
        self.devs.append(el)
        self._els[sid] = el
        if install:
            self.install_module(sid, install, bay)
        return sid

    def install_module(self, dev_id, module_model, bay=None, *, slot=None):
        """Install a module into one of a device's eInterfaceCard bays.

        Two ways to say where, and they are not the same thing:

        ``slot=N``
            The **absolute** index among the device's eInterfaceCard bays,
            counting filled ones.  This is what "bay N" normally means, and it
            does not move as other bays fill.
        ``slot=None`` (or nothing)
            The **next empty** bay -- use this to fill bays in order.

        ``bay`` is accepted only for backwards compatibility, and only as
        ``0`` or ``None``, both of which mean "the next empty bay".  ``bay=N``
        for N > 0 **raises**: it would index the list of *currently empty* bays,
        which renumbers as bays fill, so ``bay=1`` silently skips a bay once
        ``bay=0`` has been filled.  That is a trap, not a feature (problem 7 in
        ``docs/ENTERPRISE_PROBLEMS.md``), so it now fails loudly instead of
        quietly doing the wrong thing.
        """
        el = self._els[dev_id]
        eng = el.find("ENGINE")
        # every eInterfaceCard bay, occupied or not, in document order
        all_bays = [sl for sl in eng.iter("SLOT")
                    if sl.findtext("TYPE") == "eInterfaceCard"]
        empties = [sl for sl in all_bays if sl.find("MODULE") is None]

        if slot is not None:
            if slot < 0 or slot >= len(all_bays):
                raise ValueError(
                    f"{dev_id}: slot {slot} out of range; the device has "
                    f"{len(all_bays)} eInterfaceCard bay(s)"
                )
            target = all_bays[slot]
            if target.find("MODULE") is not None:
                raise ValueError(
                    f"{dev_id}: bay {slot} is already occupied; pass "
                    "slot=None to take the next empty bay"
                )
        else:
            if bay not in (None, 0):
                raise ValueError(
                    f"bay={bay} indexes the list of *currently empty* bays, which "
                    "renumbers as bays fill, so bay=1 can silently skip a bay. "
                    "Use slot=<absolute bay index>, or omit both to take the "
                    "next empty bay."
                )
            if not empties:
                raise ValueError(f"{dev_id}: no empty eInterfaceCard bays")
            target = empties[0]

        mod = ET.fromstring(self.modules[module_model])
        for tag in ("MACADDRESS", "BIA"):
            for e in mod.iter(tag):
                e.text = self._next_mac()
        for c in list(target):
            target.remove(c)
        for c in list(mod):
            target.append(c)

    def _append_config(self, dev_id, lines):
        """Append IOS config lines to a device, before a trailing `end` if present."""
        el = self._els.get(dev_id)
        if el is None or not lines:
            return
        eng = el.find("ENGINE")
        rc = eng.find("RUNNINGCONFIG")
        if rc is None:
            rc = ET.SubElement(eng, "RUNNINGCONFIG")
        kids = list(rc)
        idx = len(kids)
        if kids and (kids[-1].text or "").strip().lower() == "end":
            idx = len(kids) - 1
        for off, l in enumerate(lines):
            e = ET.Element("LINE")
            e.text = l
            rc.insert(idx + off, e)

    def _set_serial_port(self, dev_id, port_name, rate):
        """Set CLOCKRATE / CLOCKRATEFLAG=true / POWER=true on a serial port.
        Both ends of a serial link carry POWER=true and CLOCKRATEFLAG=true; only the
        DCE end carries a non-zero CLOCKRATE.  Without these the line stays down
        (cable renders red) even if the IOS config is correct."""
        el = self._els.get(dev_id)
        if el is None:
            return
        ports = [p for p in el.iter("PORT") if p.findtext("TYPE") == "eSmartSerial"]
        if not ports:
            return
        try:
            idx = int(port_name.split("/")[-1])
        except ValueError:
            idx = 0
        if idx >= len(ports):
            idx = 0
        p = ports[idx]
        for tag, val in (("CLOCKRATE", str(rate)), ("CLOCKRATEFLAG", "true"), ("POWER", "true")):
            e = p.find(tag)
            if e is None:
                e = ET.SubElement(p, tag)
            e.text = val

    def link(self, a_id, a_port, b_id, b_port, kind="copper", dce=None, dce_port=None, clock=128000):
        """Add a cable.  kind='copper' (eCopper/eStraightThrough) or
        'serial' (eSerial; pass dce=<device id of the DCE end>).  For a serial
        link the DCE interface is given a `clock rate` automatically (without it
        the line stays down / the cable renders red)."""
        L = ET.SubElement(self.net.find("LINKS"), "LINK")
        ET.SubElement(L, "TYPE").text = "eCopper" if kind == "copper" else ("eSerial" if kind == "serial" else None)
        cab = ET.SubElement(L, "CABLE")
        if kind == "copper":
            fields = [("LENGTH", "1"), ("FUNCTIONAL", "true"), ("FROM", a_id), ("PORT", a_port),
                      ("TO", b_id), ("PORT", b_port), ("FROM_DEVICE_MEM_ADDR", "1"), ("TO_DEVICE_MEM_ADDR", "2"),
                      ("FROM_PORT_MEM_ADDR", "3"), ("TO_PORT_MEM_ADDR", "4"),
                      ("GEO_VIEW_COLOR", "#6ba72e"), ("IS_MANAGED_IN_RACK_VIEW", "false"),
                      ("TYPE", "eStraightThrough")]
        elif kind == "serial":
            dce = dce or a_id
            dport = dce_port or (a_port if dce == a_id else b_port)
            self._set_serial_port(a_id, a_port, clock if dce == a_id else 0)
            self._set_serial_port(b_id, b_port, clock if dce == b_id else 0)
            self._append_config(dce, ["interface %s" % dport, " clock rate %d" % clock])
            fields = [("LENGTH", "1"), ("FUNCTIONAL", "true"), ("FROM", a_id), ("PORT", a_port),
                      ("TO", b_id), ("PORT", b_port), ("FROM_DEVICE_MEM_ADDR", "1"), ("TO_DEVICE_MEM_ADDR", "2"),
                      ("FROM_PORT_MEM_ADDR", "3"), ("TO_PORT_MEM_ADDR", "4"),
                      ("GEO_VIEW_COLOR", "#1e59a5"), ("IS_MANAGED_IN_RACK_VIEW", "false"),
                      ("DCEDEV", dce), ("DCEPORT", dport)]
        else:
            raise ValueError("kind must be 'copper' or 'serial'")
        for t, v in fields:
            ET.SubElement(cab, t).text = v

    def set_os(self, dev_id, image=None, file_name=None):
        """Set a device's OS image / boot file (`<OS_IMAGE>`, `<OS_FILE_NAME>`)."""
        eng = self._els[dev_id].find("ENGINE")
        for tag, val in (("OS_IMAGE", image), ("OS_FILE_NAME", file_name)):
            if val is None:
                continue
            e = eng.find(tag)
            if e is None:
                e = ET.SubElement(eng, tag)
            e.text = val

    def set_config_register(self, dev_id, value):
        eng = self._els[dev_id].find("ENGINE")
        e = eng.find("CONFIG_REGISTER")
        if e is None:
            e = ET.SubElement(eng, "CONFIG_REGISTER")
        e.text = str(value)

    def set_wireless(self, dev_id, ssid=None, auth_type=None, encrypt_type=None,
                     password=None, userid=None, channel=None, radio_band=None):
        """Set the SSID / security on every wireless port of a device (AP, home
        router, laptop, phone, ...).  Wireless devices associate by SSID at runtime
        (no `<LINK>` element is created).  `auth_type`/`encrypt_type` are the raw
        PT enum values (e.g. 0=open, WPA/WPA2 variants differ per device)."""
        el = self._els[dev_id]
        n = 0
        for p in el.iter("PORT"):
            if p.find("SSID") is None:
                continue
            n += 1
            def setp(tag, val):
                e = p.find(tag)
                if e is None:
                    e = ET.SubElement(p, tag)
                e.text = str(val)
            if ssid is not None:
                setp("SSID", ssid)
            if auth_type is not None:
                setp("AUTHEN_TYPE", auth_type)
            if encrypt_type is not None:
                setp("ENCRYPT_TYPE", encrypt_type)
            if password is not None and p.find("WPA_EAP_PASSWORD") is not None:
                setp("WPA_EAP_PASSWORD", password)
            if userid is not None and p.find("WPA_EAP_USERID") is not None:
                setp("WPA_EAP_USERID", userid)
            if channel is not None:
                setp("CHANNEL", channel)
            if radio_band is not None:
                setp("RADIO_BAND", radio_band)
        return n

    def initial_id(self, index=0):
        eng = self._initial_devs[index].find("ENGINE")
        sid = eng.find("SAVE_REF_ID")
        return sid.text if sid is not None else None

    def drop_initial(self):
        """Remove the seed's own devices, their workspace leaves, and any links that
        referenced them (dangling links / orphan leaves corrupt the file)."""
        dead = set()
        for el in self._initial_devs:
            eng = el.find("ENGINE")
            sid = eng.findtext("SAVE_REF_ID")
            if sid:
                dead.add(sid)
            ph = el.findtext("WORKSPACE/PHYSICAL")
            if ph and self._wsroot is not None:
                leaf = "{%s}" % ph.split(",")[-1].strip().strip("{}")
                for n in list(self._wsroot.iter("NODE")):
                    if n.findtext("UUID_STR") == leaf:
                        for parent in self._wsroot.iter("NODE"):
                            ch = parent.find("CHILDREN")
                            if ch is not None and n in list(ch):
                                ch.remove(n)
            if el in list(self.devs):
                self.devs.remove(el)
        links = self.net.find("LINKS")
        if links is not None and dead:
            for L in list(links.findall("LINK")):
                cab = L.find("CABLE")
                if cab is not None and (cab.findtext("FROM") in dead or cab.findtext("TO") in dead):
                    links.remove(L)
        self._initial_devs = []

    def prune_seed_devices(self) -> list[str]:
        """Remove the devices inherited from the seed network, so the lab
        contains only the devices the author placed.  (`drop_seed_devices` is an
        alias for the same method.)

        This is `drop_initial()` under an author-facing name: it removes the seed
        devices, their physical-workspace leaves, and any links that referenced
        them.  Returns the names of the removed devices.  Safe to call twice
        (the second call removes nothing)."""
        names = [el.findtext("ENGINE/NAME") or "" for el in self._initial_devs]
        self.drop_initial()
        return names

    drop_seed_devices = prune_seed_devices

    def save(self, path):
        encode(path, ET.tostring(self.base, encoding="unicode").encode("utf-8"), "pkt")
