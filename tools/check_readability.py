#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 aacanadaa
# This file is part of packet-tracer-pkt-format (GPL-3.0-or-later).
"""Measure how *readable* a lab's layout is, not just whether it is legal.

`check_layout.py` answers "does anything overlap or fall off the page?". It does
not answer the question a reader asks first: **can I follow a cable?** A lab can
pass every geometry gate and still be a wall of crossing lines, because a layout
that is geometrically valid is not necessarily legible.

Two measurements, both from the written artefact:

``crossings``
    How many times two cables cross. A crossing is where a reader's eye is
    pulled onto the wrong cable; crossings per cable is the single best proxy
    for "spaghetti".

``cable length``
    Centre-to-centre distance in canvas units (1 unit = 1 px at 100% zoom),
    reported as min/median/p95/max/mean. Long cables are the *cause* of most
    crossings: a cable that spans eight bands crosses everything in between.

Bands are derived from the layout itself -- devices are grouped by their Y
coordinate -- so this works on any lab without knowing its naming convention.

    python3 tools/check_readability.py lab.pkt
    python3 tools/check_readability.py lab.pkt --max-crossings-per-cable 4.0
"""
from __future__ import annotations

import argparse
import collections
import json
import sys
import xml.etree.ElementTree as ET
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
for _p in (str(ROOT), str(ROOT / "tools")):
    if _p not in sys.path:
        sys.path.insert(0, _p)

from pkt_core import decode_bytes          # noqa: E402


def _cross(p, p2, q, q2) -> bool:
    """True when open segments p-p2 and q-q2 cross (touching does not count)."""
    def orient(a, b, c):
        v = (b[0] - a[0]) * (c[1] - a[1]) - (b[1] - a[1]) * (c[0] - a[0])
        return (v > 0) - (v < 0)
    o1, o2 = orient(p, p2, q), orient(p, p2, q2)
    o3, o4 = orient(q, q2, p), orient(q, q2, p2)
    return o1 != o2 and o3 != o4


def analyse(root: ET.Element, band_tol: int = 120) -> dict:
    pos: dict[str, tuple[int, int]] = {}
    for d in root.iter("DEVICE"):
        nm = d.findtext("ENGINE/NAME")
        x = d.findtext("WORKSPACE/LOGICAL/X")
        y = d.findtext("WORKSPACE/LOGICAL/Y")
        if nm and x is not None and y is not None:
            pos[nm] = (int(float(x)), int(float(y)))

    # Bands come from the layout: sort distinct Y levels and cut where the gap
    # exceeds a row pitch, so this needs no knowledge of the lab's names.
    levels = sorted({y for _x, y in pos.values()})
    band_of: dict[int, int] = {}
    idx = -1
    prev = None
    for y in levels:
        if prev is None or y - prev > band_tol:
            idx += 1
        band_of[y] = idx
        prev = y
    band = {nm: band_of[y] for nm, (_x, y) in pos.items()}

    sid = {d.findtext("ENGINE/SAVE_REF_ID"): d.findtext("ENGINE/NAME")
           for d in root.iter("DEVICE")}
    seen = set()
    cables: list[tuple[str, str]] = []
    for lk in root.iter("LINK"):
        cab = lk.find("CABLE")
        if cab is None:
            continue
        a, b = sid.get(cab.findtext("FROM")), sid.get(cab.findtext("TO"))
        if a in pos and b in pos and a != b:
            k = tuple(sorted((a, b)))
            if k not in seen:
                seen.add(k)
                cables.append((a, b))

    lengths = []
    per_band = collections.Counter()
    per_band_len = collections.Counter()
    for a, b in cables:
        (x1, y1), (x2, y2) = pos[a], pos[b]
        d = ((x2 - x1) ** 2 + (y2 - y1) ** 2) ** 0.5
        lengths.append((d, a, b))
        for nm in (a, b):
            per_band[band[nm]] += 1
            per_band_len[band[nm]] += d

    crossings = 0
    crossing_pairs = []
    for i in range(len(cables)):
        a1, b1 = cables[i]
        for j in range(i + 1, len(cables)):
            a2, b2 = cables[j]
            if len({a1, b1, a2, b2}) < 4:
                continue                      # share an endpoint: not a crossing
            if _cross(pos[a1], pos[b1], pos[a2], pos[b2]):
                crossings += 1
                if len(crossing_pairs) < 20:
                    crossing_pairs.append((a1, b1, a2, b2))

    lengths.sort(reverse=True)
    vals = sorted(d for d, _a, _b in lengths) or [0]
    inter = sum(1 for a, b in cables if band[a] != band[b])
    return dict(
        devices=len(pos),
        cables=len(cables),
        bands=idx + 1,
        inter_band_cables=inter,
        intra_band_cables=len(cables) - inter,
        crossings=crossings,
        crossings_per_cable=round(crossings / max(1, len(cables)), 2),
        length_min=round(vals[0], 1),
        length_median=round(vals[len(vals) // 2], 1),
        length_p95=round(vals[int(len(vals) * 0.95) - 1], 1),
        length_max=round(vals[-1], 1),
        length_mean=round(sum(vals) / len(vals), 1),
        longest=[dict(length=round(d, 1), a=a, b=b) for d, a, b in lengths[:10]],
        band_cables=dict(sorted(per_band.items())),
        band_mean_length={k: round(per_band_len[k] / per_band[k], 1)
                          for k in sorted(per_band)},
        crossing_pairs=crossing_pairs,
    )


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("lab", type=Path)
    ap.add_argument("--json", type=Path, default=None)
    ap.add_argument("--band-tol", type=int, default=120,
                    help="Y gap that starts a new band (default 120)")
    ap.add_argument("--max-crossings-per-cable", type=float, default=None,
                    help="exit 1 above this ratio")
    ap.add_argument("--show-pairs", action="store_true")
    a = ap.parse_args(argv)

    raw = a.lab.read_bytes()
    root = ET.fromstring(raw if raw[:1] == b"<" else decode_bytes(raw).xml)
    r = analyse(root, band_tol=a.band_tol)

    print(f"lab       : {a.lab.name}")
    print(f"devices   : {r['devices']}   cables: {r['cables']}   bands: {r['bands']}")
    print(f"cabling   : {r['intra_band_cables']} intra-band, "
          f"{r['inter_band_cables']} inter-band")
    print(f"crossings : {r['crossings']}  ({r['crossings_per_cable']} per cable)")
    print(f"length    : min {r['length_min']}  median {r['length_median']}  "
          f"p95 {r['length_p95']}  max {r['length_max']}  mean {r['length_mean']}")
    print("\n-- per band: cables and mean cable length --")
    for b in r["band_cables"]:
        print(f"   band {b:3d}  cables {r['band_cables'][b]:4d}   "
              f"mean length {r['band_mean_length'][b]:7.1f}")
    print("\n-- longest ten cables --")
    for e in r["longest"]:
        print(f"   {e['length']:7.1f}  {e['a']}  <->  {e['b']}")
    if a.show_pairs:
        print("\n-- first crossing pairs --")
        for a1, b1, a2, b2 in r["crossing_pairs"]:
            print(f"   ({a1} - {b1})  x  ({a2} - {b2})")
    if a.json:
        a.json.parent.mkdir(parents=True, exist_ok=True)
        a.json.write_text(json.dumps(r, indent=1, sort_keys=True))
    if (a.max_crossings_per_cable is not None
            and r["crossings_per_cable"] > a.max_crossings_per_cable):
        print(f"\nFAIL: {r['crossings_per_cable']} crossings per cable exceeds "
              f"{a.max_crossings_per_cable}")
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
