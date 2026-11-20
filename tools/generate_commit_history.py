#!/usr/bin/env python3
"""Generate xkcd-style repository commit history SVGs (light + dark).

Matches the visual layout of star-history.com charts (800x533.333, xkcd font,
feTurbulence + feDisplacementMap hand-drawn filter, top-left legend) and plots
cumulative commits over time for the repository along with per-contributor
curves.
"""

from __future__ import annotations

import collections
import datetime as dt
import pathlib
import re
import subprocess
from typing import Sequence

REPO_NAME = "aacanadaa/packet-tracer-pkt-format"
ROOT = pathlib.Path(__file__).resolve().parent.parent
IMG_DIR = ROOT / "docs" / "img"

# Author normalization map (maps git author name / email prefix -> GitHub login)
AUTHOR_ALIAS = {
    "suoim": "aacanadaa",
    "aacanadaa": "aacanadaa",
    "rydenb": "Rydenb",
}

LIGHT_PALETTE = [
    "#dd4528",  # total repo commits (star-history signature red-orange)
    "#2b7bba",  # contributor 1 (blue)
    "#2ca02c",  # contributor 2 (green)
    "#9467bd",  # contributor 3 (purple)
    "#e377c2",  # contributor 4 (pink)
]

DARK_PALETTE = [
    "#ff6b6b",  # total repo commits (star-history dark signature coral)
    "#58a6ff",  # contributor 1 (blue)
    "#3fb950",  # contributor 2 (green)
    "#bc8cff",  # contributor 3 (purple)
    "#f778ba",  # contributor 4 (pink)
]


def _normalize_author(name: str, email: str) -> str:
    low_name = name.strip().lower()
    if low_name in AUTHOR_ALIAS:
        return AUTHOR_ALIAS[low_name]
    m = re.match(r"^(?:\d+\+)?([^@]+)@users\.noreply\.github\.com$", email.strip(), re.I)
    if m:
        handle = m.group(1)
        return AUTHOR_ALIAS.get(handle.lower(), handle)
    return name.strip()


def _collect_commit_series() -> tuple[list[dt.date], dict[str, list[int]]]:
    out = subprocess.check_output(
        ["git", "log", "--reverse", "--format=%ad|%an|%ae", "--date=short"],
        cwd=ROOT,
        text=True,
    )
    daily_total: dict[dt.date, int] = collections.Counter()
    daily_by_author: dict[str, dict[dt.date, int]] = collections.defaultdict(
        collections.Counter
    )
    author_totals: dict[str, int] = collections.Counter()

    for line in out.splitlines():
        line = line.strip()
        if not line:
            continue
        date_s, name, email = line.split("|", 2)
        day = dt.date.fromisoformat(date_s)
        author = _normalize_author(name, email)
        daily_total[day] += 1
        daily_by_author[author][day] += 1
        author_totals[author] += 1

    if not daily_total:
        today = dt.date.today()
        return [today], {REPO_NAME: [0]}

    start_day = min(daily_total) - dt.timedelta(days=1)
    end_day = max(daily_total)
    num_days = (end_day - start_day).days
    dates = [start_day + dt.timedelta(days=i) for i in range(num_days + 1)]

    series: dict[str, list[int]] = {}
    running = 0
    total_curve: list[int] = []
    for d in dates:
        running += daily_total.get(d, 0)
        total_curve.append(running)
    series[f"{REPO_NAME} (total)"] = total_curve

    for author, _count in sorted(
        author_totals.items(), key=lambda kv: (-kv[1], kv[0].lower())
    ):
        running_a = 0
        curve: list[int] = []
        per_day = daily_by_author[author]
        for d in dates:
            running_a += per_day.get(d, 0)
            curve.append(running_a)
        series[f"@{author}"] = curve

    return dates, series


def _nice_ymax(max_val: int) -> tuple[int, int]:
    if max_val <= 10:
        return 10, 2
    if max_val <= 50:
        return ((max_val + 9) // 10) * 10, 10
    if max_val <= 100:
        return ((max_val + 19) // 20) * 20, 20
    step = 25 if max_val <= 200 else 50
    top = ((max_val + step - 1) // step) * step
    return top, step


def _svg_path(points: Sequence[tuple[float, float]]) -> str:
    if not points:
        return ""
    cmds = [f"M{points[0][0]:.2f} {points[0][1]:.2f}"]
    for x, y in points[1:]:
        cmds.append(f"L{x:.2f} {y:.2f}")
    return " ".join(cmds)


def _extract_xkcd_font_css() -> str:
    sh_svg = pathlib.Path("/tmp/sh_light.svg")
    if sh_svg.exists():
        m = re.search(r"(@font-face\{font-family:&quot;xkcd&quot;;src:url\([^)]+\)format\(&quot;woff&quot;\)\})", sh_svg.read_text())
        if m:
            return m.group(1)
    existing = IMG_DIR / "commit-history-light.svg"
    if existing.exists():
        m = re.search(r"(@font-face\{font-family:&quot;xkcd&quot;;src:url\([^)]+\)format\(&quot;woff&quot;\)\})", existing.read_text())
        if m:
            return m.group(1)
    return ""


def render_svg(
    dates: list[dt.date],
    series: dict[str, list[int]],
    *,
    dark: bool,
    font_css: str,
) -> str:
    bg = "#0d1117" if dark else "#fff"
    fg = "#fff" if dark else "#000"
    muted = "#8b949e" if dark else "#666"
    palette = DARK_PALETTE if dark else LIGHT_PALETTE

    chart_w = 700.0
    chart_h = 423.333

    max_val = max(max(vals) for vals in series.values())
    y_max, y_step = _nice_ymax(max_val)

    # X-axis ticks (~6 evenly spaced dates)
    n_dates = len(dates)
    tick_count = min(6, n_dates)
    tick_indices = sorted(
        {round(i * (n_dates - 1) / max(1, tick_count - 1)) for i in range(tick_count)}
    )
    x_ticks_xml: list[str] = []
    for idx in tick_indices:
        x = (idx / max(1, n_dates - 1)) * chart_w
        label = dates[idx].strftime("%b %d")
        x_ticks_xml.append(
            f'<text y="6" fill="currentColor" class="tick" dy=".71em" '
            f'style="font-family:xkcd;font-size:15px;fill:{fg}" '
            f'transform="translate({x:.2f} {chart_h:.3f})">{label}</text>'
        )

    # Y-axis ticks
    y_ticks_xml: list[str] = []
    for val in range(0, y_max + 1, y_step):
        y = chart_h - (val / y_max) * (chart_h - 12.0)
        label = " " if val == 0 else str(val)
        y_ticks_xml.append(
            f'<g class="tick"><path stroke="currentColor" d="M0 {y:.3f}h-1"/>'
            f'<text x="-7" fill="currentColor" dy=".32em" '
            f'style="font-family:xkcd;font-size:16px;fill:{fg}" '
            f'transform="translate(0 {y:.3f})">{label}</text></g>'
        )

    # Data lines & end markers
    lines_xml: list[str] = []
    legend_rows_xml: list[str] = []
    max_label_len = 0
    for i, (label, vals) in enumerate(series.items()):
        color = palette[i % len(palette)]
        pts: list[tuple[float, float]] = []
        for idx, v in enumerate(vals):
            x = (idx / max(1, n_dates - 1)) * chart_w
            y = chart_h - (v / y_max) * (chart_h - 12.0)
            pts.append((x, y))
        path_d = _svg_path(pts)
        stroke_w = "3.5" if i == 0 else "2.5"
        dash = "" if i == 0 else ' stroke-dasharray="6,3"'
        lines_xml.append(
            f'<path fill="none" stroke="{color}" stroke-width="{stroke_w}"{dash} '
            f'd="{path_d}" class="xkcd-chart-xyline" filter="url(#xkcdify)"/>'
        )
        end_x, end_y = pts[-1]
        lines_xml.append(
            f'<circle cx="{end_x:.2f}" cy="{end_y:.2f}" r="4.5" fill="{color}" '
            f'filter="url(#xkcdify)"/>'
        )
        display_label = f"{label}: {vals[-1]}"
        max_label_len = max(max_label_len, len(display_label))
        row_y = 20 + i * 22
        box_y = row_y - 8
        legend_rows_xml.append(
            f'<rect width="8" height="8" x="10" y="{box_y}" filter="url(#xkcdify)" '
            f'rx="2" ry="2" style="fill:{color}"/>'
            f'<text x="24" y="{row_y}" style="font-size:15px;fill:{fg}">{display_label}</text>'
        )

    legend_w = max(210, int(max_label_len * 8.2 + 34))
    legend_h = 14 + len(series) * 22

    return (
        f'<svg xmlns="http://www.w3.org/2000/svg" width="800" height="533.333" '
        f'viewBox="0 0 800 533.333" style="stroke-width:3;font-family:xkcd;background:{bg}">'
        f"<defs><style>{font_css}</style></defs>"
        f'<filter id="xkcdify" width="100%" height="100%" x="-5" y="-5" filterUnits="userSpaceOnUse">'
        f'<feTurbulence baseFrequency=".05" result="noise" type="fractalNoise"/>'
        f'<feDisplacementMap in="SourceGraphic" in2="noise" scale="5" xChannelSelector="R" yChannelSelector="G"/>'
        f"</filter>"
        f'<g pointer-events="all" transform="translate(70 60)">'
        f'<text style="font-size:15px;fill:{muted}" text-anchor="end" transform="translate(695 463.333)">'
        f"{REPO_NAME}</text>"
        f'<g fill="none" class="xaxis" font-family="sans-serif" font-size="10" text-anchor="middle">'
        f'<path stroke="currentColor" d="M.5.5h700" class="domain" filter="url(#xkcdify)" '
        f'style="stroke:{fg}" transform="translate(0 {chart_h:.3f})"/>'
        f'{"".join(x_ticks_xml)}'
        f"</g>"
        f'<g fill="none" class="yaxis" font-family="sans-serif" font-size="10" text-anchor="end">'
        f'<path stroke="currentColor" d="M-1 423.833H.5V.5H-1" class="domain" filter="url(#xkcdify)" '
        f'style="stroke:{fg}"/>'
        f'{"".join(y_ticks_xml)}'
        f"</g>"
        f'{"".join(lines_xml)}'
        f'<rect width="{legend_w}" height="{legend_h}" fill-opacity=".88" stroke="{fg}" '
        f'stroke-width="2" filter="url(#xkcdify)" rx="5" ry="5" style="fill:{bg}" '
        f'transform="translate(8 5)"/>'
        f'<g transform="translate(8 5)">{"".join(legend_rows_xml)}</g>'
        f"</g>"
        f'<text x="50%" y="32" style="font-size:20px;font-weight:700;fill:{fg}" text-anchor="middle">'
        f"Commit History</text>"
        f'<text x="50%" y="523.333" style="font-size:17px;fill:{fg}" text-anchor="middle">Date</text>'
        f'<text x="-217" y="18" dy=".75em" style="font-size:17px;fill:{fg}" text-anchor="end" '
        f'transform="rotate(-90)">Commits</text>'
        f"</svg>\n"
    )


def main() -> None:
    import sys

    out_dir = pathlib.Path(sys.argv[1]).resolve() if len(sys.argv) > 1 else IMG_DIR
    out_dir.mkdir(parents=True, exist_ok=True)
    dates, series = _collect_commit_series()
    font_css = _extract_xkcd_font_css()
    light_path = out_dir / "commit-history-light.svg"
    dark_path = out_dir / "commit-history-dark.svg"
    light_path.write_text(render_svg(dates, series, dark=False, font_css=font_css), encoding="utf-8")
    dark_path.write_text(render_svg(dates, series, dark=True, font_css=font_css), encoding="utf-8")
    print(f"Wrote {light_path} and {dark_path} ({len(dates)} days, series={list(series)})")


if __name__ == "__main__":
    main()

