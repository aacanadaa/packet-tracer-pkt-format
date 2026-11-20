# Generation from `pip install` — status

**Shipped in 0.4.0.** A clean `pip install packet-tracer-pkt-format` can now build a
`.pkt`: `pkt_core.builder.Lab` places devices, sets power, installs modules, cables
copper or serial, writes IOS running-configs, assigns PC addressing and saves, all
against the bundled template library and seed document.

This file records what was done, what was deliberately deferred, and what will bite
whoever picks up the rest.

## What shipped

| Piece | Location |
| --- | --- |
| `Lab` authoring API | `src/pkt_core/builder/lab.py` (port of `tools/lab_api.py`) |
| Template library, 137 models / 78 modules | `src/pkt_core/data/device_templates.json` |
| Seed document | `src/pkt_core/data/network_seed.xml` |
| Cached loaders | `src/pkt_core/resources.py` |
| Compatibility shim | `tools/lab_api.py` (re-exports the package) |
| Tests | `tests/test_resources.py` + the existing lab_api/layout/power suites |

`Lab()` and `load_templates()` with no arguments use the bundled data, so the
five-line example in the README works with no checkout and no `sys.path` edits.

## Status of deferred items

**1. Full annotations for `pkt_core.builder` — DONE.** Every method and helper in
`src/pkt_core/builder/lab.py` is now annotated and checked under `mypy --strict`,
and the `pkt_core.builder.*` override in `pyproject.toml` has been removed.

**2. Scored-activity authoring.** `tools/activity.py` and `tools/scoring.py`
remain in `tools/` (now updated to use `pkt_core.codec.container` and proper XML
escaping instead of the root `pt9` script), so building a `.pka` still runs from
a checkout.

**3. Coverage — DONE.** `pkt_core.builder` now sits above **90%** branch-aware
coverage and is folded into the package-wide 90% coverage gate in
`pyproject.toml` (`omit` removed).

**4. Wheel size and a duplicated asset.** The two bundled assets are 1.9 MB raw and
the wheel is roughly 820 KB. Note that `network_seed.xml` and
`device_templates.json` currently exist in both `tools/` and `src/pkt_core/data/`.
Consolidating on one copy (and having `tools/` read from the package) is the
right follow-up so the two cannot drift.

A related trap: `.gitignore` excludes `*.xml` with narrow exceptions, and the first
CI run on this branch failed because the seed document was silently not committed.
The glob is now exempted with a comment, and `tests/test_resources.py` fails loudly
if either asset goes missing again.

## Things that will bite

1. **`import pt9`.** The authoring code used the root-level reference codec. Inside
   the package everything goes through `pkt_core.codec.container`. Do not re-add
   `pt9` as a `py-modules` entry: `packages.find` resolves under `src/`, so
   setuptools looks for `src/pt9.py`, and the file is at the repository root — that
   is exactly how the dead `pt9` console script happened in 0.3.0.

2. **`decode()` now returns a `Container`, not bytes.** The old `pt9.decode(f, fmt)`
   returned the XML payload directly. Every ported call site needs `.xml`. The
   compatibility shim exposes `decode_bytes`/`encode_bytes` for the `tools/` scripts
   that used to reach through `lab_api.pt9`.

3. **The shim re-exports everything dynamically.** That is deliberate — the tools
   reach for `_det_uuid`, `FLOOR` and `ET` — but it means a shim that silently
   misses a name is worse than no shim. If you add a public name to
   `pkt_core.builder.lab`, it is available through `lab_api` automatically.

4. **Coverage is branch-aware.** Adding a module without tests shows up as a
   percentage drop, not as an error, until it trips `fail_under`. Check the builder
   row explicitly after touching it.
