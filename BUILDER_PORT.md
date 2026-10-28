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

## Deferred, on purpose

**1. Full annotations for `pkt_core.builder`.** The module is excluded from
`mypy --strict` in `pyproject.toml`, with the reason inline. Its public signatures
are typed; the bodies are `ElementTree` surgery where `find()` returns `Optional`
everywhere, and annotating 1,000 lines in the same change as a behaviour-preserving
port would have risked the byte-exactness for no user-visible gain.

Annotating it properly is a standalone change: expect asserts or a non-`Optional`
lookup helper at each `find()`, and no behavioural change. Remove the override in
the same commit.

**2. Scored-activity authoring.** `tools/activity.py` (151 lines) and
`tools/scoring.py` (264 lines) are not ported, so building a `.pka` still needs a
checkout. Same treatment: move, replace the `pt9` calls, shim the old path.

**3. Coverage.** The ported module sits at **67%** and is `omit`ted from the
aggregate so it cannot dilute the 90% gate that applies to codec and models. It is
exercised by `test_lab_api`, `test_layout` and `test_power`, just not densely.

**4. Wheel size and a duplicated asset.** The two bundled assets are 1.9 MB raw and
the wheel is now roughly 820 KB. Note that `network_seed.xml` and
`device_templates.json` now exist **twice** — in `tools/` for the authoring scripts
and in `src/pkt_core/data/` for the package. Consolidating on one copy (and having
`tools/` read from the package) is the right follow-up; do it before the two drift.

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

## Next

1. Annotate `pkt_core.builder` and drop the override.
2. Port `activity.py` and `scoring.py`, then a `pkt new` CLI command so the first
   run is one command instead of a Python snippet.
3. Raise builder coverage and fold it back into the aggregate.
