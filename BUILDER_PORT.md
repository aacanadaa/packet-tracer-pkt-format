# Plan: make generation work from `pip install`

**Status:** not started. **Blocker it removes:** the README promises "build Packet
Tracer labs without Packet Tracer", but a clean `pip install` can only *read*.
Generation still requires a source checkout and `python3 tools/...`.

## Why this is the next release

Every distribution channel sends people to `pip install`. Today that install cannot
do the thing the project is named for, so the first thing a new user tries fails —
not with an error, but with a missing feature. Until this lands, the package is a
reader, and the headline claim belongs to the repository rather than the product.

## What moves

| Source | Destination | Lines |
| --- | --- | --- |
| `tools/lab_api.py` | `src/pkt_core/builder/lab.py` | 1,037 |
| `tools/activity.py` | `src/pkt_core/builder/activity.py` | 151 |
| `tools/scoring.py` | `src/pkt_core/builder/scoring.py` | 264 |
| `tools/device_templates.json` | `src/pkt_core/data/device_templates.json` | 829 KB |
| `tools/device_shapes.json` | `src/pkt_core/data/device_shapes.json` | 134 KB |
| `tools/network_seed.xml` | `src/pkt_core/data/network_seed.xml` | 1.0 MB |
| `tools/activity_skeleton.xml` | `src/pkt_core/data/activity_skeleton.xml` | 314 KB |

Plus a new `src/pkt_core/resources.py` exposing cached loaders over
`importlib.resources`, so callers stop passing filesystem paths.

## Five traps, in the order they will bite

1. **`import pt9`.** `lab_api.py` imports the root-level `pt9` module, which is not
   shipped in the wheel (and now has no console script either). Every call site must
   move to `from pkt_core.codec import decode, encode`, and `pt9.py` stays behind as
   a standalone reference script. Do not `py-modules`-ship it: `packages.find`
   resolves under `src/`, so `src/pt9.py` is where setuptools looks, and the file is
   at the root.

2. **`mypy --strict`.** This is the real cost. The module has roughly 60 annotated
   sites across 1,037 lines; `--strict` requires full coverage on every function,
   including the `ET.Element` juggling and the `NamedTuple` field types. Budget most
   of the work here, not on the move. An `# type: ignore` blanket is not acceptable —
   the CI gate is `mypy --strict src/pkt_core` with no exclusions, and weakening it
   to land this would cost more than it buys.

3. **Coverage gate.** `fail_under = 90` is enforced in `pyproject.toml`. 1,452 moved
   lines with no tests drags the total down sharply. Port `tests/test_lab_api.py`,
   `test_layout.py` and `test_power.py` in the same commit, and add coverage for
   `resources.py`.

4. **Seven test files reference `tools/`** — `test_audit`, `test_install_module`,
   `test_ios_audit`, `test_lab_api`, `test_layout`, `test_power`,
   `test_reproducible_build`. They must resolve through the package instead of the
   checkout, or the release passes tests that no longer reflect what ships.

5. **Wheel size.** The four assets are 2.3 MB raw. They compress well (the seed XML
   is highly repetitive), but check the wheel after adding them; if it matters, ship
   them gzipped and inflate in `resources.py`. Do not add them twice — keep
   `tools/` as the authoring source and copy, or make `tools/` read from the package,
   but pick one.

## Order of work

1. `src/pkt_core/data/` + `resources.py` + `[tool.setuptools.package-data]` entry.
   Small, typed, testable. Ship it even if the rest slips.
2. `builder/lab.py`: move, replace `pt9` imports, annotate to `--strict`.
3. `builder/activity.py` and `builder/scoring.py`: same treatment.
4. `tests/`: repoint the seven files, add `test_builder.py` and `test_resources.py`.
5. `cli/main.py`: add `pkt new --out lab.pkt` so the first-run experience is one
   command, not a Python snippet.
6. README: move the generation example from "requires a checkout" to Quickstart.

## Acceptance criteria

- [ ] `pip install packet-tracer-pkt-format` then a five-line script writes a `.pkt`
      that Packet Tracer opens, with no checkout and no `sys.path` edits.
- [ ] `mypy --strict src/pkt_core` passes with no new exclusions.
- [ ] `pytest` passes, coverage ≥ 90%, corpus round trip unchanged.
- [ ] `grep -r "import pt9" src/` is empty.
- [ ] The wheel contains `pkt_core/data/*` and `pkt_core/py.typed`.

## Rough estimate

One focused session for `resources.py` plus the move; a second for the annotations,
which is where the variance is. The port is mechanical but not small, and doing it
half-typed would trade a shipped feature for a weakened type gate.

## Interim wording

Until this lands, say so plainly in the README rather than letting the promise stand
unqualified — a scoped honest claim converts better than a broken generous one.
