# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the project adheres to
[Semantic Versioning](https://semver.org/spec/v2.0.0.html).

Version numbering note: the `SKILL.md v1.2.0` and `v1.3.0` releases in this
repository are revisions of the agent skill document, not of the library. Library
releases are tagged `sdk-v*` and published to PyPI as
[`packet-tracer-pkt-format`](https://pypi.org/project/packet-tracer-pkt-format/).

## [0.4.0] — 2026-10-28

A `pip install` can now **build** a lab, not only read one.

### Added

- **`pkt_core.builder`** — the `Lab` authoring API, ported into the package from
  `tools/lab_api.py`: place a device, set power, install a module, cable copper or
  serial, write an IOS running-config, assign PC addressing, and save.
- **`pkt_core.resources`** — the bundled template library (137 device models, 78
  modules) and the seed document, loaded through `importlib.resources` and cached.
  This is what removes the checkout requirement.
- `from pkt_core import Lab, Layout, load_templates`; `Lab()` and `load_templates()`
  with no arguments use the bundled data.
- `tests/test_resources.py`, covering the loaders and a full build-and-decode round
  trip from the packaged data alone.

### Changed

- `tools/lab_api.py` is now a compatibility shim re-exporting `pkt_core.builder`, so
  the `tools/` scripts and anything doing `import lab_api` from a checkout keep
  working.
- The few call sites that reached through `lab_api.pt9` now use
  `lab_api.decode_bytes` / `encode_bytes`.

### Notes

- The port is behaviour-preserving: the `Lab` code is unchanged apart from the codec
  calls, which now go to the package instead of the root `pt9` module.
- `pkt_core.builder` is **not yet annotated internally** and is therefore excluded
  from `mypy --strict` in `pyproject.toml`, with the reason recorded there. Its
  public signatures are typed, and every other module remains fully checked. The
  remaining work is tracked in `BUILDER_PORT.md`.
- The wheel grows by the two bundled assets (~1.9 MB raw). Scored-activity authoring
  from the package (`tools/activity.py`, `tools/scoring.py`) is not ported yet.

## [0.3.0] — 2026-10-28

First release under the `packet-tracer-pkt-format` name on PyPI.

### Added

- `project.urls` metadata: homepage, repository, issue tracker, documentation,
  changelog, format specification and corpus verification report. The PyPI page
  previously linked nowhere, so the package and the source were mutually invisible.
- `py.typed` marker, so type checkers honour the inline annotations the package
  already carried under `mypy --strict`.
- `Install` and `Quickstart` sections in the README. The README never mentioned the
  published package, and its Python example required a source checkout.

### Fixed

- **Missing runtime dependency.** `pkt_core.models` imports `pydantic`, which
  `pyproject.toml` did not declare, so a clean `pip install -e .` raised
  `ModuleNotFoundError` on `from pkt_core.models import Lab`. Now declared as
  `pydantic>=2.0.0`.
- **Dead console script.** `pt9 = "pt9:main"` could never resolve:
  `[tool.setuptools.packages.find] where = ["src"]` makes setuptools look for
  `src/pt9.py`, and the module lives at the repository root. Entry point removed;
  `pt9.py` remains runnable as a script from a checkout.
- **CLI examples that did not run.** `pkt export -f graphviz` is `--format
  graphviz`, and `pkt pack out/` takes an XML file, not a directory —
  `pkt pack out/<name>.xml`.
- **Misleading dependency claim.** The README presented `libgcrypt` as *the* only
  dependency and required root to install it. It is an optional accelerator; the
  pure-Python cipher path is always available and verified.

### Changed

- Licence declared as a PEP 639 expression (`GPL-3.0-or-later`) with
  `license-files`, replacing the deprecated table form.
- Classifiers: `Development Status :: 4 - Beta`, `Typing :: Typed`, Python 3.10
  through 3.14, `Topic :: Education`.
- Version string in `pkt_core.__version__` now matches the distribution (it said
  `0.1.0` while the metadata said `0.2.0`).

### Credits

- The undeclared `pydantic` dependency was reported by
  [@AhmedIrfan7](https://github.com/AhmedIrfan7) in
  [#2](https://github.com/aacanadaa/packet-tracer-pkt-format/pull/2). The fix here
  was written independently from `main` and shipped before the PR was reviewed; the
  report was correct and the diagnosis in it — that CI hid the problem by installing
  `pydantic` alongside the package — is the reason it is documented this thoroughly.

### Notes

- Still byte-exact: `encode(decode(f)) == f` on all 1,058 corpus files, PT 4.1
  through 9.0.1, and the round trip is exercised in the release verification.
- Generation of new labs still requires the `tools/` generators from a checkout;
  moving them into the package is the next release. See `BUILDER_PORT.md`.

## [Unreleased]

### Planned

- Ship the device/module templates as package data, and move the authoring API from
  `tools/lab_api.py` into `pkt_core.builder`, so `pip install` can generate a lab
  without a checkout.
- Documentation site on GitHub Pages.
