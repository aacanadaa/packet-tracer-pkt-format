# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the project adheres to
[Semantic Versioning](https://semver.org/spec/v2.0.0.html).

Version numbering note: the `SKILL.md v1.2.0` and `v1.3.0` releases in this
repository are revisions of the agent skill document, not of the library. Library
releases are tagged `sdk-v*` and published to PyPI as
[`packet-tracer-pkt-format`](https://pypi.org/project/packet-tracer-pkt-format/).

## [0.4.3] — 2026-11-19

### Security & Robustness

- **Prevent `libgcrypt` handle leaks** in `pkt_core.crypto.ciphers` and `pt9.py`
  by binding and calling `gcry_cipher_close` (including on `setkey` failure,
  in `cipher_available()`, and via `close()` / `__del__`). Added cross-platform
  library discovery (`ctypes.util.find_library` / `.dylib` / `.dll`) and cached
  failed probes.
- **Bound `quncompress()` against decompression bombs** using
  `zlib.decompressobj().decompress(..., max_length=expected + 1)` and wrap
  `struct.error` / `zlib.error` in `qcompress()` as `CompressionError`.
- **Constant-time EAX tag comparison** via `hmac.compare_digest` in
  `EaxResult.valid` and `eax_verify()`; validate `len(nonce) == 16` in
  `ctr_crypt()`.
- **XML parser and writer hardening**: escape `&`, `<`, and active quotes in
  `XmlElement.set()`; add `escape_xml_text()` and use it in `PktNode._set_text()`,
  `Device.set_name()`, and `builder.Lab`; enforce a 512-level nesting limit
  raising `FormatError` instead of `RecursionError`; reject leading `</` and
  empty tag names; preserve trailing `XmlText` on EOF; mark `writer.element()`
  dirty on creation.
- **Native Rust extension (`pkt_core_native`)**: guard `index >= 12` in
  `cast256_quad_round` to return `ValueError` instead of panicking, allocate
  output directly via `PyBytes::new_with` in `encrypt_blocks`, update MSRV to
  Rust 1.83, and add `cast256_quad_round` to `typings/pkt_core_native.pyi`.
- **CI & Docker hardening**: pass `inputs.tag` via `env:` in `publish.yml`,
  validate distributions with `twine check`, auto-create missing GitHub
  Releases, lowercase GHCR repository names, tag `:latest` only on tag pushes,
  validate docs on pull requests in `docs.yml`, and run `Dockerfile` as a
  non-root user after cleaning `/app`.

### Fixed

- **Crypto & Codec**: align `CIPHER_KEY_SIZES["cast256"]` to RFC 2612
  `(16, 20, 24, 28, 32)`; parse `PKT_CORE_DISABLE_RUST=0`/`false` properly and
  assign `_RUST_CIPHER_CLS` before `_RUST_PROBED = True`; fix `root_tag()` to
  skip XML declarations/comments/prologues and guard empty `<>`; allow valid
  legacy containers `>= 6` bytes; wrap unknown format `KeyError` as
  `FormatError`; compute `layer_a` once per decode/detect; use an O(1) 6-byte
  probe in `_looks_like_legacy()`; make `eax_verify()` CMAC-only and accelerate
  `_xor()` / `ctr_crypt()` with integer XOR and bulk `encrypt_blocks`.
- **Models, Audit, Diff & Export**: implement `PktNode.__eq__` on `_el` and
  catch `OverflowError` in `_int()`; fix `Workspace.dev_addr`/`mem_addr`,
  `Port.power`, `Lab.canvas_shapes` direct-child iteration, `.pka` nested
  `<PACKETTRACER5>` resolution, `ScoringNode.children`, `CanvasShape.bounds`,
  and duplicate `PortConfig._claimed` entry; scope `aaa_users` to `<ACS_SERVER>`
  and DHCPv4 port-binding stripping to `<DHCP_SERVERS>`/`<DHCP_SERVER>`; guard
  `engine is None` in `inventory()`; include embedded DNS servers; extract
  `<TYPE model>` when passing `<ENGINE>` directly to `sanitize_engine()`; fix
  `format_identity(("", ""))` and 0-server count in `ServiceInventory.summary()`;
  use `difflib.SequenceMatcher` and canonicalized/disambiguated links in
  `diff_labs()`; inherit `ExportError` from `(PacketTracerError, ValueError)`,
  fix Graphviz `\n` double-escaping, map NetBox `enabled` to `port.power`, and
  safely quote/deduplicate YAML in `to_containerlab()`.
- **Builder, CLI & Docs**: copy `models`/`modules` dicts and use a context
  manager in `builder.Lab.__init__()`; validate `model`, `pc_ip`, `kind`, and
  `dce` before mutating state; support `slot=` in `add_device()`; fix
  multi-module serial port resolution in `_set_serial_port()`; skip empty
  pattern lists in `load_tier_map()`; output pure JSON in `pkt info --json` and
  hide `key byte`/`iv byte` for legacy containers; deduplicate `.cfg` filenames
  in `pkt unpack`; fix `pkt diff` exit status and `--unified` on layout-only
  diffs; add `--version` and catch `(OSError, ValueError, KeyError)` in `main()`;
  handle `#anchor` fragments and directory `/tree/` links in
  `hooks/rewrite_repo_links.py`; update stale `README.md` notes.

## [0.4.2] — 2026-11-15

### Added

- **`python -m pkt_core.cli`** — added `src/pkt_core/cli/__main__.py` so the CLI
  can be invoked directly as a module without a console-script install.

### Changed

- Documentation, README, demo, and Windows CI updates since `0.4.1`.

## [0.4.1] — 2026-10-29

### Fixed

- **`add_device(pc_ip=...)` wrote the default gateway where Packet Tracer does not
  read it.** The gateway went to `<PORT><PORT_GATEWAY>`; PT reads an end device's
  gateway from `<ENGINE><GATEWAY>`, which kept the harvested template's value —
  `1.1.1.2` on the shipped PC template. The NIC address and mask were correct, so
  `ipconfig` looked fine except for a gateway belonging to no network in the lab,
  and the device could not route off-link: a ping to the far site timed out.

  Found by generating a lab and actually opening it in Packet Tracer 9.0.1. Both
  elements are now written, and `tests/test_resources.py` pins both, since writing
  only one is the bug. See `demo/DEMO.md`.

### Known issue

- Serial links (`install="HWIC-2T"` with `lab.link(..., kind="serial")`) still
  produce a container that PT 9.0.1 rejects as *"not compatible with this version"*.
  The same topology over Gigabit opens cleanly, so the fault is in what the serial
  link writes rather than in the codec. Not yet diagnosed.

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
