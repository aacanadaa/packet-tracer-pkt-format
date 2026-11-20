# Contributing

Thanks for looking at contributing to `packet-tracer-pkt-format`. The main invariant across the codec is byte-exact round-tripping: `encode(decode(f)) == f` on every valid container.

## Useful contributions

- **Round-trip bugs**: a `.pkt`/`.pka` file that fails to decode or changes after `pkt unpack` / `pkt pack`. Include `pkt info` output and the Packet Tracer version (`Help > About`).
- **New Packet Tracer versions**: format or schema changes introduced by newer PT builds.
- **Template coverage**: new device, module, or scoring templates harvested from your own files using `tools/harvest_library.py`, with a test covering them.
- **Docs and tests**: fixes to format docs, examples, or test coverage.

## Local setup

Requires Python 3.10+.

```console
$ git clone https://github.com/aacanadaa/packet-tracer-pkt-format.git
$ cd packet-tracer-pkt-format
$ python -m venv .venv
$ source .venv/bin/activate          # Linux / macOS
$ .venv\Scripts\activate             # Windows
$ pip install -e ".[dev]"
```

To build the optional Rust extension locally (requires Rust 1.83+):

```console
$ pip install maturin
$ pip install --no-build-isolation ./native/pkt_core_native
```

The Rust extension is optional; `pkt_core` must always work with the pure-Python backend alone.

## Running checks

| Check | Command |
| --- | --- |
| Type check | `python -m mypy --strict src/pkt_core` |
| Tests + coverage | `python -m pytest tests/ --cov=pkt_core --cov-report=term-missing` |
| Pure-Python backend | `PKT_CORE_DISABLE_RUST=1 python -m pytest tests/` |
| Rust unit tests / KATs | `cargo test --no-default-features` (in `native/pkt_core_native`) |
| Package build check | `python -m build && twine check dist/*` |

CI enforces a 90% coverage gate across the entire `pkt_core` package (including `pkt_core.builder`) and runs `pytest` and `mypy --strict` on both Linux and Windows.

## Corpus and test fixtures

The 1,026 third-party `.pkt`/`.pka` files used for verification are not committed. You can fetch them locally with [`corpus/fetch_corpus.py`](corpus/fetch_corpus.py) (verified against [`corpus/CORPUS_INDEX.tsv`](corpus/CORPUS_INDEX.tsv)), then run the slow corpus suite:

```console
$ python -m pytest tests/ -m corpus
```

`*.pkt`, `*.pka`, and `*.xml` are gitignored. If a test needs a fixture file, generate it with this project's tools and place it in [`corpus/samples/`](corpus/samples/). Do not commit third-party Packet Tracer files.

## Coding guidelines

- Keep `src/pkt_core` clean under `mypy --strict`. Raise typed exceptions from `pkt_core.errors` instead of bare `Exception`.
- Keep `pkt_core.cli` a consumer of the library; nothing under `src/pkt_core/` (outside `cli/`) should import `pkt_core.cli`.
- Bug fixes should include a regression test that fails before the fix.
- Any audit/validation count should report distinct items rather than raw occurrences alone.

## Pull requests

`main` is protected, so all changes go through a PR.

- Keep PRs focused on one change where possible.
- Include a short description of what changed and how you tested it (including the PT version if you verified in Packet Tracer).
- Link any related issue.

## Licensing and content rules

This project is licensed under **GPL-3.0-or-later**, and contributions are accepted under the same license. Please do not submit:

- Cisco courseware or Cisco-copyrighted material.
- Third-party `.pkt`/`.pka` binaries.
- Code copied from GPL-incompatible sources.

## Reporting bugs

When opening an issue, please include:

- Packet Tracer version (`Help > About`)
- `pkt info <file>` output
- Python version and `pip show packet-tracer-pkt-format`
- A minimal reproducer (or a description of the file if you cannot share it)
- Expected vs. actual behavior

For security issues, reach out via the contact details on the maintainer's GitHub profile rather than opening a public issue.
