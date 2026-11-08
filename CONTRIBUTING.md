# Contributing

This is a reverse-engineering project with one hard promise:
`encode(decode(f)) == f`, byte for byte, on every file it accepts. Most of what
follows exists to keep that promise checkable.

## What helps most

* **A file that does not round-trip.** The most valuable bug report here is a real
  `.pkt`/`.pka` that the decoder mis-handles. Include the `pkt info` output, the
  Packet Tracer version that wrote it, and what `pkt pack` does differently.
* **A Packet Tracer build that behaves differently.** If a new PT release changes
  the container, that is a format bug, not a user error. Say which build
  (`Help > About` gives the full version) and what changed.
* **A device, module or shape the template library lacks.** `tools/harvest_library.py`
  can extend coverage from your own files; a PR that adds harvested entries plus
  the test that exercises them is welcome.
* **A correction to the documentation**, with the evidence behind it. Numbers in
  these docs are supposed to be checkable against something in the repo. If one
  is not, that itself is the bug.

## Setting up

```console
$ git clone https://github.com/aacanadaa/packet-tracer-pkt-format.git
$ cd packet-tracer-pkt-format
$ python -m venv .venv
$ source .venv/bin/activate          # Linux / macOS
$ .venv\Scripts\activate             # Windows
$ pip install -e . pytest pytest-cov hypothesis mypy
```

Python 3.10 or newer. CI runs the suite on 3.10 (the documented floor) and 3.14.

To build the optional Rust accelerator:

```console
$ pip install maturin
$ pip install --no-build-isolation ./native/pkt_core_native
```

It is optional on purpose. Nothing in `src/pkt_core` may require it, and the
pure-Python ciphers are the reference path.

## What CI checks

| Check | Command |
| --- | --- |
| Types | `python -m mypy --strict src/pkt_core` |
| Tests and coverage | `python -m pytest tests/ --cov=pkt_core --cov-report=term-missing` |
| Pure-Python only | `PKT_CORE_DISABLE_RUST=1 python -m pytest tests/` |
| Native KATs | `cargo test --no-default-features` in `native/pkt_core_native` |

Coverage is gated at 90%. `pkt_core.builder` is excluded from the aggregate on
purpose; [`BUILDER_PORT.md`](BUILDER_PORT.md) explains why and tracks closing the
gap, and its public signatures are still type-checked.

## The corpus

The 1,026 third-party containers used for the reverse engineering are **not**
committed. [`corpus/fetch_corpus.py`](corpus/fetch_corpus.py) rebuilds them from
the upstreams, verified by SHA-256 against
[`corpus/CORPUS_INDEX.tsv`](corpus/CORPUS_INDEX.tsv). The policy is in
[`corpus/README.md`](corpus/README.md).

Whole-corpus tests are slow and opt-in:

```console
$ python -m pytest tests/ -m corpus
```

`*.pkt`, `*.pka` and `*.xml` are gitignored. If you need a fixture, generate one
and commit it under [`corpus/samples/`](corpus/samples/): those are produced by
this project and carry its licence. Do not commit files you did not make.

## Tests that earn their place

Two habits, both learned the hard way:

1. **A bug fix lands with a test that fails before it.** The `pc_ip` gateway bug
   wrote the gateway to `<PORT_GATEWAY>` when PT reads `<ENGINE><GATEWAY>`; the
   fix pins *both* elements, because writing only one is the bug.
2. **If a validator prints a count, it must prove those items are distinct.**
   This is Rule 3 in [`SKILL.md`](SKILL.md), and it exists because a validator
   once printed `PASSED` over 202 AAA clients of which 140 were real.

A test that only asserts presence is not a test.

## Code style

* `mypy --strict` for `src/pkt_core`. No bare `Exception`; raise the typed ones
  in `pkt_core.errors`.
* Comments explain *why*. The code already says what.
* Prose uses British spelling (licence, normalise, serialise).
* The READMEs avoid em dashes. Chinese punctuation in `README.zh-CN.md` is fine.
* Keep the CLI a consumer of the library. Nothing in `src/pkt_core` imports it.

## Pull requests

`main` is protected, so everything goes through a PR. Please keep them small and
single-purpose: a format fix and a README edit are two PRs.

* Imperative subject line, no prefix ceremony required.
* Link the issue if there is one.
* Say how you verified it: which Packet Tracer version, what you opened, what
  you expected and what happened.

## Licensing and provenance

This project is **GPL-3.0-or-later**, and contributions come in under the same
licence. Three things that cannot be merged:

* Cisco course material or any Cisco-copyrighted file.
* Third-party `.pkt`/`.pka` binaries, however small.
* Code copied from a source whose licence is incompatible with the GPL.

The work is interoperability only: reading and writing files with a locally
licensed Packet Tracer. No DRM or licence protection is bypassed, and there is no
encryption password to find.

## Reporting something broken

A report that can be acted on has:

* the Packet Tracer version that wrote the file (`Help > About`),
* the output of `pkt info yourfile.pkt`,
* your Python version and the package version (`pip show packet-tracer-pkt-format`),
* the smallest file that shows the problem,
* what you expected, and what happened instead.

If the file cannot be shared, describe it: which PT version wrote it, roughly how
many devices, and whether it is a lab or an activity. That is often enough to
reproduce.

For a security problem, please use the contact on the maintainer's GitHub profile
rather than a public issue.
