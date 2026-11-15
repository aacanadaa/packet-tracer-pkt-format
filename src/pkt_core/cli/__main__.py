"""Allow ``python -m pkt_core.cli`` execution."""

from __future__ import annotations

from pkt_core.cli.main import main

if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
