# SPDX-License-Identifier: GPL-3.0-or-later
"""MkDocs hook: point repo-relative links at GitHub.

The documents in ``docs/`` link to source files, the corpus index and so on with
paths like ``../tools/lab_api.py``. Those resolve correctly when read on GitHub,
where the file tree is the site, but a MkDocs site only publishes ``docs/`` and
would emit a broken relative link.

Rather than rewriting the documents — which would break the GitHub rendering that
most readers actually use — rewrite the links at build time, and only when the
target exists in the repository, so genuinely dead links stay visible as warnings.
"""

from __future__ import annotations

import re
from pathlib import Path

REPO = "https://github.com/aacanadaa/packet-tracer-pkt-format"
BRANCH = "main"

# ](../something) — one or more leading "../", no spaces, not an absolute URL.
_PARENT_LINK = re.compile(r"\]\((\.\./[^)\s]+)\)")


def _repo_root(config: object) -> Path:
    return Path(getattr(config, "config_file_path", ".")).resolve().parent


def on_page_markdown(markdown: str, page: object, config: object, files: object) -> str:
    root = _repo_root(config)

    def rewrite(match: re.Match[str]) -> str:
        target = match.group(1)
        relative = target
        while relative.startswith("../"):
            relative = relative[3:]
        path_part, sep, fragment = relative.partition("#")
        clean_path = path_part.rstrip("/")
        fs_target = root / clean_path
        # Only rewrite when the target really exists in the repository; leave
        # broken links alone so they still surface as build warnings.
        if not clean_path or not fs_target.exists():
            return match.group(0)
        kind = "tree" if fs_target.is_dir() else "blob"
        suffix = f"#{fragment}" if sep else ""
        return f"]({REPO}/{kind}/{BRANCH}/{clean_path}{suffix})"

    return _PARENT_LINK.sub(rewrite, markdown)
