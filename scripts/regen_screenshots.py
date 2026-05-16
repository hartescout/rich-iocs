#!/usr/bin/env python3
"""Regenerate docs/banner.svg and docs/dry-run.svg.

Run from the repo root:
    python scripts/regen_screenshots.py
"""

from __future__ import annotations

import io
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT))


class _FakeTTY:
    """Wraps a stream to claim isatty() is True so banner+colors stay on."""

    def __init__(self, real):
        self._real = real

    def __getattr__(self, name):
        return getattr(self._real, name)

    def isatty(self) -> bool:
        return True


def _capture_banner() -> str:
    from rich_iocs import _print_banner
    buf = io.StringIO()
    _print_banner(use_color=True, stream=buf)
    return buf.getvalue()


def _capture_dry_run() -> str:
    """Run rich_iocs.main(--dry-run --color always) and capture stderr+stdout."""
    from rich_iocs import main

    real_stdout, real_stderr = sys.stdout, sys.stderr
    buf = io.StringIO()
    sys.stdout = _FakeTTY(buf)
    sys.stderr = _FakeTTY(buf)
    try:
        main([
            "--input", str(REPO_ROOT / "test_iocs.csv"),
            "--dry-run",
            "--color", "always",
        ])
    finally:
        sys.stdout, sys.stderr = real_stdout, real_stderr
    return buf.getvalue()


def main() -> int:
    from scripts.ansi_to_svg import parse_ansi, render_svg  # type: ignore

    docs = REPO_ROOT / "docs"
    docs.mkdir(parents=True, exist_ok=True)

    # Banner
    banner_ansi = _capture_banner()
    banner_lines = parse_ansi(banner_ansi)
    while banner_lines and not any(s.text.strip() for s in banner_lines[-1]):
        banner_lines.pop()
    (docs / "banner.svg").write_text(
        render_svg(banner_lines, cols=72, title="rich_iocs banner"),
        encoding="utf-8",
    )
    print(f"wrote {docs / 'banner.svg'}", file=sys.stderr)

    # Dry run
    dry_ansi = _capture_dry_run()
    dry_lines = parse_ansi(dry_ansi)
    while dry_lines and not any(s.text.strip() for s in dry_lines[-1]):
        dry_lines.pop()
    (docs / "dry-run.svg").write_text(
        render_svg(
            dry_lines, cols=92,
            title="python rich_iocs.py --input test_iocs.csv --dry-run",
        ),
        encoding="utf-8",
    )
    print(f"wrote {docs / 'dry-run.svg'}", file=sys.stderr)

    return 0


if __name__ == "__main__":
    sys.exit(main())
