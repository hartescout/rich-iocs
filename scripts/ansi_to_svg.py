#!/usr/bin/env python3
"""
Convert captured ANSI-colored terminal output into an SVG "screenshot".

Used to generate the screenshots in docs/ for the README. Reads ANSI text from
stdin (or a file), produces an SVG with a dark terminal background, monospace
font, and per-run foreground colors.

Usage:
    python rich_iocs.py --color always --input test_iocs.csv --dry-run 2>&1 \
        | python scripts/ansi_to_svg.py --out docs/dry-run.svg --title "rich_iocs --dry-run"

Supports:
- SGR foreground colors (30-37, 90-97) and reset (0)
- Bold (1) and dim (2)
- 256-color sequences (38;5;N) — basic palette mapping
- Strips other CSI sequences silently

Limitations:
- Single foreground/background per run; no underline/italic rendering
- Hard-coded width; long lines will overflow if they exceed `--cols`
"""

from __future__ import annotations

import argparse
import re
import sys
import unicodedata
from dataclasses import dataclass
from pathlib import Path
from xml.sax.saxutils import escape


# --------------------------------------------------------------------------- #
# Catppuccin-Mocha-inspired palette (looks great on GitHub light + dark)
# --------------------------------------------------------------------------- #

BG = "#1e1e2e"
FG = "#cdd6f4"
DIM_FG = "#7f849c"
WINDOW_BG = "#181825"
TITLE_FG = "#bac2de"
HEADER_BG = "#11111b"

PALETTE = {
    # Standard 8
    30: "#45475a",  # black -> surface1
    31: "#f38ba8",  # red
    32: "#a6e3a1",  # green
    33: "#f9e2af",  # yellow
    34: "#89b4fa",  # blue
    35: "#cba6f7",  # magenta / mauve
    36: "#94e2d5",  # cyan / teal
    37: "#bac2de",  # white / subtext1
    # Bright 8
    90: "#585b70",  # bright black -> surface2
    91: "#eba0ac",  # bright red -> maroon
    92: "#94e2d5",  # bright green (tweaked toward teal for contrast)
    93: "#fab387",  # bright yellow -> peach
    94: "#89dceb",  # bright blue -> sky
    95: "#f5c2e7",  # bright magenta -> pink
    96: "#89b4fa",  # bright cyan (re-use blue for visibility)
    97: "#cdd6f4",  # bright white
}


# --------------------------------------------------------------------------- #
# ANSI parsing
# --------------------------------------------------------------------------- #

CSI = re.compile(r"\x1b\[([0-9;?]*)([A-Za-z])")


@dataclass
class Style:
    fg: str = FG
    bold: bool = False
    dim: bool = False

    def clone(self) -> "Style":
        return Style(fg=self.fg, bold=self.bold, dim=self.dim)


def _apply_sgr(style: Style, params: list[int]) -> Style:
    """Update style in-place from one SGR sequence's parameters."""
    if not params:
        params = [0]
    i = 0
    while i < len(params):
        p = params[i]
        if p == 0:
            style.fg = FG
            style.bold = False
            style.dim = False
        elif p == 1:
            style.bold = True
        elif p == 2:
            style.dim = True
        elif p == 22:
            style.bold = False
            style.dim = False
        elif p == 39:
            style.fg = FG
        elif p in PALETTE:
            style.fg = PALETTE[p]
        elif p == 38 and i + 2 < len(params) and params[i + 1] == 5:
            # 256-color foreground: map first 16 to palette, fall back to FG.
            idx = params[i + 2]
            ansi_eq = idx + 30 if idx < 8 else (idx - 8) + 90 if idx < 16 else None
            style.fg = PALETTE.get(ansi_eq, FG) if ansi_eq else FG
            i += 2
        i += 1
    return style


@dataclass
class Span:
    text: str
    style: Style


def parse_ansi(text: str) -> list[list[Span]]:
    """Return list of lines; each line is a list of Span(text, style) runs."""
    lines: list[list[Span]] = []
    current: list[Span] = []
    style = Style()

    def emit_text(s: str) -> None:
        if not s:
            return
        parts = s.split("\n")
        for i, chunk in enumerate(parts):
            if chunk:
                current.append(Span(chunk, style.clone()))
            if i < len(parts) - 1:
                lines.append(list(current))
                current.clear()

    pos = 0
    for m in CSI.finditer(text):
        emit_text(text[pos:m.start()])
        pos = m.end()
        params_str, code = m.group(1), m.group(2)
        if code == "m":
            params = [int(p) if p else 0 for p in params_str.split(";")] if params_str else [0]
            _apply_sgr(style, params)
        # Silently strip other CSI sequences (cursor moves, clears, etc.)

    emit_text(text[pos:])
    if current:
        lines.append(current)
    return lines


# --------------------------------------------------------------------------- #
# Visible-width (matches the heuristic used by rich_iocs banner)
# --------------------------------------------------------------------------- #


def visible_width(text: str) -> int:
    width = 0
    for ch in text:
        cp = ord(ch)
        if cp < 0x80:
            width += 1
        elif cp in (0xFE0F, 0xFE0E, 0x200D):
            continue
        elif (0x1F300 <= cp <= 0x1FAFF
              or 0x2600 <= cp <= 0x27BF
              or 0x1F000 <= cp <= 0x1F2FF):
            width += 2
        else:
            ea = unicodedata.east_asian_width(ch)
            width += 2 if ea in ("W", "F") else 1
    return width


# --------------------------------------------------------------------------- #
# SVG rendering
# --------------------------------------------------------------------------- #


CELL_W = 8.4      # px per column at 14px font
LINE_H = 18       # px per line
PAD_X = 16
PAD_Y_TOP = 44    # title bar height
PAD_Y_BOT = 16
FONT = "ui-monospace, SFMono-Regular, Menlo, Consolas, 'Liberation Mono', monospace"
FONT_SIZE = 14


def render_svg(lines: list[list[Span]], cols: int, title: str) -> str:
    n_lines = len(lines)
    width_px = int(PAD_X * 2 + cols * CELL_W)
    height_px = int(PAD_Y_TOP + n_lines * LINE_H + PAD_Y_BOT)

    out: list[str] = []
    out.append(
        f'<svg xmlns="http://www.w3.org/2000/svg" width="{width_px}" '
        f'height="{height_px}" viewBox="0 0 {width_px} {height_px}" '
        f'font-family="{FONT}" font-size="{FONT_SIZE}">'
    )

    # Window background + rounded corners
    out.append(
        f'<rect x="0" y="0" width="{width_px}" height="{height_px}" '
        f'rx="8" ry="8" fill="{BG}"/>'
    )
    # Title bar
    out.append(
        f'<rect x="0" y="0" width="{width_px}" height="30" '
        f'rx="8" ry="8" fill="{HEADER_BG}"/>'
    )
    out.append(
        f'<rect x="0" y="22" width="{width_px}" height="8" fill="{HEADER_BG}"/>'
    )
    # Three traffic-light buttons
    for i, color in enumerate(("#f38ba8", "#f9e2af", "#a6e3a1")):
        out.append(
            f'<circle cx="{16 + i * 18}" cy="15" r="6" fill="{color}"/>'
        )
    # Title text
    safe_title = escape(title)
    out.append(
        f'<text x="{width_px // 2}" y="20" fill="{TITLE_FG}" text-anchor="middle" '
        f'font-size="12">{safe_title}</text>'
    )

    # Body lines. Important: emit each <text> on one logical line with no
    # whitespace between tags — xml:space="preserve" would otherwise leak
    # whitespace from element boundaries into the rendered output.
    for line_idx, spans in enumerate(lines):
        y = PAD_Y_TOP + line_idx * LINE_H + 4  # +4 baseline tweak
        parts = [f'<text x="{PAD_X}" y="{y}" xml:space="preserve">']
        for span in spans:
            attrs = [f'fill="{span.style.fg}"']
            if span.style.bold:
                attrs.append('font-weight="bold"')
            if span.style.dim:
                attrs.append('opacity="0.65"')
            attrs_str = " ".join(attrs)
            text = escape(span.text).replace("\t", "    ")
            parts.append(f'<tspan {attrs_str}>{text}</tspan>')
        parts.append("</text>")
        out.append("".join(parts))

    out.append("</svg>")
    return "\n".join(out)


# --------------------------------------------------------------------------- #
# CLI
# --------------------------------------------------------------------------- #


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(description="Convert ANSI text to SVG.")
    p.add_argument("--input", "-i", type=Path,
                   help="Input file (default: stdin)")
    p.add_argument("--out", "-o", type=Path, required=True, help="Output SVG path")
    p.add_argument("--title", default="terminal", help="Window title text")
    p.add_argument("--cols", type=int, default=88,
                   help="Terminal width in columns (controls SVG width)")
    args = p.parse_args(argv)

    if args.input:
        text = args.input.read_text(encoding="utf-8")
    else:
        text = sys.stdin.read()

    lines = parse_ansi(text)
    # Trim trailing blank lines so the SVG isn't excessively tall.
    while lines and not any(s.text.strip() for s in lines[-1]):
        lines.pop()

    svg = render_svg(lines, args.cols, args.title)
    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(svg, encoding="utf-8")
    print(f"wrote {args.out} ({len(lines)} lines)", file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main())
