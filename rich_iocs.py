#!/usr/bin/env python3
"""
rich_iocs — enrich IOCs from hunt result CSVs.

Detects IPs, domains, URLs, and MD5/SHA1/SHA256 hashes in a CSV (auto-detect by
default; CLI flags can pin specific columns), queries threat-intel APIs in
parallel (one worker per source, each with its own rate limiter), and writes
three artifacts: enriched CSV, per-IOC JSON, and a markdown triage report.

See README.md for usage.
"""

from __future__ import annotations

import argparse
import csv
import logging
import os
import sys
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from typing import Any

import requests

from config import SOURCE_CONFIGS, get_key, load_env
from enrichers import ENRICHERS, IOC_ROUTING, BaseEnricher, EnrichmentResult
from iocs import IOC, detect_iocs, DetectionStats
from ratelimit import TokenBucket
from writers import write_enriched_csv, write_json_files, write_markdown_report


# --------------------------------------------------------------------------- #
# Logger (copied style from ../hunt-scraper/sync_detections.py)
# --------------------------------------------------------------------------- #

ANSI = {
    "reset": "\033[0m", "bold": "\033[1m", "dim": "\033[2m",
    "red": "\033[31m", "green": "\033[32m", "yellow": "\033[33m",
    "blue": "\033[34m", "magenta": "\033[35m", "cyan": "\033[36m",
    # bright variants for the banner gradient
    "br_red": "\033[91m", "br_green": "\033[92m", "br_yellow": "\033[93m",
    "br_blue": "\033[94m", "br_magenta": "\033[95m", "br_cyan": "\033[96m",
    "br_white": "\033[97m",
}

LOG_ICONS = {
    logging.DEBUG: "🔎", logging.INFO: "🛡️", logging.WARNING: "⚠️",
    logging.ERROR: "❌", logging.CRITICAL: "🚨",
}
LOG_COLORS = {
    logging.DEBUG: "dim", logging.INFO: "cyan", logging.WARNING: "yellow",
    logging.ERROR: "red", logging.CRITICAL: "red",
}


def _colorize(text: str, style: str, enabled: bool) -> str:
    return f"{ANSI[style]}{text}{ANSI['reset']}" if enabled else text


def _should_use_color(mode: str) -> bool:
    if mode == "always":
        return True
    if mode == "never" or os.environ.get("NO_COLOR"):
        return False
    return sys.stdout.isatty() or sys.stderr.isatty()


class PrettyLogFormatter(logging.Formatter):
    def __init__(self, use_color: bool):
        super().__init__("%(levelname)s %(message)s")
        self.use_color = use_color

    def format(self, record: logging.LogRecord) -> str:
        icon = LOG_ICONS.get(record.levelno, "•")
        level = record.levelname.lower().ljust(7)
        level = _colorize(level, LOG_COLORS.get(record.levelno, "cyan"), self.use_color)
        return f"{icon} {level} {record.getMessage()}"


def _configure_logging(verbose: bool, use_color: bool) -> None:
    handler = logging.StreamHandler()
    handler.setFormatter(PrettyLogFormatter(use_color))
    root = logging.getLogger()
    root.handlers.clear()
    root.addHandler(handler)
    root.setLevel(logging.DEBUG if verbose else logging.INFO)


logger = logging.getLogger(__name__)


# --------------------------------------------------------------------------- #
# Banner
# --------------------------------------------------------------------------- #
#
# Big ASCII title with a per-line gradient + emoji border. Suppressed by
# --no-banner or when stdout is not a tty (e.g. piped to a file).

_BANNER_LINES: tuple[str, ...] = (
    "  ██████╗ ██╗ ██████╗██╗  ██╗    ██╗ ██████╗  ██████╗███████╗ ",
    "  ██╔══██╗██║██╔════╝██║  ██║    ██║██╔═══██╗██╔════╝██╔════╝ ",
    "  ██████╔╝██║██║     ███████║    ██║██║   ██║██║     ███████╗ ",
    "  ██╔══██╗██║██║     ██╔══██║    ██║██║   ██║██║     ╚════██║ ",
    "  ██║  ██║██║╚██████╗██║  ██║    ██║╚██████╔╝╚██████╗███████║ ",
    "  ╚═╝  ╚═╝╚═╝ ╚═════╝╚═╝  ╚═╝    ╚═╝ ╚═════╝ ╚═════╝╚══════╝ ",
)

_BANNER_GRADIENT: tuple[str, ...] = (
    "br_magenta", "br_red", "br_yellow", "br_green", "br_cyan", "br_blue",
)

_BANNER_TAGLINE = "🛡️  threat-intel enrichment for hunt CSVs  🔍🧪🦠⚡"
_BANNER_SUBTAG  = "🌐 VirusTotal · AbuseIPDB · OTX · GreyNoise · abuse.ch suite 🌐"
_BANNER_WIDTH = 66


def _print_banner(use_color: bool, stream=None) -> None:
    if stream is None:
        stream = sys.stderr
    border_top    = "╔" + "═" * _BANNER_WIDTH + "╗"
    border_bot    = "╚" + "═" * _BANNER_WIDTH + "╝"
    border_sep    = "╠" + "═" * _BANNER_WIDTH + "╣"

    def wall(content: str, content_visible_len: int, color: str = "br_cyan") -> str:
        pad = max(_BANNER_WIDTH - content_visible_len, 0)
        return (
            _colorize("║", "br_cyan", use_color)
            + _colorize(content, color, use_color)
            + " " * pad
            + _colorize("║", "br_cyan", use_color)
        )

    print(_colorize(border_top, "br_cyan", use_color), file=stream)
    print(wall(" " * _BANNER_WIDTH, _BANNER_WIDTH), file=stream)

    # Center the ASCII art block: compute the longest line's visible width once,
    # then pad every line with the same left margin so the art stays a block.
    art_width = max(_visible_width(l) for l in _BANNER_LINES)
    left_margin = max((_BANNER_WIDTH - art_width) // 2, 0)
    for line, color in zip(_BANNER_LINES, _BANNER_GRADIENT):
        padded_left = " " * left_margin + line
        print(wall(padded_left, _visible_width(padded_left), color), file=stream)

    print(wall(" " * _BANNER_WIDTH, _BANNER_WIDTH), file=stream)
    print(_colorize(border_sep, "br_cyan", use_color), file=stream)

    # Taglines, centered. Emojis count as 2 cells in most terminals; we use a
    # conservative visible-length estimate so the right border lines up.
    for text, color in ((_BANNER_TAGLINE, "br_yellow"),
                        (_BANNER_SUBTAG, "br_magenta")):
        visible = _visible_width(text)
        left = max((_BANNER_WIDTH - visible) // 2, 0)
        right = max(_BANNER_WIDTH - visible - left, 0)
        body = " " * left + text + " " * right
        # Recompute pad based on the actual visible width we built.
        print(
            _colorize("║", "br_cyan", use_color)
            + " " * left
            + _colorize(text, color, use_color)
            + " " * right
            + _colorize("║", "br_cyan", use_color),
            file=stream,
        )

    print(_colorize(border_bot, "br_cyan", use_color), file=stream)
    print("", file=stream)


def _visible_width(text: str) -> int:
    """Best-effort visible-width count. Emojis ≈ 2 cells, punctuation ≈ 1.

    Not perfect (terminals disagree on emoji widths) but close enough for
    banner alignment.
    """
    width = 0
    for ch in text:
        cp = ord(ch)
        if cp < 0x80:
            width += 1
        elif cp in (0xFE0F, 0xFE0E, 0x200D):  # variation selectors, ZWJ
            continue
        elif (
            0x1F300 <= cp <= 0x1FAFF        # misc symbols & pictographs, emoji
            or 0x2600 <= cp <= 0x27BF       # misc symbols + dingbats
            or 0x1F000 <= cp <= 0x1F2FF     # mahjong / playing cards / enclosed alphanumerics
        ):
            width += 2
        else:
            # Latin-1 supplement, general punctuation, box drawing — 1 cell.
            width += 1
    return width


# --------------------------------------------------------------------------- #
# Arg parsing
# --------------------------------------------------------------------------- #


def _parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    p = argparse.ArgumentParser(
        prog="rich_iocs",
        description="Enrich IOCs from hunt result CSVs using threat-intel APIs.",
    )
    p.add_argument("--input", "-i", required=True, type=Path,
                   help="Input CSV file")
    p.add_argument("--output-dir", "-o", type=Path, default=Path("./out"),
                   help="Output directory (default: ./out)")

    # Column constraints
    p.add_argument("--ip-col", help="Restrict IP detection to this column")
    p.add_argument("--domain-col", help="Restrict domain detection to this column")
    p.add_argument("--url-col", help="Restrict URL detection to this column")
    p.add_argument("--hash-col", help="Restrict hash detection to this column")

    # Source selection
    p.add_argument("--skip-sources", default="",
                   help="Comma-separated source names to skip")
    p.add_argument("--only-sources", default="",
                   help="Comma-separated source names; overrides --skip-sources")

    # Filter lists
    p.add_argument("--skip-domains-file", type=Path,
                   help="File with extra allowlisted domains (one per line)")
    p.add_argument("--skip-ips-file", type=Path,
                   help="File with extra IPs to skip (one per line)")

    # Per-source rpm
    p.add_argument("--vt-rpm", type=int, default=SOURCE_CONFIGS["vt"].default_rpm)
    p.add_argument("--abuseipdb-rpm", type=int, default=SOURCE_CONFIGS["abuseipdb"].default_rpm)
    p.add_argument("--otx-rpm", type=int, default=SOURCE_CONFIGS["otx"].default_rpm)
    p.add_argument("--greynoise-rpm", type=int, default=SOURCE_CONFIGS["greynoise"].default_rpm)
    p.add_argument("--abusech-rpm", type=int, default=SOURCE_CONFIGS["mb"].default_rpm)

    p.add_argument("--abuseipdb-max-age", type=int, default=90,
                   help="AbuseIPDB maxAgeInDays (default 90)")

    # Concurrency + behavior
    p.add_argument("--max-workers", type=int,
                   help="Max concurrent source workers (default = number of enabled sources)")
    p.add_argument("--sequential", action="store_true",
                   help="Disable concurrency (debugging)")
    p.add_argument("--dry-run", action="store_true",
                   help="Detect + filter, no API calls; print summary and exit")
    p.add_argument("--timeout", type=float, default=20.0,
                   help="Per-request read timeout in seconds (default 20)")
    p.add_argument("--env-file", type=Path, default=Path(".env"),
                   help="Path to .env (default ./.env)")

    p.add_argument("--color", choices=("auto", "always", "never"), default="auto")
    p.add_argument("--no-banner", action="store_true",
                   help="Suppress the ASCII banner at startup")
    p.add_argument("--verbose", "-v", action="store_true")

    return p.parse_args(argv)


# --------------------------------------------------------------------------- #
# Source selection
# --------------------------------------------------------------------------- #


def _select_sources(
    only: str, skip: str,
) -> list[str]:
    only_set = {s.strip() for s in only.split(",") if s.strip()}
    skip_set = {s.strip() for s in skip.split(",") if s.strip()}
    if only_set:
        unknown = only_set - set(ENRICHERS)
        if unknown:
            logger.warning("Unknown sources in --only-sources: %s",
                           ",".join(sorted(unknown)))
        return [s for s in ENRICHERS if s in only_set]
    return [s for s in ENRICHERS if s not in skip_set]


def _build_enrichers(
    selected: list[str],
    args: argparse.Namespace,
    session: requests.Session,
) -> dict[str, BaseEnricher]:
    rpm_for = {
        "vt": args.vt_rpm,
        "abuseipdb": args.abuseipdb_rpm,
        "otx": args.otx_rpm,
        "greynoise": args.greynoise_rpm,
        "mb": args.abusech_rpm,
        "urlhaus": args.abusech_rpm,
        "threatfox": args.abusech_rpm,
    }
    out: dict[str, BaseEnricher] = {}
    for name in selected:
        cfg = SOURCE_CONFIGS[name]
        key = get_key(name)
        if cfg.requires_key and not key:
            logger.warning("Skipping %s: missing %s in env", name, cfg.env_key)
            continue
        cls = ENRICHERS[name]
        limiter = TokenBucket(rpm_for[name])
        kwargs: dict[str, Any] = {
            "api_key": key, "rpm": rpm_for[name],
            "session": session, "limiter": limiter,
            "timeout": args.timeout,
        }
        if name == "abuseipdb":
            kwargs["max_age_days"] = args.abuseipdb_max_age
        out[name] = cls(**kwargs)
    return out


# --------------------------------------------------------------------------- #
# Per-source worker
# --------------------------------------------------------------------------- #


def _run_source(
    enricher: BaseEnricher,
    iocs_for_source: list[IOC],
) -> list[EnrichmentResult]:
    """Iterate IOCs for one source. Exceptions are already caught in query_safe."""
    results: list[EnrichmentResult] = []
    for ioc in iocs_for_source:
        results.append(enricher.query_safe(ioc.value, ioc.type))
    return results


# --------------------------------------------------------------------------- #
# CSV input
# --------------------------------------------------------------------------- #


def _read_csv(path: Path) -> tuple[list[dict[str, str]], list[str]]:
    with path.open("r", encoding="utf-8-sig", newline="") as f:
        reader = csv.DictReader(f)
        rows = [{k: (v or "") for k, v in row.items()} for row in reader]
        fieldnames = list(reader.fieldnames or [])
    return rows, fieldnames


def _read_lines(path: Path | None) -> list[str]:
    if path is None or not path.exists():
        return []
    return [ln.strip() for ln in path.read_text(encoding="utf-8").splitlines()
            if ln.strip() and not ln.strip().startswith("#")]


# --------------------------------------------------------------------------- #
# Main
# --------------------------------------------------------------------------- #


def main(argv: list[str] | None = None) -> int:
    args = _parse_args(argv)
    use_color = _should_use_color(args.color)
    _configure_logging(args.verbose, use_color)

    if not args.no_banner and sys.stderr.isatty():
        _print_banner(use_color)

    if not args.input.exists():
        logger.error("Input file not found: %s", args.input)
        return 2

    load_env(args.env_file)

    logger.info("Reading %s", args.input)
    rows, fieldnames = _read_csv(args.input)
    logger.info("Loaded %d rows, %d columns", len(rows), len(fieldnames))

    constraints = {
        "ip": args.ip_col, "domain": args.domain_col,
        "url": args.url_col, "hash": args.hash_col,
    }
    extra_skip = _read_lines(args.skip_domains_file)
    iocs, det_stats = detect_iocs(rows, constraints, extra_skip_domains=extra_skip)
    _log_detection(det_stats)

    if args.dry_run:
        logger.info("Dry-run: skipping API calls. Detected IOCs:")
        for ioc in iocs:
            print(f"  {ioc.type:7s} {ioc.value}  (rows: {','.join(map(str, ioc.rows))})")
        return 0

    selected = _select_sources(args.only_sources, args.skip_sources)
    if not selected:
        logger.error("No sources selected after --only/--skip filtering")
        return 2

    session = requests.Session()
    enrichers = _build_enrichers(selected, args, session)
    if not enrichers:
        logger.error("No enrichers usable (all missing keys?). Aborting.")
        return 2
    logger.info("Sources enabled: %s", ", ".join(sorted(enrichers)))

    # Per-source IOC slate: only IOCs whose type that source supports, AND the
    # source is listed in IOC_ROUTING for that type.
    work: dict[str, list[IOC]] = {}
    for src_name, enricher in enrichers.items():
        work[src_name] = [
            i for i in iocs
            if i.type in enricher.supports and src_name in IOC_ROUTING.get(i.type, [])
        ]
        logger.info("  %s: %d IOC(s)", src_name, len(work[src_name]))

    # Run
    all_results: list[EnrichmentResult] = []
    if args.sequential:
        for src_name, enricher in enrichers.items():
            logger.info("Running %s sequentially...", src_name)
            all_results.extend(_run_source(enricher, work[src_name]))
    else:
        max_workers = args.max_workers or len(enrichers)
        with ThreadPoolExecutor(max_workers=max_workers) as pool:
            futures = {
                pool.submit(_run_source, enrichers[name], work[name]): name
                for name in enrichers
            }
            for fut in futures:
                src = futures[fut]
                try:
                    all_results.extend(fut.result())
                except Exception as e:  # noqa: BLE001 — defense in depth
                    logger.error("Worker %s crashed: %r", src, e)

    # Bucket results
    results_by_ioc: dict[tuple[str, str], list[EnrichmentResult]] = {}
    source_stats: dict[str, dict[str, int]] = {n: {} for n in enrichers}
    for r in all_results:
        results_by_ioc.setdefault((r.ioc_type, r.ioc), []).append(r)
        s = source_stats.setdefault(r.source, {})
        s["total"] = s.get("total", 0) + 1
        s[r.status] = s.get(r.status, 0) + 1

    # Write outputs
    out_dir = args.output_dir
    out_dir.mkdir(parents=True, exist_ok=True)
    json_count = write_json_files(iocs, results_by_ioc, out_dir)
    logger.info("Wrote %d per-IOC JSON files under %s/json/", json_count, out_dir)

    csv_path = out_dir / "enriched.csv"
    write_enriched_csv(rows, fieldnames, iocs, results_by_ioc, csv_path)
    logger.info("Wrote enriched CSV: %s", csv_path)

    disabled = {n: e.disabled_reason() for n, e in enrichers.items() if e.is_disabled()}
    md_path = out_dir / "report.md"
    write_markdown_report(args.input, iocs, results_by_ioc, det_stats,
                          source_stats, disabled, md_path)
    logger.info("Wrote markdown report: %s", md_path)

    # Final summary line
    if disabled:
        logger.warning("Sources disabled mid-run: %s",
                       ", ".join(f"{n} ({r})" for n, r in disabled.items()))
    return 0


def _log_detection(stats: DetectionStats) -> None:
    logger.info("Detected %d unique IOCs (from %d raw matches)",
                stats.deduped, stats.raw_matches)
    if stats.by_type:
        for t, n in sorted(stats.by_type.items()):
            logger.info("  %-7s %d", t, n)
    logger.info("Filtered: %d private IPs, %d allowlisted domains, %d junk TLDs",
                stats.skipped_private_ip, stats.skipped_domain_allowlist,
                stats.skipped_junk_tld)


if __name__ == "__main__":
    sys.exit(main())
