"""Output writers: enriched CSV, per-IOC JSON, markdown report."""

from __future__ import annotations

import csv
import datetime as dt
import hashlib
import json
import logging
import re
from dataclasses import asdict
from pathlib import Path
from typing import Iterable

from enrichers import EnrichmentResult
from iocs import IOC


logger = logging.getLogger(__name__)


# --------------------------------------------------------------------------- #
# Column schema for enriched CSV
# --------------------------------------------------------------------------- #
#
# Per-source columns appended after original columns. If a source returns
# nothing for a row's IOCs, the cells stay blank. If a row has multiple IOCs
# routed to the same source, summary values are joined with ";".

ENRICHMENT_COLUMNS: list[str] = [
    "ioc_count", "ioc_types",
    # VirusTotal
    "vt_malicious", "vt_suspicious", "vt_reputation", "vt_link",
    # AbuseIPDB
    "abuseipdb_score", "abuseipdb_reports", "abuseipdb_country", "abuseipdb_isp", "abuseipdb_link",
    # OTX
    "otx_pulse_count", "otx_first_pulse", "otx_link",
    # GreyNoise
    "gn_classification", "gn_name", "gn_last_seen", "gn_link",
    # Malware Bazaar
    "mb_signature", "mb_file_type", "mb_tags", "mb_first_seen", "mb_link",
    # URLhaus
    "urlhaus_threat", "urlhaus_status", "urlhaus_tags", "urlhaus_url_count",
    "urlhaus_blacklists", "urlhaus_link",
    # ThreatFox
    "threatfox_threat", "threatfox_malware", "threatfox_confidence",
    "threatfox_hits", "threatfox_link",
    # Run-level
    "enrichment_errors",
]


# --------------------------------------------------------------------------- #
# Path-safety
# --------------------------------------------------------------------------- #

_UNSAFE_FS = re.compile(r"[^A-Za-z0-9._-]")


def _safe_name(ioc_type: str, value: str) -> str:
    if ioc_type == "url":
        return hashlib.sha256(value.encode()).hexdigest()[:16] + ".json"
    safe = _UNSAFE_FS.sub("_", value)
    return f"{safe}.json"


# --------------------------------------------------------------------------- #
# JSON writer
# --------------------------------------------------------------------------- #


def write_json_files(
    iocs: list[IOC],
    results_by_ioc: dict[tuple[str, str], list[EnrichmentResult]],
    out_dir: Path,
) -> int:
    """Write one JSON file per unique IOC. Returns count written."""
    json_root = out_dir / "json"
    timestamp = dt.datetime.now(dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    written = 0

    for ioc in iocs:
        key = (ioc.type, ioc.value)
        results = results_by_ioc.get(key, [])
        sources: dict[str, dict] = {}
        for r in results:
            entry: dict = {"status": r.status}
            if r.summary:
                entry["summary"] = r.summary
            if r.raw is not None:
                entry["raw"] = r.raw
            if r.error:
                entry["error"] = r.error
            sources[r.source] = entry

        doc = {
            "ioc": ioc.value,
            "type": ioc.type,
            "queried_at": timestamp,
            "sources": sources,
        }
        target_dir = json_root / ioc.type
        target_dir.mkdir(parents=True, exist_ok=True)
        out_path = target_dir / _safe_name(ioc.type, ioc.value)
        out_path.write_text(json.dumps(doc, indent=2, default=str), encoding="utf-8")
        written += 1

    return written


# --------------------------------------------------------------------------- #
# CSV writer
# --------------------------------------------------------------------------- #


def write_enriched_csv(
    rows: list[dict[str, str]],
    fieldnames: list[str],
    iocs: list[IOC],
    results_by_ioc: dict[tuple[str, str], list[EnrichmentResult]],
    out_path: Path,
) -> None:
    """Write CSV preserving original rows + appending enrichment columns."""

    # Map row_idx -> list[IOC]
    iocs_by_row: dict[int, list[IOC]] = {}
    for ioc in iocs:
        for row_idx in ioc.rows:
            iocs_by_row.setdefault(row_idx, []).append(ioc)

    all_fields = list(fieldnames) + [c for c in ENRICHMENT_COLUMNS if c not in fieldnames]

    out_path.parent.mkdir(parents=True, exist_ok=True)
    with out_path.open("w", encoding="utf-8", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=all_fields, quoting=csv.QUOTE_MINIMAL,
                                extrasaction="ignore")
        writer.writeheader()
        for row_idx, row in enumerate(rows):
            row_iocs = iocs_by_row.get(row_idx, [])
            enriched = _build_enrichment_columns(row_iocs, results_by_ioc)
            out_row = {**row, **enriched}
            writer.writerow(out_row)


def _build_enrichment_columns(
    row_iocs: list[IOC],
    results_by_ioc: dict[tuple[str, str], list[EnrichmentResult]],
) -> dict[str, str]:
    cols: dict[str, list[str]] = {c: [] for c in ENRICHMENT_COLUMNS}
    errors: list[str] = []

    cols["ioc_count"].append(str(len(row_iocs)))
    cols["ioc_types"].append(",".join(sorted({i.type for i in row_iocs})))

    for ioc in row_iocs:
        for result in results_by_ioc.get((ioc.type, ioc.value), []):
            if result.status == "error" and result.error:
                errors.append(f"{result.source}: {result.error}")
            if result.status != "ok":
                continue
            for k, v in result.summary.items():
                if k in cols:
                    cols[k].append(_stringify(v))

    if errors:
        cols["enrichment_errors"].append("; ".join(errors))

    return {k: ";".join(_dedupe_keep_order(vs)) for k, vs in cols.items()}


def _stringify(v) -> str:
    if v is None:
        return ""
    if isinstance(v, (list, tuple)):
        return ",".join(str(x) for x in v)
    return str(v)


def _dedupe_keep_order(items: list[str]) -> list[str]:
    seen: set[str] = set()
    out: list[str] = []
    for x in items:
        if x and x not in seen:
            out.append(x)
            seen.add(x)
    return out


# --------------------------------------------------------------------------- #
# Markdown writer
# --------------------------------------------------------------------------- #


def write_markdown_report(
    input_path: Path,
    iocs: list[IOC],
    results_by_ioc: dict[tuple[str, str], list[EnrichmentResult]],
    detection_stats,
    source_stats: dict[str, dict[str, int]],
    disabled_sources: dict[str, str],
    out_path: Path,
) -> None:
    """Render the triage markdown report."""
    timestamp = dt.datetime.now(dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    lines: list[str] = []
    lines.append(f"# IOC Enrichment Report")
    lines.append("")
    lines.append(f"- **Input:** `{input_path}`")
    lines.append(f"- **Generated:** {timestamp}")
    lines.append(f"- **Unique IOCs:** {len(iocs)}")
    by_type = detection_stats.by_type or {}
    if by_type:
        type_str = ", ".join(f"{t}={n}" for t, n in sorted(by_type.items()))
        lines.append(f"- **By type:** {type_str}")
    lines.append(f"- **Filtered (private IP):** {detection_stats.skipped_private_ip}")
    lines.append(f"- **Filtered (allowlisted domain):** {detection_stats.skipped_domain_allowlist}")
    lines.append(f"- **Filtered (junk TLD / filename):** {detection_stats.skipped_junk_tld}")
    lines.append("")

    # Sources
    lines.append("## Sources")
    lines.append("")
    if source_stats:
        lines.append("| Source | Queries | OK | Not Found | Errors | Skipped |")
        lines.append("|---|---:|---:|---:|---:|---:|")
        for src in sorted(source_stats):
            s = source_stats[src]
            lines.append(
                f"| {src} | {s.get('total', 0)} | {s.get('ok', 0)} | "
                f"{s.get('not_found', 0)} | {s.get('error', 0)} | {s.get('skipped', 0)} |"
            )
    if disabled_sources:
        lines.append("")
        lines.append("**Disabled mid-run:**")
        for src, reason in disabled_sources.items():
            lines.append(f"- `{src}` — {reason}")
    lines.append("")

    # Top malicious
    scored = _score_iocs(iocs, results_by_ioc)
    top = [s for s in scored if s["score"] > 0][:25]
    lines.append("## Top Findings")
    lines.append("")
    if not top:
        lines.append("_No malicious hits._")
    else:
        lines.append("| Score | IOC | Type | VT | AbuseIPDB | OTX | GN | URLhaus | ThreatFox |")
        lines.append("|---:|---|---|---:|---:|---:|---|---|---|")
        for entry in top:
            lines.append(
                f"| {entry['score']} | `{entry['ioc']}` | {entry['type']} | "
                f"{entry['vt']} | {entry['abuseipdb']} | {entry['otx']} | "
                f"{entry['gn']} | {entry['urlhaus']} | {entry['threatfox']} |"
            )
    lines.append("")

    # No-hit IOCs
    no_hits = [s for s in scored if s["score"] == 0]
    lines.append(f"## No-hit IOCs ({len(no_hits)})")
    lines.append("")
    if no_hits:
        if len(no_hits) > 25:
            lines.append("<details><summary>Show all</summary>")
            lines.append("")
        for entry in no_hits:
            lines.append(f"- `{entry['ioc']}` ({entry['type']})")
        if len(no_hits) > 25:
            lines.append("")
            lines.append("</details>")
    lines.append("")

    # Errors
    err_lines: list[str] = []
    for ioc in iocs:
        for r in results_by_ioc.get((ioc.type, ioc.value), []):
            if r.status == "error" and r.error:
                err_lines.append(f"- `{r.source}` on `{ioc.value}`: {r.error}")
    if err_lines:
        lines.append(f"## Errors ({len(err_lines)})")
        lines.append("")
        if len(err_lines) > 25:
            lines.append("<details><summary>Show all</summary>")
            lines.append("")
            lines.extend(err_lines)
            lines.append("")
            lines.append("</details>")
        else:
            lines.extend(err_lines)
        lines.append("")

    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text("\n".join(lines), encoding="utf-8")


def _score_iocs(
    iocs: list[IOC],
    results_by_ioc: dict[tuple[str, str], list[EnrichmentResult]],
) -> list[dict]:
    """Composite score = VT malicious + (AbuseIPDB score // 25) + OTX pulse count + GN malicious flag * 5."""
    scored: list[dict] = []
    for ioc in iocs:
        results = results_by_ioc.get((ioc.type, ioc.value), [])
        by_src = {r.source: r for r in results}
        vt_mal = _int(by_src.get("vt"), "vt_malicious")
        ab_score = _int(by_src.get("abuseipdb"), "abuseipdb_score")
        otx_n = _int(by_src.get("otx"), "otx_pulse_count")
        gn = by_src.get("greynoise")
        gn_class = (gn.summary.get("gn_classification", "")
                    if gn and gn.status == "ok" else "")
        tf = by_src.get("threatfox")
        tf_hits = _int(by_src.get("threatfox"), "threatfox_hits")
        urlhaus = by_src.get("urlhaus")
        urlhaus_hit = 1 if (urlhaus and urlhaus.status == "ok"
                            and urlhaus.summary.get("urlhaus_threat")) else 0

        score = vt_mal + (ab_score // 25) + otx_n + tf_hits + urlhaus_hit * 3
        if gn_class == "malicious":
            score += 5

        scored.append({
            "ioc": ioc.value,
            "type": ioc.type,
            "score": score,
            "vt": vt_mal or "-",
            "abuseipdb": ab_score or "-",
            "otx": otx_n or "-",
            "gn": gn_class or "-",
            "urlhaus": (urlhaus.summary.get("urlhaus_threat", "")
                        if urlhaus and urlhaus.status == "ok" else "-") or "-",
            "threatfox": (tf.summary.get("threatfox_malware", "")
                          if tf and tf.status == "ok" else "-") or "-",
        })
    scored.sort(key=lambda x: x["score"], reverse=True)
    return scored


def _int(result: EnrichmentResult | None, key: str) -> int:
    if result is None or result.status != "ok":
        return 0
    try:
        return int(result.summary.get(key, 0) or 0)
    except (ValueError, TypeError):
        return 0
