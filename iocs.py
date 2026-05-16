"""
IOC detection, refanging, and filtering.

Pulls IPs, domains, URLs, and MD5/SHA1/SHA256 hashes out of arbitrary CSV cells.
Refangs common defanging patterns first (so `1.1.1[.]1` becomes `1.1.1.1` before
the IPv4 regex sees it). Filters out noise: private/loopback/link-local IPs,
allowlisted enterprise domains, and "domains" that are obviously filenames
(web.config, system32.exe).
"""

from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass, field
from typing import Iterable


# --------------------------------------------------------------------------- #
# Refang
# --------------------------------------------------------------------------- #

_REFANG_SUBS: tuple[tuple[re.Pattern[str], str], ...] = (
    (re.compile(r"\[\.\]|\(\.\)|\{\.\}"), "."),
    (re.compile(r"\[:\]|\(:\)"), ":"),
    (re.compile(r"\[/\]"), "/"),
    (re.compile(r"\bhxxps\b", re.IGNORECASE), "https"),
    (re.compile(r"\bhxxp\b", re.IGNORECASE), "http"),
    (re.compile(r"\bfxp\b", re.IGNORECASE), "ftp"),
    (re.compile(r"\[at\]|\(at\)", re.IGNORECASE), "@"),
)


def refang(text: str) -> str:
    for pat, repl in _REFANG_SUBS:
        text = pat.sub(repl, text)
    return text


# --------------------------------------------------------------------------- #
# Regexes
# --------------------------------------------------------------------------- #

# Order matters at use-site: SHA256 before SHA1 before MD5 (length-priority);
# URL before domain (URLs are extracted, then domains scanned in the remainder).

RE_SHA256 = re.compile(r"\b[A-Fa-f0-9]{64}\b")
RE_SHA1 = re.compile(r"\b[A-Fa-f0-9]{40}\b")
RE_MD5 = re.compile(r"\b[A-Fa-f0-9]{32}\b")

RE_IPV4 = re.compile(
    r"\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\b"
)

# URLs: http/https/ftp. Stops at whitespace, quotes, angle brackets, and CSV-ish punctuation.
RE_URL = re.compile(
    r"\b(?:https?|ftp)://[^\s\"'<>,;)]+",
    re.IGNORECASE,
)

# Domain: at least one label + dot + 2+ alpha TLD. Conservative; pairs with TLD-suffix filter.
RE_DOMAIN = re.compile(
    r"\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,63}\b"
)


# --------------------------------------------------------------------------- #
# Filter lists
# --------------------------------------------------------------------------- #

# Suffix-matched against the right-most labels. A user-supplied list (via
# --skip-domains-file) is unioned with this at runtime.
BUILTIN_SKIP_DOMAINS: frozenset[str] = frozenset(
    {
        "microsoft.com",
        "windows.com",
        "windowsupdate.com",
        "office.com",
        "office365.com",
        "live.com",
        "msn.com",
        "bing.com",
        "azure.com",
        "azureedge.net",
        "azurewebsites.net",
        "windows.net",
        "msftncsi.com",
        "msftconnecttest.com",
        "google.com",
        "googleapis.com",
        "gstatic.com",
        "googleusercontent.com",
        "youtube.com",
        "ytimg.com",
        "apple.com",
        "icloud.com",
        "mzstatic.com",
        "cloudflare.com",
        "cloudflare.net",
        "amazon.com",
        "amazonaws.com",
        "akamai.net",
        "akamaiedge.net",
        "akamaihd.net",
        "digicert.com",
        "verisign.com",
        "mozilla.com",
        "mozilla.org",
        "github.com",
        "githubusercontent.com",
    }
)

# Right-most "TLD" labels that are obviously filenames or fragments — domain
# regex will happily match `web.config`, `system32.exe`, `notes.txt` otherwise.
JUNK_TLDS: frozenset[str] = frozenset(
    {
        "exe", "dll", "bat", "cmd", "sys", "ps1", "psm1", "vbs", "js",
        "py", "pyc", "rb", "pl", "sh", "lua",
        "txt", "log", "tmp", "temp", "bak", "old",
        "config", "conf", "cfg", "ini", "env", "lock", "md", "rst",
        "zip", "tar", "gz", "7z", "rar", "iso", "img",
        "json", "xml", "csv", "yaml", "yml", "toml",
        "png", "jpg", "jpeg", "gif", "ico", "bmp", "svg", "webp",
        "pdf", "doc", "docx", "xls", "xlsx", "ppt", "pptx",
        "dat", "db", "sqlite", "bin", "msi", "pkg", "deb", "rpm",
        "html", "htm", "css",
    }
)


# --------------------------------------------------------------------------- #
# IOC dataclass
# --------------------------------------------------------------------------- #


@dataclass(frozen=True)
class IOC:
    value: str          # canonical (refanged, lowercased for domain/hash)
    type: str           # "ip" | "domain" | "url" | "md5" | "sha1" | "sha256"
    rows: tuple[int, ...]  # row indices where this IOC appeared (0-based, header excluded)


@dataclass
class DetectionStats:
    raw_matches: int = 0
    skipped_private_ip: int = 0
    skipped_domain_allowlist: int = 0
    skipped_junk_tld: int = 0
    deduped: int = 0  # final unique count
    by_type: dict[str, int] = field(default_factory=dict)


# --------------------------------------------------------------------------- #
# Filter helpers
# --------------------------------------------------------------------------- #


def _is_skippable_ip(value: str) -> bool:
    try:
        ip = ipaddress.ip_address(value)
    except ValueError:
        return True  # not a valid IP at all
    return (
        ip.is_private
        or ip.is_loopback
        or ip.is_link_local
        or ip.is_multicast
        or ip.is_reserved
        or ip.is_unspecified
    )


def _domain_is_allowlisted(domain: str, extra: frozenset[str]) -> bool:
    domain = domain.lower().rstrip(".")
    skip = BUILTIN_SKIP_DOMAINS | extra
    # Suffix match: foo.microsoft.com matches "microsoft.com".
    for suffix in skip:
        if domain == suffix or domain.endswith("." + suffix):
            return True
    return False


def _looks_like_filename(domain: str) -> bool:
    tld = domain.rsplit(".", 1)[-1].lower()
    return tld in JUNK_TLDS


# --------------------------------------------------------------------------- #
# Per-cell extraction
# --------------------------------------------------------------------------- #


def _extract_from_text(
    text: str,
    want_types: set[str],
) -> list[tuple[str, str]]:
    """Return list of (type, raw_value) tuples from a single refanged cell.

    `want_types` controls which IOC types to scan for; used by column constraints.
    """
    out: list[tuple[str, str]] = []
    work = text

    # Hashes: longest first so a SHA256 isn't double-counted as MD5/SHA1.
    if "sha256" in want_types:
        for m in RE_SHA256.findall(work):
            out.append(("sha256", m))
        work = RE_SHA256.sub(" ", work)
    if "sha1" in want_types:
        for m in RE_SHA1.findall(work):
            out.append(("sha1", m))
        work = RE_SHA1.sub(" ", work)
    if "md5" in want_types:
        for m in RE_MD5.findall(work):
            out.append(("md5", m))
        work = RE_MD5.sub(" ", work)

    if "url" in want_types:
        for m in RE_URL.findall(work):
            out.append(("url", m))
        work = RE_URL.sub(" ", work)

    if "ip" in want_types:
        for m in RE_IPV4.findall(work):
            out.append(("ip", m))
        # Don't remove IPs from `work` — domain regex won't match bare IPs anyway
        # because it requires a non-numeric TLD.

    if "domain" in want_types:
        for m in RE_DOMAIN.findall(work):
            out.append(("domain", m))

    return out


# --------------------------------------------------------------------------- #
# Canonicalization + post-filter
# --------------------------------------------------------------------------- #


def _canonicalize(ioc_type: str, value: str) -> str:
    if ioc_type in ("domain", "md5", "sha1", "sha256"):
        return value.lower().strip(".")
    if ioc_type == "url":
        # Strip trailing punctuation that often clings to URLs in CSVs.
        return value.rstrip(".,;)]'\"").rstrip("/")
    return value


# --------------------------------------------------------------------------- #
# Public entrypoint
# --------------------------------------------------------------------------- #


ALL_TYPES: tuple[str, ...] = ("ip", "domain", "url", "md5", "sha1", "sha256")


def detect_iocs(
    rows: list[dict[str, str]],
    column_constraints: dict[str, str | None] | None = None,
    extra_skip_domains: Iterable[str] = (),
) -> tuple[list[IOC], DetectionStats]:
    """Walk every cell of every row, extract IOCs, refang, filter, dedupe.

    `column_constraints` keys are user-facing groups ("ip", "domain", "url",
    "hash") because the CLI exposes a single --hash-col (covers md5/sha1/sha256).
    Value is the column name to restrict to, or None to scan every column.
    """
    constraints = column_constraints or {}
    extra_skip = frozenset(d.lower().strip(".") for d in extra_skip_domains if d.strip())
    stats = DetectionStats()

    # Map (type, value) -> ordered set of row indices.
    seen: dict[tuple[str, str], list[int]] = {}

    for row_idx, row in enumerate(rows):
        for col_name, cell in row.items():
            if not cell:
                continue
            want = _types_for_cell(col_name, constraints)
            if not want:
                continue
            refanged = refang(str(cell))
            matches = _extract_from_text(refanged, want)
            for ioc_type, raw_value in matches:
                stats.raw_matches += 1
                value = _canonicalize(ioc_type, raw_value)

                if ioc_type == "ip" and _is_skippable_ip(value):
                    stats.skipped_private_ip += 1
                    continue
                if ioc_type == "domain":
                    if _looks_like_filename(value):
                        stats.skipped_junk_tld += 1
                        continue
                    if _domain_is_allowlisted(value, extra_skip):
                        stats.skipped_domain_allowlist += 1
                        continue

                key = (ioc_type, value)
                seen.setdefault(key, []).append(row_idx)

    iocs: list[IOC] = []
    for (ioc_type, value), row_indices in seen.items():
        iocs.append(IOC(value=value, type=ioc_type, rows=tuple(row_indices)))
        stats.by_type[ioc_type] = stats.by_type.get(ioc_type, 0) + 1
    stats.deduped = len(iocs)

    return iocs, stats


def _types_for_cell(col_name: str, constraints: dict[str, str | None]) -> set[str]:
    """Decide which IOC types to scan for in this cell, given column constraints.

    Constraint keys: "ip", "domain", "url", "hash" (where "hash" = md5+sha1+sha256).
    If a constraint is set and this column is not the named one, that type is
    excluded for this cell. Types with no constraint are always scanned.
    """
    want = set(ALL_TYPES)
    type_groups = {
        "ip": {"ip"},
        "domain": {"domain"},
        "url": {"url"},
        "hash": {"md5", "sha1", "sha256"},
    }
    for group, target_col in constraints.items():
        if target_col is None:
            continue
        if col_name != target_col:
            want -= type_groups[group]
    return want
