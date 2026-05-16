"""
Configuration loading: .env -> os.environ, plus per-source defaults.
"""

from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path


@dataclass
class SourceConfig:
    name: str
    env_key: str | None        # env var holding the API key (None = no key needed)
    default_rpm: int
    requires_key: bool


# Built-in defaults. Override per source via CLI flags.
SOURCE_CONFIGS: dict[str, SourceConfig] = {
    "vt":        SourceConfig("vt",        "VT_API_KEY",        4,  requires_key=True),
    "abuseipdb": SourceConfig("abuseipdb", "ABUSEIPDB_API_KEY", 45, requires_key=True),
    "otx":       SourceConfig("otx",       "OTX_API_KEY",       60, requires_key=True),
    "greynoise": SourceConfig("greynoise", "GREYNOISE_API_KEY", 30, requires_key=False),
    "mb":        SourceConfig("mb",        "ABUSECH_AUTH_KEY",  60, requires_key=True),
    "urlhaus":   SourceConfig("urlhaus",   "ABUSECH_AUTH_KEY",  60, requires_key=True),
    "threatfox": SourceConfig("threatfox", "ABUSECH_AUTH_KEY",  60, requires_key=True),
}


def load_env(env_file: Path | None) -> None:
    """Load .env into os.environ. Silent no-op if the file is missing."""
    if env_file is None:
        return
    try:
        from dotenv import load_dotenv
    except ImportError:
        # python-dotenv missing: log and continue using whatever's already in env.
        return
    if env_file.exists():
        load_dotenv(env_file, override=False)


def get_key(source: str) -> str | None:
    cfg = SOURCE_CONFIGS.get(source)
    if cfg is None or cfg.env_key is None:
        return None
    val = os.environ.get(cfg.env_key, "").strip()
    return val or None
