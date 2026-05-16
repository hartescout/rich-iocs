"""Enricher registry + IOC routing."""

from __future__ import annotations

from .abuseipdb import AbuseIPDB
from .abusech import MalwareBazaar, ThreatFox, URLhaus
from .base import BaseEnricher, EnrichmentResult
from .greynoise import GreyNoise
from .otx import OTX
from .virustotal import VirusTotal


ENRICHERS: dict[str, type[BaseEnricher]] = {
    "vt":        VirusTotal,
    "abuseipdb": AbuseIPDB,
    "otx":       OTX,
    "greynoise": GreyNoise,
    "mb":        MalwareBazaar,
    "urlhaus":   URLhaus,
    "threatfox": ThreatFox,
}


# Which sources handle which IOC types. A source not listed here for a type will
# never be queried for that type, even if --only-sources says so.
IOC_ROUTING: dict[str, list[str]] = {
    "ip":     ["vt", "abuseipdb", "otx", "greynoise", "threatfox"],
    "domain": ["vt", "otx", "urlhaus", "threatfox"],
    "url":    ["vt", "otx", "urlhaus", "threatfox"],
    "md5":    ["vt", "otx", "mb", "threatfox"],
    "sha1":   ["vt", "otx", "mb", "threatfox"],
    "sha256": ["vt", "otx", "mb", "threatfox"],
}


__all__ = ["ENRICHERS", "IOC_ROUTING", "BaseEnricher", "EnrichmentResult"]
