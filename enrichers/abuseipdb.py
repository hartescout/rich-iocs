"""AbuseIPDB enricher (IPv4 only)."""

from __future__ import annotations

from .base import BaseEnricher, EnrichmentResult, _NotFound


class AbuseIPDB(BaseEnricher):
    name = "abuseipdb"
    supports = {"ip"}
    requires_key = True
    default_rpm = 45

    _URL = "https://api.abuseipdb.com/api/v2/check"

    def __init__(self, *args, max_age_days: int = 90, **kwargs):
        super().__init__(*args, **kwargs)
        self.max_age_days = max_age_days

    def query(self, ioc: str, ioc_type: str) -> EnrichmentResult:
        if ioc_type != "ip":
            return EnrichmentResult(self.name, ioc, ioc_type, status="skipped",
                                    error=f"unsupported type {ioc_type}")
        resp = self._request(
            "GET", self._URL,
            params={"ipAddress": ioc, "maxAgeInDays": self.max_age_days, "verbose": ""},
            headers={"Key": self.api_key or "", "Accept": "application/json"},
        )
        if resp.status_code == 404:
            raise _NotFound
        resp.raise_for_status()
        payload = resp.json()
        data = payload.get("data") or {}
        summary = {
            "abuseipdb_score":   data.get("abuseConfidenceScore", 0),
            "abuseipdb_reports": data.get("totalReports", 0),
            "abuseipdb_country": data.get("countryCode", ""),
            "abuseipdb_isp":     data.get("isp", ""),
            "abuseipdb_link":    f"https://www.abuseipdb.com/check/{ioc}",
        }
        return EnrichmentResult(self.name, ioc, ioc_type, status="ok",
                                raw=payload, summary=summary)
