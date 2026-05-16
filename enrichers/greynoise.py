"""GreyNoise community API (IPv4 only)."""

from __future__ import annotations

from .base import BaseEnricher, EnrichmentResult, _NotFound


class GreyNoise(BaseEnricher):
    name = "greynoise"
    supports = {"ip"}
    requires_key = False  # community endpoint works without a key (lower rate limit)
    default_rpm = 30

    _URL = "https://api.greynoise.io/v3/community"

    def query(self, ioc: str, ioc_type: str) -> EnrichmentResult:
        if ioc_type != "ip":
            return EnrichmentResult(self.name, ioc, ioc_type, status="skipped",
                                    error=f"unsupported type {ioc_type}")

        headers = {"Accept": "application/json"}
        if self.api_key:
            headers["key"] = self.api_key

        resp = self._request("GET", f"{self._URL}/{ioc}", headers=headers)
        if resp.status_code == 404:
            raise _NotFound
        resp.raise_for_status()
        payload = resp.json()
        # Community endpoint returns {"message": "IP not observed scanning the internet..."}
        # on no-data instead of a 404 — treat that as not_found.
        if payload.get("noise") is None and payload.get("classification") is None:
            raise _NotFound
        summary = {
            "gn_classification": payload.get("classification", ""),
            "gn_name":           payload.get("name", ""),
            "gn_last_seen":      payload.get("last_seen", ""),
            "gn_link":           payload.get("link") or f"https://viz.greynoise.io/ip/{ioc}",
        }
        return EnrichmentResult(self.name, ioc, ioc_type, status="ok",
                                raw=payload, summary=summary)
