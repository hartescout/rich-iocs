"""AlienVault OTX enricher."""

from __future__ import annotations

from urllib.parse import quote

from .base import BaseEnricher, EnrichmentResult, _NotFound


class OTX(BaseEnricher):
    name = "otx"
    supports = {"ip", "domain", "url", "md5", "sha1", "sha256"}
    requires_key = True
    default_rpm = 60

    _BASE = "https://otx.alienvault.com/api/v1/indicators"

    _TYPE_MAP = {
        "ip":     "IPv4",
        "domain": "domain",
        "url":    "url",
        "md5":    "file",
        "sha1":   "file",
        "sha256": "file",
    }

    _GUI_MAP = {
        "ip":     "ip",
        "domain": "domain",
        "url":    "url",
        "md5":    "file",
        "sha1":   "file",
        "sha256": "file",
    }

    def query(self, ioc: str, ioc_type: str) -> EnrichmentResult:
        otx_type = self._TYPE_MAP.get(ioc_type)
        if otx_type is None:
            return EnrichmentResult(self.name, ioc, ioc_type, status="skipped",
                                    error=f"unsupported type {ioc_type}")

        url = f"{self._BASE}/{otx_type}/{quote(ioc, safe='')}/general"
        resp = self._request("GET", url, headers={"X-OTX-API-KEY": self.api_key or ""})
        if resp.status_code == 404:
            raise _NotFound
        resp.raise_for_status()
        payload = resp.json()
        pulse_info = payload.get("pulse_info") or {}
        pulses = pulse_info.get("pulses") or []
        gui_kind = self._GUI_MAP[ioc_type]
        summary = {
            "otx_pulse_count": pulse_info.get("count", len(pulses)),
            "otx_first_pulse": (pulses[0].get("name") if pulses else ""),
            "otx_link":        f"https://otx.alienvault.com/indicator/{gui_kind}/{ioc}",
        }
        return EnrichmentResult(self.name, ioc, ioc_type, status="ok",
                                raw=payload, summary=summary)
