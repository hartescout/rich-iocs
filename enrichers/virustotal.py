"""VirusTotal v3 enricher."""

from __future__ import annotations

import base64
import hashlib

from .base import BaseEnricher, EnrichmentResult, _NotFound


class VirusTotal(BaseEnricher):
    name = "vt"
    supports = {"ip", "domain", "url", "md5", "sha1", "sha256"}
    requires_key = True
    default_rpm = 4

    _BASE = "https://api.virustotal.com/api/v3"

    def query(self, ioc: str, ioc_type: str) -> EnrichmentResult:
        if ioc_type == "ip":
            url, gui_kind, gui_id = f"{self._BASE}/ip_addresses/{ioc}", "ip-address", ioc
        elif ioc_type == "domain":
            url, gui_kind, gui_id = f"{self._BASE}/domains/{ioc}", "domain", ioc
        elif ioc_type == "url":
            # API id = urlsafe-base64(url) without padding; GUI id = sha256(url) hex.
            api_id = base64.urlsafe_b64encode(ioc.encode()).decode().rstrip("=")
            gui_id = hashlib.sha256(ioc.encode()).hexdigest()
            url, gui_kind = f"{self._BASE}/urls/{api_id}", "url"
        elif ioc_type in ("md5", "sha1", "sha256"):
            url, gui_kind, gui_id = f"{self._BASE}/files/{ioc}", "file", ioc
        else:
            return EnrichmentResult(self.name, ioc, ioc_type, status="skipped",
                                    error=f"unsupported type {ioc_type}")

        resp = self._request("GET", url, headers={"x-apikey": self.api_key or ""})
        if resp.status_code == 404:
            raise _NotFound
        resp.raise_for_status()
        payload = resp.json()

        attrs = (payload.get("data") or {}).get("attributes") or {}
        stats = attrs.get("last_analysis_stats") or {}
        summary = {
            "vt_malicious":  stats.get("malicious", 0),
            "vt_suspicious": stats.get("suspicious", 0),
            "vt_harmless":   stats.get("harmless", 0),
            "vt_reputation": attrs.get("reputation", ""),
            "vt_link":       f"https://www.virustotal.com/gui/{gui_kind}/{gui_id}",
        }
        return EnrichmentResult(self.name, ioc, ioc_type, status="ok",
                                raw=payload, summary=summary)
