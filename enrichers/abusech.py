"""abuse.ch suite: Malware Bazaar, URLhaus, ThreatFox.

These three services share an Auth-Key (single account on auth.abuse.ch) but use
different endpoints, request shapes, and response schemas. They live in one
module because they share auth and are commonly used together.
"""

from __future__ import annotations

import json
from urllib.parse import urlparse

from .base import BaseEnricher, EnrichmentResult, _NotFound


# --------------------------------------------------------------------------- #
# Malware Bazaar — hashes only
# --------------------------------------------------------------------------- #


class MalwareBazaar(BaseEnricher):
    name = "mb"
    supports = {"md5", "sha1", "sha256"}
    requires_key = True
    default_rpm = 60

    _URL = "https://mb-api.abuse.ch/api/v1/"

    def query(self, ioc: str, ioc_type: str) -> EnrichmentResult:
        if ioc_type not in self.supports:
            return EnrichmentResult(self.name, ioc, ioc_type, status="skipped",
                                    error=f"unsupported type {ioc_type}")

        resp = self._request(
            "POST", self._URL,
            data={"query": "get_info", "hash": ioc},
            headers={"Auth-Key": self.api_key or ""},
        )
        resp.raise_for_status()
        payload = resp.json()
        status = payload.get("query_status")
        if status in ("hash_not_found", "no_results"):
            raise _NotFound
        if status != "ok":
            return EnrichmentResult(self.name, ioc, ioc_type, status="error",
                                    raw=payload, error=f"MB status: {status}")

        entries = payload.get("data") or []
        first = entries[0] if entries else {}
        tags = first.get("tags") or []
        summary = {
            "mb_signature": first.get("signature", "") or "",
            "mb_file_type": first.get("file_type", "") or "",
            "mb_tags":      ",".join(t for t in tags if t),
            "mb_first_seen": first.get("first_seen", "") or "",
            "mb_link":      f"https://bazaar.abuse.ch/sample/{first.get('sha256_hash', ioc)}/",
        }
        return EnrichmentResult(self.name, ioc, ioc_type, status="ok",
                                raw=payload, summary=summary)


# --------------------------------------------------------------------------- #
# URLhaus — URLs and domains (via host lookup)
# --------------------------------------------------------------------------- #


class URLhaus(BaseEnricher):
    name = "urlhaus"
    supports = {"url", "domain"}
    requires_key = True
    default_rpm = 60

    _URL_ENDPOINT = "https://urlhaus-api.abuse.ch/v1/url/"
    _HOST_ENDPOINT = "https://urlhaus-api.abuse.ch/v1/host/"

    def query(self, ioc: str, ioc_type: str) -> EnrichmentResult:
        headers = {"Auth-Key": self.api_key or ""}

        if ioc_type == "url":
            resp = self._request("POST", self._URL_ENDPOINT,
                                 data={"url": ioc}, headers=headers)
            resp.raise_for_status()
            payload = resp.json()
            status = payload.get("query_status")
            if status in ("no_results", "ok"):
                pass
            else:
                return EnrichmentResult(self.name, ioc, ioc_type, status="error",
                                        raw=payload, error=f"URLhaus status: {status}")

            # If URL not found, fall back to host lookup so we still catch domain hits.
            if status == "no_results":
                host = _host_from_url(ioc)
                if not host:
                    raise _NotFound
                return self._query_host(host, ioc, ioc_type)

            return _urlhaus_url_result(self.name, ioc, ioc_type, payload)

        if ioc_type == "domain":
            return self._query_host(ioc, ioc, ioc_type)

        return EnrichmentResult(self.name, ioc, ioc_type, status="skipped",
                                error=f"unsupported type {ioc_type}")

    def _query_host(self, host: str, ioc: str, ioc_type: str) -> EnrichmentResult:
        resp = self._request("POST", self._HOST_ENDPOINT,
                             data={"host": host},
                             headers={"Auth-Key": self.api_key or ""})
        resp.raise_for_status()
        payload = resp.json()
        status = payload.get("query_status")
        if status == "no_results":
            raise _NotFound
        if status != "ok":
            return EnrichmentResult(self.name, ioc, ioc_type, status="error",
                                    raw=payload, error=f"URLhaus host status: {status}")

        url_count = payload.get("url_count", 0) or 0
        blacklists = payload.get("blacklists") or {}
        summary = {
            "urlhaus_threat":     payload.get("firstseen", "") and "malware_download",
            "urlhaus_url_count":  url_count,
            "urlhaus_blacklists": ",".join(f"{k}:{v}" for k, v in blacklists.items() if v),
            "urlhaus_link":       f"https://urlhaus.abuse.ch/host/{host}/",
        }
        return EnrichmentResult(self.name, ioc, ioc_type, status="ok",
                                raw=payload, summary=summary)


def _urlhaus_url_result(source: str, ioc: str, ioc_type: str, payload: dict) -> EnrichmentResult:
    tags = payload.get("tags") or []
    summary = {
        "urlhaus_threat":     payload.get("threat", ""),
        "urlhaus_status":     payload.get("url_status", ""),
        "urlhaus_tags":       ",".join(t for t in tags if t),
        "urlhaus_link":       payload.get("urlhaus_reference",
                                          f"https://urlhaus.abuse.ch/url/{payload.get('id', '')}/"),
    }
    return EnrichmentResult(source, ioc, ioc_type, status="ok",
                            raw=payload, summary=summary)


def _host_from_url(url: str) -> str:
    try:
        return urlparse(url).hostname or ""
    except ValueError:
        return ""


# --------------------------------------------------------------------------- #
# ThreatFox — all IOC types
# --------------------------------------------------------------------------- #


class ThreatFox(BaseEnricher):
    name = "threatfox"
    supports = {"ip", "domain", "url", "md5", "sha1", "sha256"}
    requires_key = True
    default_rpm = 60

    _URL = "https://threatfox-api.abuse.ch/api/v1/"

    def query(self, ioc: str, ioc_type: str) -> EnrichmentResult:
        body = {"query": "search_ioc", "search_term": ioc}
        resp = self._request(
            "POST", self._URL,
            data=json.dumps(body),
            headers={"Auth-Key": self.api_key or "", "Content-Type": "application/json"},
        )
        resp.raise_for_status()
        payload = resp.json()
        status = payload.get("query_status")
        if status in ("no_result", "no_results", "illegal_search_term"):
            raise _NotFound
        if status != "ok":
            return EnrichmentResult(self.name, ioc, ioc_type, status="error",
                                    raw=payload, error=f"ThreatFox status: {status}")

        entries = payload.get("data") or []
        first = entries[0] if entries else {}
        confidence = first.get("confidence_level", "")
        summary = {
            "threatfox_threat":     first.get("threat_type", ""),
            "threatfox_malware":    first.get("malware_printable") or first.get("malware", ""),
            "threatfox_confidence": confidence,
            "threatfox_hits":       len(entries),
            "threatfox_link":       f"https://threatfox.abuse.ch/ioc/{first.get('id', '')}/"
                                    if first.get("id") else "https://threatfox.abuse.ch/",
        }
        return EnrichmentResult(self.name, ioc, ioc_type, status="ok",
                                raw=payload, summary=summary)
