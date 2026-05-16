"""
Base class for enrichers.

Each per-source enricher subclasses BaseEnricher and implements `query(ioc, type)`.
The base provides `_request` which handles rate limiting, timeouts, retries with
exponential backoff (429/5xx/network), and auth-failure auto-disable. Any
exception escaping `query()` is caught at the worker level and converted to an
error result — see rich_iocs.py::_run_source.
"""

from __future__ import annotations

import logging
import random
import threading
import time
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Any

import requests

from ratelimit import TokenBucket


logger = logging.getLogger(__name__)


@dataclass
class EnrichmentResult:
    source: str
    ioc: str
    ioc_type: str
    status: str                       # "ok" | "not_found" | "skipped" | "error"
    raw: dict | None = None           # full API JSON (None on error/not_found/skipped)
    summary: dict[str, Any] = field(default_factory=dict)  # flat key/value for CSV cols
    error: str | None = None


class AuthFailure(Exception):
    """Raised inside _request on 401/403 so the enricher disables itself."""


class _NotFound(Exception):
    pass


class BaseEnricher(ABC):
    name: str = ""
    supports: set[str] = set()
    requires_key: bool = False
    default_rpm: int = 60

    def __init__(
        self,
        api_key: str | None,
        rpm: int,
        session: requests.Session,
        limiter: TokenBucket,
        timeout: float = 20.0,
    ):
        self.api_key = api_key
        self.rpm = rpm
        self.session = session
        self.limiter = limiter
        self.timeout = timeout
        self._disabled: bool = False
        self._disabled_reason: str = ""
        self._lock = threading.Lock()

    # ----- public ----- #

    def is_disabled(self) -> bool:
        return self._disabled

    def disabled_reason(self) -> str:
        return self._disabled_reason

    def query_safe(self, ioc: str, ioc_type: str) -> EnrichmentResult:
        """Outer wrapper: never raises. Catches everything `query()` lets escape."""
        if self._disabled:
            return EnrichmentResult(
                source=self.name, ioc=ioc, ioc_type=ioc_type,
                status="skipped", error=f"source disabled: {self._disabled_reason}",
            )
        try:
            return self.query(ioc, ioc_type)
        except AuthFailure as e:
            self._disable(str(e))
            return EnrichmentResult(
                source=self.name, ioc=ioc, ioc_type=ioc_type,
                status="error", error=str(e),
            )
        except _NotFound:
            return EnrichmentResult(
                source=self.name, ioc=ioc, ioc_type=ioc_type, status="not_found",
            )
        except Exception as e:  # noqa: BLE001 — guarantee no crash escapes
            logger.debug("%s query failed for %s: %r", self.name, ioc, e, exc_info=True)
            return EnrichmentResult(
                source=self.name, ioc=ioc, ioc_type=ioc_type,
                status="error", error=f"{type(e).__name__}: {e}",
            )

    @abstractmethod
    def query(self, ioc: str, ioc_type: str) -> EnrichmentResult:
        """Subclasses implement. May raise; query_safe will catch."""

    # ----- helpers for subclasses ----- #

    def _request(
        self,
        method: str,
        url: str,
        *,
        params: dict | None = None,
        data: dict | None = None,
        json_body: dict | None = None,
        headers: dict | None = None,
        max_retries: int = 3,
    ) -> requests.Response:
        """Rate-limited HTTP with retry/backoff. Raises AuthFailure on 401/403."""
        last_exc: Exception | None = None
        for attempt in range(max_retries + 1):
            self.limiter.acquire()
            try:
                resp = self.session.request(
                    method, url,
                    params=params, data=data, json=json_body, headers=headers,
                    timeout=(10, self.timeout),
                )
            except (requests.Timeout, requests.ConnectionError) as e:
                last_exc = e
                if attempt < max_retries:
                    _sleep_backoff(attempt, base=1.0)
                    continue
                raise

            if resp.status_code in (401, 403):
                raise AuthFailure(
                    f"{self.name} auth failed (HTTP {resp.status_code}); disabling source"
                )
            if resp.status_code == 429:
                if attempt < max_retries:
                    retry_after = _parse_retry_after(resp.headers.get("Retry-After"))
                    if retry_after is not None:
                        # Cap so a misbehaving server can't pause us for hours.
                        capped = min(retry_after, 60.0)
                        if capped < retry_after:
                            logger.warning(
                                "%s: server asked us to wait %.0fs; capping at %.0fs",
                                self.name, retry_after, capped,
                            )
                        time.sleep(capped)
                    else:
                        _sleep_backoff(attempt, base=2.0)
                    continue
                resp.raise_for_status()
            if 500 <= resp.status_code < 600:
                if attempt < max_retries:
                    _sleep_backoff(attempt, base=1.0)
                    continue
                resp.raise_for_status()

            return resp

        # All retries exhausted via continue branch without returning.
        if last_exc:
            raise last_exc
        raise RuntimeError(f"{self.name}: exhausted retries with no response")

    def _disable(self, reason: str) -> None:
        with self._lock:
            if not self._disabled:
                self._disabled = True
                self._disabled_reason = reason
                logger.warning("%s", reason)


def _sleep_backoff(attempt: int, base: float) -> None:
    # Exponential backoff with mild jitter. attempt is 0-indexed.
    delay = base * (2 ** attempt) + random.uniform(0, 0.5)
    time.sleep(delay)


def _parse_retry_after(value: str | None) -> float | None:
    if not value:
        return None
    try:
        return float(value)
    except ValueError:
        return None
