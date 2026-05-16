"""
Regulated-spacing token bucket. One instance per source.

Not a true bursty bucket — we space requests by exactly `60/rpm` seconds. This
maps better to free-tier APIs that enforce per-minute cliffs (e.g. VirusTotal
free = 4/min) than a 60-token bucket would.
"""

from __future__ import annotations

import threading
import time


class TokenBucket:
    def __init__(self, rate_per_min: int):
        self._interval = 60.0 / max(rate_per_min, 1)
        self._lock = threading.Lock()
        self._next_allowed = 0.0  # monotonic timestamp

    def acquire(self) -> None:
        with self._lock:
            now = time.monotonic()
            wait = self._next_allowed - now
            if wait > 0:
                time.sleep(wait)
                now = time.monotonic()
            self._next_allowed = now + self._interval
