"""
DNS cache with both positive (A/AAAA) and negative (NXDOMAIN) caching.

Negative caching (RFC 2308):
  When a domain doesn't exist, we cache that *absence* so repeated
  lookups for non-existent domains don't hit the wire.  We use a
  shorter TTL for negative entries (default 60s vs 300s positive).

The NegativeEntry sentinel is a separate type so callers can
distinguish "cached miss" from "never queried":

    cache.get("bad.example")  →  NegativeEntry  (cached NXDOMAIN)
    cache.get("new.example")  →  None           (not yet queried)
"""

from __future__ import annotations

import logging
import time
from dataclasses import dataclass
from typing import Any

log = logging.getLogger(__name__)

# Sentinel for NXDOMAIN entries — distinguish from "not in cache"
class NegativeEntry:
    """Marks a cached NXDOMAIN response."""
    __slots__ = ()
NXDOMAIN = NegativeEntry()


@dataclass(slots=True)
class CacheEntry:
    value: Any          # str (IP) or NXDOMAIN
    expiry: float       # monotonic
    inserted_at: float

    @property
    def is_expired(self) -> bool:
        return time.monotonic() > self.expiry

    @property
    def is_negative(self) -> bool:
        return isinstance(self.value, NegativeEntry)


class SecureDNSCache:
    POSITIVE_TTL = 300   # seconds — overridden by actual DNS TTL when known
    NEGATIVE_TTL = 60    # seconds — short so legitimate domains recover quickly

    def __init__(self, max_size: int = 4096) -> None:
        self._store: dict[tuple[str, str], CacheEntry] = {}
        self._max_size = max_size
        self._hits = self._misses = self._evictions = 0
        self._negative_hits = 0

    # ── public ────────────────────────────────────────────────────────

    def get(self, domain: str, record_type: str = "A") -> Any | None:
        """
        Returns:
          str          → cached positive result (IP address)
          NegativeEntry → cached NXDOMAIN
          None         → not in cache (must query upstream)
        """
        key = (domain.lower(), record_type)
        entry = self._store.get(key)

        if entry is None:
            self._misses += 1
            return None

        if entry.is_expired:
            del self._store[key]
            self._misses += 1
            return None

        if entry.is_negative:
            self._negative_hits += 1
        else:
            self._hits += 1

        return entry.value

    def put_positive(
        self,
        domain: str,
        ip: str,
        ttl: int,
        record_type: str = "A",
    ) -> None:
        if ttl <= 0:
            return
        self._store_entry(domain, ip, ttl, record_type)

    def put_negative(self, domain: str, record_type: str = "A") -> None:
        """Cache an NXDOMAIN response."""
        self._store_entry(domain, NXDOMAIN, self.NEGATIVE_TTL, record_type)
        log.debug("NEG-CACHE  %s %s  TTL=%ds", record_type, domain, self.NEGATIVE_TTL)

    @property
    def stats(self) -> dict[str, Any]:
        total = self._hits + self._misses + self._negative_hits
        return {
            "size":          len(self._store),
            "hits":          self._hits,
            "negative_hits": self._negative_hits,
            "misses":        self._misses,
            "hit_rate":      round((self._hits + self._negative_hits) / total, 4) if total else 0.0,
            "evictions":     self._evictions,
        }

    # ── internals ────────────────────────────────────────────────────

    def _store_entry(self, domain: str, value: Any, ttl: int, record_type: str) -> None:
        key = (domain.lower(), record_type)
        now = time.monotonic()
        if len(self._store) >= self._max_size and key not in self._store:
            self._evict()
        self._store[key] = CacheEntry(value=value, expiry=now + ttl, inserted_at=now)

    def _evict(self) -> None:
        expired = [k for k, v in self._store.items() if v.is_expired]
        for k in expired:
            del self._store[k]
            self._evictions += 1
        if len(self._store) >= self._max_size:
            oldest = min(self._store, key=lambda k: self._store[k].inserted_at)
            del self._store[oldest]
            self._evictions += 1


class VulnerableCache:
    """
    Deliberately weak cache for the educational vulnerable mode.

    It has no TTL, no negative caching, and no size limit. Keep this class out
    of the secure resolver path.
    """

    def __init__(self) -> None:
        self._store: dict[tuple[str, int], str] = {}

    def get(self, domain: str, qtype: int = 1) -> str | None:
        return self._store.get((domain.lower(), qtype))

    def put(self, domain: str, qtype: int, value: str) -> None:
        self._store[(domain.lower(), qtype)] = value
