"""
Secure handler chain with encrypted upstreams.

Chain:
    CacheHandler → HostsFileHandler → DoHHandler → DoTHandler

DoH is tried first (HTTP/2, JSON, easiest to inspect).
DoT is the fallback (raw DNS over TLS, slightly lower latency).

Both handlers store the actual TTL from the DNS response in the cache,
rather than a hardcoded 300s default.
"""

from __future__ import annotations

import logging
import os
from typing import cast

from py_dns.cache import NegativeEntry, SecureDNSCache
from py_dns.doh import DoHClient
from py_dns.dot import DoTClient
from py_dns.rate_limiter import RateLimitExceeded, TokenBucket

log = logging.getLogger(__name__)


class DNSHandler:
    def __init__(self) -> None:
        self._next: DNSHandler | None = None

    def set_next(self, h: DNSHandler) -> DNSHandler:
        self._next = h
        return h

    def pass_to_next(self, domain: str, record_type: str = "A") -> str | None:
        return self._next.handle(domain, record_type) if self._next else None

    def handle(self, domain: str, record_type: str = "A") -> str | None:
        raise NotImplementedError


class SecureCacheHandler(DNSHandler):
    """
    Handles positive AND negative cache results.

    A cached NegativeEntry short-circuits the chain immediately —
    no network I/O for known-bad domains.
    """

    def __init__(self, cache: SecureDNSCache, rate_limiter: TokenBucket) -> None:
        super().__init__()
        self._cache   = cache
        self._limiter = rate_limiter

    def handle(self, domain: str, record_type: str = "A") -> str | None:
        try:
            self._limiter.consume_or_raise()
        except RateLimitExceeded:
            log.warning("rate limit exceeded for %s", domain)
            return None

        result = self._cache.get(domain, record_type)

        if isinstance(result, NegativeEntry):
            log.info("NEG-CACHE %-45s → NXDOMAIN", domain)
            return None   # cached miss — don't hit the network

        if result is not None:
            log.info("CACHE     %-45s → %s", domain, result)
            return cast(str, result)

        return self.pass_to_next(domain, record_type)


class HostsFileHandler(DNSHandler):
    """Static overrides from /etc/hosts — same logic as dns-basic."""

    def __init__(self, hosts_path: str | None = None) -> None:
        super().__init__()
        path = hosts_path or ("/etc/hosts" if os.name == "posix" else
                              r"C:\Windows\System32\drivers\etc\hosts")
        self._hosts: dict[str, str] = {}
        try:
            with open(path) as fh:
                for line in fh:
                    line = line.strip()
                    if not line or line.startswith("#"):
                        continue
                    parts = line.split()
                    if len(parts) >= 2:
                        ip, *names = parts
                        for n in names:
                            self._hosts[n.lower()] = ip
        except OSError:
            pass

    def handle(self, domain: str, record_type: str = "A") -> str | None:
        if record_type.upper() != "A":
            return self.pass_to_next(domain, record_type)
        result = self._hosts.get(domain.lower())
        if result:
            log.info("HOSTS     %-45s → %s", domain, result)
            return result
        return self.pass_to_next(domain, record_type)


class DoHHandler(DNSHandler):
    """Primary encrypted upstream: DNS over HTTPS."""

    def __init__(self, client: DoHClient, cache: SecureDNSCache) -> None:
        super().__init__()
        self._doh   = client
        self._cache = cache

    def handle(self, domain: str, record_type: str = "A") -> str | None:
        ip, ttl = self._doh.resolve(domain, record_type)

        if ip is not None:
            self._cache.put_positive(domain, ip, ttl, record_type)
            log.info("DOH       %-45s → %s  (TTL=%ds)", domain, ip, ttl)
            return ip

        # DoH failed — try next handler (DoT)
        result = self.pass_to_next(domain, record_type)

        # If everything failed, cache the negative result
        if result is None:
            self._cache.put_negative(domain, record_type)

        return result


class DoTHandler(DNSHandler):
    """Fallback encrypted upstream: DNS over TLS."""

    def __init__(self, client: DoTClient, cache: SecureDNSCache) -> None:
        super().__init__()
        self._dot   = client
        self._cache = cache

    def handle(self, domain: str, record_type: str = "A") -> str | None:
        ip, ttl = self._dot.resolve(domain, record_type)

        if ip is not None:
            self._cache.put_positive(domain, ip, ttl, record_type)
            log.info("DOT       %-45s → %s  (TTL=%ds)", domain, ip, ttl)
            return ip

        log.warning("ALL upstreams failed for %s", domain)
        return None


def build_secure_chain(
    *,
    rate: float = 100.0,
    burst: float = 200.0,
    hosts_path: str | None = None,
) -> tuple[SecureCacheHandler, SecureDNSCache, DoHClient, DoTClient]:
    """
    Returns (chain_head, cache, doh_client, dot_client).

    Caller is responsible for closing doh_client when done.
    """
    cache   = SecureDNSCache()
    limiter = TokenBucket(rate=rate, capacity=burst)
    doh     = DoHClient()
    dot     = DoTClient()

    cache_h = SecureCacheHandler(cache, limiter)
    hosts_h = HostsFileHandler(hosts_path=hosts_path)
    doh_h   = DoHHandler(doh, cache)
    dot_h   = DoTHandler(dot, cache)

    cache_h.set_next(hosts_h).set_next(doh_h).set_next(dot_h)

    return cache_h, cache, doh, dot
