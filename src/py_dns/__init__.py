"""
py_dns — Educational DNS security toolkit.

Two sub-systems in one package:

  VULNERABLE side (lab / CTF / teaching)
  ────────────────────────────────────────
  VulnerableServer   — deliberately insecure UDP forwarder with all eight
                       classic DNS vulnerabilities active and annotated.
  VulnerableCache    — no-TTL, no-negative-caching in-memory store
                       (demonstrates VULN-008).

  SECURE side (hardened reference implementation)
  ────────────────────────────────────────────────
  SecureResolver     — public API; wraps the full handler chain.
  SecureDNSCache     — TTL-aware cache with positive + negative entries,
                       LRU eviction, and optional thread safety.
  DoHClient          — DNS over HTTPS via Cloudflare / Google / Quad9.
  DoTClient          — DNS over TLS (RFC 7858) with TLS 1.2+ enforcement.
  TokenBucket        — O(1) token-bucket rate limiter.

Vulnerability catalogue:
  Run `py-dns --list-vulns` or import `py_dns.vulns.VULNERABILITIES`.

Quick start:
    from py_dns.resolver import SecureResolver

    with SecureResolver() as r:
        ip = r.resolve("example.com")
        print(ip)          # "93.184.216.34"
        print(r.stats)     # cache hit-rate, eviction count, …
"""

from py_dns.cache import NegativeEntry, SecureDNSCache, VulnerableCache
from py_dns.resolver import SecureResolver

__all__ = [
    "SecureResolver",
    "SecureDNSCache",
    "VulnerableCache",
    "NegativeEntry",
]
