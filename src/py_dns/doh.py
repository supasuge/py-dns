"""
DNS over HTTPS (DoH) client — RFC 8484 + Cloudflare/Google JSON API.

We use the JSON wire format (application/dns-json) rather than the
binary dns-message format because:
  1. Easier to inspect / debug
  2. Both Cloudflare (1.1.1.1) and Google (8.8.8.8) support it natively
  3. httpx handles TLS, certificate verification, and HTTP/2

Security properties:
  ✓ TLS 1.3 with certificate verification (httpx default)
  ✓ HTTPS — queries are encrypted in transit
  ✓ No UDP — immune to DNS-over-UDP spoofing
  ✓ Supports DNSSEC (AD bit returned in JSON response)
  ✗ Still trusts the upstream resolver (not end-to-end DNSSEC)

To add a custom upstream:
  Instantiate DoHClient(upstream=DoHUpstream("https://your.resolver/dns-query"))
"""

from __future__ import annotations

import logging
from dataclasses import dataclass
from typing import Any

import httpx

log = logging.getLogger(__name__)


@dataclass(frozen=True)
class DoHUpstream:
    url:  str
    name: str


@dataclass(frozen=True)
class DoHAnswer:
    name: str
    type: int
    ttl: int
    data: str


@dataclass(frozen=True)
class DoHResult:
    domain: str
    record_type: str
    upstream: str
    status: int
    answers: tuple[DoHAnswer, ...]
    authenticated_data: bool
    recursion_available: bool
    checking_disabled: bool

    @property
    def min_ttl(self) -> int:
        ttls = [answer.ttl for answer in self.answers if answer.ttl > 0]
        return min(ttls) if ttls else 0


# Well-known public DoH upstreams
CLOUDFLARE = DoHUpstream("https://1.1.1.1/dns-query",         "Cloudflare")
GOOGLE     = DoHUpstream("https://dns.google/resolve",         "Google")
QUAD9      = DoHUpstream("https://dns.quad9.net/dns-query",    "Quad9")


class DoHClient:
    """
    Resolves domains via DNS over HTTPS.

    Tries upstreams in order; returns the first successful response.
    On failure, returns None (caller falls back to DoT or raises).
    """

    def __init__(
        self,
        upstreams: list[DoHUpstream] | None = None,
        timeout: float = 5.0,
    ) -> None:
        self._upstreams = upstreams or [CLOUDFLARE, GOOGLE]
        # verify=True is the httpx default — DO NOT disable this
        self._client = httpx.Client(
            timeout=timeout,
            http2=True,   # Cloudflare + Google both support HTTP/2
            verify=True,  # enforces TLS certificate chain verification
            headers={
                "Accept": "application/dns-json",
                "User-Agent": "dns-secure/0.1 (educational resolver)",
            },
        )

    def resolve(self, domain: str, record_type: str = "A") -> tuple[str | None, int]:
        """
        Returns (ip_address | None, ttl).

        TTL is 0 if the lookup failed (caller should not cache).
        """
        qtype = record_type.upper()
        desired_type = {"A": 1, "AAAA": 28}.get(qtype)

        for upstream in self._upstreams:
            result = self._query(upstream, domain, qtype)
            if result is not None and result.status == 0:
                for answer in result.answers:
                    if desired_type is None or answer.type == desired_type:
                        return answer.data, answer.ttl
            log.debug("DoH upstream %s failed for %s", upstream.name, domain)

        return None, 0

    def lookup(self, domain: str, record_type: str = "A") -> DoHResult | None:
        """Return the first parseable DoH response, including NXDOMAIN details."""
        for upstream in self._upstreams:
            result = self._query(upstream, domain, record_type.upper())
            if result is not None:
                return result
            log.debug("DoH upstream %s failed for %s", upstream.name, domain)
        return None

    def _query(self, upstream: DoHUpstream, domain: str, record_type: str) -> DoHResult | None:
        try:
            resp = self._client.get(
                upstream.url,
                params={"name": domain, "type": record_type},
            )
            resp.raise_for_status()
            return self._parse_json(resp.json(), domain, record_type, upstream.name)
        except httpx.HTTPStatusError as exc:
            log.debug("DoH HTTP %s from %s: %s", exc.response.status_code, upstream.name, exc)
        except httpx.RequestError as exc:
            log.debug("DoH request error from %s: %s", upstream.name, exc)
        except (KeyError, ValueError, TypeError) as exc:
            log.debug("DoH parse error from %s: %s", upstream.name, exc)
        return None

    def _parse_json(
        self,
        data: dict[str, Any],
        domain: str,
        record_type: str,
        upstream: str,
    ) -> DoHResult:
        """
        Cloudflare / Google JSON response structure:
          {
            "Status": 0,          # RCODE (0=NOERROR, 3=NXDOMAIN)
            "AD": true/false,     # DNSSEC authenticated data
            "Answer": [
              { "name": "...", "type": 1, "TTL": 300, "data": "1.2.3.4" }
            ]
          }
        """
        rcode = data.get("Status", -1)
        if rcode == 3:
            log.debug("DoH NXDOMAIN for %s", domain)
        elif rcode != 0:
            log.debug("DoH rcode=%d for %s", rcode, domain)

        if data.get("AD"):
            log.debug("DNSSEC validated for %s", domain)

        answers = tuple(
            DoHAnswer(
                name=str(answer.get("name", "")),
                type=int(answer.get("type", 0)),
                ttl=int(answer.get("TTL", 0)),
                data=str(answer.get("data", "")),
            )
            for answer in data.get("Answer", [])
        )
        return DoHResult(
            domain=domain,
            record_type=record_type,
            upstream=upstream,
            status=int(rcode),
            answers=answers,
            authenticated_data=bool(data.get("AD")),
            recursion_available=bool(data.get("RA")),
            checking_disabled=bool(data.get("CD")),
        )

    def close(self) -> None:
        self._client.close()

    def __enter__(self) -> DoHClient:
        return self

    def __exit__(self, *_: object) -> None:
        self.close()
