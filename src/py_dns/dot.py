"""
DNS over TLS (DoT) client — RFC 7858.

Protocol:
  1. Open a TLS socket to port 853
  2. Verify the server's X.509 certificate against the system CA bundle
  3. Build a DNS query packet (see packet.py)
  4. Prefix with 2-byte big-endian length (RFC 7858 §3.3)
  5. Send; read 2-byte length prefix; read that many bytes
  6. Parse response, validate TXID

Security properties:
  ✓ TLS 1.2+ (ssl.PROTOCOL_TLS_CLIENT)
  ✓ Hostname verification (check_hostname=True)
  ✓ Certificate verification (verify_mode=CERT_REQUIRED)
  ✓ Secure random TXID (from packet.py)
  ✓ TXID validation in response
  ✗ No pinning — uses system CA bundle (good enough for most threat models)

To add certificate pinning:
  Use ctx.load_verify_locations(cafile="pinned_cert.pem")
  instead of ssl.create_default_context() which loads the system bundle.
"""

from __future__ import annotations

import logging
import socket
import ssl
import struct

from py_dns.packet import QTYPE_A, QTYPE_BY_NAME, build_query, parse_response

log = logging.getLogger(__name__)


class DoTUpstream:
    def __init__(self, host: str, port: int = 853, name: str = "") -> None:
        self.host = host
        self.port = port
        self.name = name or host


# Public DoT upstreams with verified hostnames
CLOUDFLARE_DOT = DoTUpstream("1.1.1.1",     853, "Cloudflare")
GOOGLE_DOT     = DoTUpstream("8.8.8.8",     853, "Google")
QUAD9_DOT      = DoTUpstream("9.9.9.9",     853, "Quad9")


class DoTClient:
    """
    Resolves domains via DNS over TLS.

    Falls back through upstreams on failure.
    Creates a new TLS connection per query (simple, no connection pool).

    To improve throughput:
        Add a connection pool with keep-alive (RFC 7858 allows this).
        In production, use asyncio + ssl for concurrent queries.
    """

    def __init__(
        self,
        upstreams: list[DoTUpstream] | None = None,
        timeout: float = 5.0,
    ) -> None:
        self._upstreams = upstreams or [CLOUDFLARE_DOT, GOOGLE_DOT]
        self._timeout   = timeout
        self._ctx       = self._make_ssl_context()

    def resolve(self, domain: str, record_type: str = "A") -> tuple[str | None, int]:
        """Returns (ip | None, ttl)."""
        for upstream in self._upstreams:
            result = self._query(upstream, domain, record_type)
            if result is not None:
                ip, ttl = result
                return ip, ttl
            log.warning("DoT upstream %s failed for %s", upstream.name, domain)
        return None, 0

    def _query(
        self, upstream: DoTUpstream, domain: str, record_type: str = "A"
    ) -> tuple[str, int] | None:
        qtype = QTYPE_BY_NAME.get(record_type.upper(), QTYPE_A)
        txid, raw_query = build_query(domain, qtype=qtype)

        # RFC 7858: prefix message with 2-byte length
        message = struct.pack("!H", len(raw_query)) + raw_query

        try:
            with socket.create_connection(
                (upstream.host, upstream.port),
                timeout=self._timeout,
            ) as sock, self._ctx.wrap_socket(sock, server_hostname=upstream.host) as tls_sock:
                tls_version = tls_sock.version()
                log.debug("DoT connected to %s (%s)", upstream.name, tls_version)

                tls_sock.sendall(message)

                # Read 2-byte length prefix
                length_data = self._recv_exact(tls_sock, 2)
                if not length_data:
                    return None
                (response_len,) = struct.unpack("!H", length_data)

                # Read the DNS response
                response_data = self._recv_exact(tls_sock, response_len)
                if not response_data:
                    return None

            parsed = parse_response(response_data, expected_txid=txid)

            if parsed.rcode == 3:   # NXDOMAIN
                log.debug("DoT NXDOMAIN for %s", domain)
                return None

            if parsed.answers:
                # Return first A record with a default TTL
                # (TTL parsing from wire format omitted for brevity — add it in packet.py)
                return parsed.answers[0], 300

            return None

        except ssl.SSLCertVerificationError as exc:
            # IMPORTANT: do not suppress this — it means the server cert is invalid
            log.error("DoT TLS cert verification FAILED for %s: %s", upstream.host, exc)
            return None
        except (OSError, struct.error, ValueError) as exc:
            log.debug("DoT error from %s: %s", upstream.name, exc)
            return None

    @staticmethod
    def _recv_exact(sock: ssl.SSLSocket, n: int) -> bytes:
        """Read exactly n bytes from a socket, blocking until available."""
        buf = b""
        while len(buf) < n:
            chunk = sock.recv(n - len(buf))
            if not chunk:
                return b""   # connection closed
            buf += chunk
        return buf

    @staticmethod
    def _make_ssl_context() -> ssl.SSLContext:
        """
        Create a hardened TLS context.

        ssl.PROTOCOL_TLS_CLIENT sets:
          - check_hostname = True   (hostname must match cert CN/SAN)
          - verify_mode = CERT_REQUIRED
          - Uses system CA bundle automatically

        Minimum version TLS 1.2 — disables SSLv3, TLS 1.0, TLS 1.1.
        """
        ctx = ssl.create_default_context()
        ctx.minimum_version = ssl.TLSVersion.TLSv1_2
        return ctx
