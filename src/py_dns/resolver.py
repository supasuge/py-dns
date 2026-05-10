"""Public secure resolver API and local UDP server."""

from __future__ import annotations

import logging
import socket
from dataclasses import dataclass

from py_dns.handlers import build_secure_chain
from py_dns.packet import (
    QCLASS_IN,
    QTYPE_A,
    QTYPE_AAAA,
    QTYPE_NAME,
    RCODE_NOERROR,
    RCODE_NOTIMP,
    build_response,
    parse_query,
)

log = logging.getLogger(__name__)


@dataclass(frozen=True)
class Resolution:
    domain: str
    record_type: str
    answer: str | None
    source: str = "secure-chain"


class SecureResolver:
    """Small public wrapper around the cache/hosts/DoH/DoT handler chain."""

    def __init__(
        self,
        *,
        rate: float = 100.0,
        burst: float = 200.0,
        hosts_path: str | None = None,
    ) -> None:
        self._chain, self._cache, self._doh, self._dot = build_secure_chain(
            rate=rate,
            burst=burst,
            hosts_path=hosts_path,
        )

    def resolve(self, domain: str, record_type: str = "A") -> str | None:
        return self._chain.handle(domain.rstrip("."), record_type.upper())

    def lookup(self, domain: str, record_type: str = "A") -> Resolution:
        record_type = record_type.upper()
        return Resolution(
            domain=domain,
            record_type=record_type,
            answer=self.resolve(domain, record_type),
        )

    @property
    def stats(self) -> dict[str, object]:
        return self._cache.stats

    def close(self) -> None:
        self._doh.close()

    def __enter__(self) -> SecureResolver:
        return self

    def __exit__(self, *_: object) -> None:
        self.close()


class SecureUDPServer:
    """Minimal local recursive UDP DNS server backed by SecureResolver."""

    def __init__(self, host: str = "127.0.0.1", port: int = 5353) -> None:
        self.host = host
        self.port = port
        self.resolver = SecureResolver()

    def serve_forever(self) -> None:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
            sock.bind((self.host, self.port))
            log.info("secure DNS resolver listening on udp://%s:%d", self.host, self.port)
            while True:
                data, addr = sock.recvfrom(4096)
                try:
                    response = self._handle_packet(data)
                except Exception:
                    log.exception("failed to handle query from %s", addr)
                    response = self._formerr(data)
                sock.sendto(response, addr)

    def _handle_packet(self, data: bytes) -> bytes:
        question = parse_query(data)
        if question.qclass != QCLASS_IN:
            return build_response(question, [], rcode=RCODE_NOTIMP)

        record_type = QTYPE_NAME.get(question.qtype)
        if record_type not in {"A", "AAAA"}:
            return build_response(question, [], rcode=RCODE_NOERROR)

        answer = self.resolver.resolve(question.domain, record_type)
        answers = [answer] if answer else []
        return build_response(question, answers, ttl=60, rcode=RCODE_NOERROR)

    @staticmethod
    def _formerr(data: bytes) -> bytes:
        txid = int.from_bytes(data[:2], "big") if len(data) >= 2 else 0
        return txid.to_bytes(2, "big") + b"\x81\x81" + b"\x00\x00\x00\x00\x00\x00\x00\x00"


def is_supported_qtype(qtype: int) -> bool:
    return qtype in {QTYPE_A, QTYPE_AAAA}
