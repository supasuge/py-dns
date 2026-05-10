"""
DNS wire-format encoder / decoder (RFC 1035).

Used by DoTClient, which must speak raw DNS over a TLS socket.
DoHClient uses JSON instead and does not depend on this module.

Packet structure (RFC 1035 §4.1):
  Header   : 12 bytes  — ID (2), Flags (2), 4 × 16-bit counts
  Question : variable  — encoded QNAME + QTYPE (2) + QCLASS (2)
  Answer   : variable  — one or more resource records

This module exports two pairs of functions:

  SECURE (cryptographically safe):
    build_query(domain, qtype)              — random TXID via secrets
    parse_response(data, expected_txid)     — validates TXID and QR bit

  VULNERABLE (intentional flaws for lab use):
    build_query_sequential(domain, qtype)   — sequential TXID (VULN-001)
    parse_response_no_validation(data)      — accepts any datagram (VULN-005)

The contrast makes the security delta explicit for teaching purposes.

TXID entropy (why it matters):
  A 16-bit TXID gives only 65 536 possible values.
  A sequential counter lets an attacker predict the next value after one
  observation, reducing the poisoning effort to a single forged response.
  secrets.randbelow(65536) draws from the OS CSPRNG, restoring the full
  16-bit space for each query independently.
"""

from __future__ import annotations

import secrets
import struct
from dataclasses import dataclass, field
from ipaddress import IPv4Address, IPv6Address

# ── DNS constants ──────────────────────────────────────────────────────────────

QTYPE_A     = 1
QTYPE_NS    = 2
QTYPE_CNAME = 5
QTYPE_SOA   = 6
QTYPE_MX    = 15
QTYPE_AAAA  = 28
QTYPE_ANY   = 255

QCLASS_IN   = 1

RCODE_NOERROR  = 0
RCODE_FORMERR  = 1
RCODE_SERVFAIL = 2
RCODE_NXDOMAIN = 3
RCODE_NOTIMP   = 4
RCODE_REFUSED  = 5

QTYPE_BY_NAME = {
    "A": QTYPE_A,
    "AAAA": QTYPE_AAAA,
    "CNAME": QTYPE_CNAME,
    "MX": QTYPE_MX,
    "NS": QTYPE_NS,
    "SOA": QTYPE_SOA,
    "ANY": QTYPE_ANY,
}
QTYPE_NAME = {value: key for key, value in QTYPE_BY_NAME.items()}


# ── Response data class ────────────────────────────────────────────────────────

@dataclass(slots=True, frozen=True)
class ParsedResponse:
    """
    Decoded DNS response.

    txid     : transaction ID echoed from the query.
    rcode    : response code (0 = NOERROR, 3 = NXDOMAIN, etc.).
    answers  : IPv4/IPv6 address strings extracted from A / AAAA records.
               CNAME targets are noted but not recursively resolved here —
               the caller should re-query the CNAME target if needed.

    The answers list contains only address records; all other record types
    (NS, MX, SOA, …) are silently skipped during parsing.
    """
    txid:    int
    rcode:   int
    answers: list[str]
    cnames:  list[str] = field(default_factory=list)


@dataclass(slots=True, frozen=True)
class DNSQuestion:
    txid: int
    domain: str
    qtype: int
    qclass: int
    question: bytes


# ── SECURE query builder ───────────────────────────────────────────────────────

def build_query(domain: str, qtype: int = QTYPE_A) -> tuple[int, bytes]:
    """
    Build a standards-compliant DNS query with a cryptographically random TXID.

    Security:
      ✓ secrets.randbelow(65536) draws from the OS CSPRNG — unpredictable.
        Mitigates VULN-001 (sequential TXID prediction).
      ✓ QNAME is lowercased and stripped of a trailing dot before encoding.

    Returns:
      (txid, raw_bytes)

    The caller MUST retain txid and pass it to parse_response() to validate
    that the response is for this query and not a spoofed/replayed packet.

    Header flags: QR=0 (query) | OPCODE=0 (standard) | RD=1 (recursion desired).
    """
    txid   = secrets.randbelow(65536)      # cryptographically random
    flags  = 0x0100                         # RD bit
    header = struct.pack("!HHHHHH", txid, flags, 1, 0, 0, 0)
    qname  = _encode_name(domain)
    question = qname + struct.pack("!HH", qtype, QCLASS_IN)
    return txid, header + question


def parse_query(data: bytes) -> DNSQuestion:
    """Parse one-question DNS query packets for the local secure UDP server."""
    if len(data) < 12:
        raise ValueError("DNS query too short")

    txid, flags, qdcount, _ancount, _nscount, _arcount = struct.unpack("!HHHHHH", data[:12])
    if flags & 0x8000:
        raise ValueError("packet is a response, not a query")
    if qdcount != 1:
        raise ValueError(f"expected exactly one DNS question, got {qdcount}")

    offset, domain = _parse_name(data, 12)
    if offset + 4 > len(data):
        raise ValueError("truncated DNS question")
    qtype, qclass = struct.unpack("!HH", data[offset:offset + 4])
    question = data[12:offset + 4]
    return DNSQuestion(txid=txid, domain=domain, qtype=qtype, qclass=qclass, question=question)


def build_response(
    question: DNSQuestion,
    answers: list[str],
    *,
    ttl: int = 60,
    rcode: int = RCODE_NOERROR,
) -> bytes:
    """
    Build a minimal DNS response for the local resolver.

    Only A and AAAA address answers are emitted. Unsupported question types get
    a valid empty NOERROR response unless the caller supplies a different rcode.
    """
    flags = 0x8000 | 0x0100 | 0x0080 | (rcode & 0x000F)  # QR, RD, RA
    records = b""
    answer_count = 0
    if rcode == RCODE_NOERROR and question.qclass == QCLASS_IN:
        for answer in answers:
            rdata = _ip_to_rdata(answer, question.qtype)
            if rdata is None:
                continue
            records += struct.pack("!HHHIH", 0xC00C, question.qtype, QCLASS_IN, ttl, len(rdata))
            records += rdata
            answer_count += 1

    header = struct.pack("!HHHHHH", question.txid, flags, 1, answer_count, 0, 0)
    return header + question.question + records


# ── VULNERABLE query builder (VULN-001) ───────────────────────────────────────

_vuln_txid_counter: int = 0


def build_query_sequential(domain: str, qtype: int = QTYPE_A) -> tuple[int, bytes]:
    """
    Build a DNS query with a SEQUENTIAL (predictable) transaction ID.

    VULN-001: Predictable Transaction IDs (Kaminsky DNS Cache Poisoning class).

    The counter increments by one per call, wrapping at 65535.
    An attacker who observes or guesses a single TXID can predict all
    future IDs and race a forged response to the resolver, poisoning its
    cache with attacker-controlled IP addresses.

    This function is intentionally insecure.  Use build_query() in all
    production code.  It exists here solely so VulnerableServer can
    demonstrate VULN-001 in a controlled lab environment.

    Compare with build_query() which uses secrets.randbelow(65536).
    """
    global _vuln_txid_counter
    _vuln_txid_counter = (_vuln_txid_counter + 1) % 65536
    txid   = _vuln_txid_counter
    flags  = 0x0100
    header = struct.pack("!HHHHHH", txid, flags, 1, 0, 0, 0)
    qname  = _encode_name(domain)
    question = qname + struct.pack("!HH", qtype, QCLASS_IN)
    return txid, header + question


# ── SECURE response parser ─────────────────────────────────────────────────────

def parse_response(data: bytes, expected_txid: int) -> ParsedResponse:
    """
    Parse and validate a DNS response packet (secure path).

    Validates:
      ✓ Minimum length (12-byte header).
      ✓ TXID matches the query we sent — rejects spoofed / replayed responses
        (mitigates VULN-005).
      ✓ QR bit (bit 15 of flags) is set — confirms it is a response, not an
        accidental echo of a query.

    Parses:
      ✓ A records  → IPv4 strings ("1.2.3.4").
      ✓ AAAA records → IPv6 strings ("2606:2800:220:1:248:1893:25c8:1946").
      ✓ CNAME records → target name collected in ParsedResponse.cnames.
      ✓ Compression pointer loops are detected and rejected.

    Raises:
      ValueError  on any structural violation (short packet, TXID mismatch,
                  QR bit unset, pointer loop, truncated record).

    The caller should check parsed.rcode before using parsed.answers:
      rcode == 0  →  NOERROR  →  answers may be populated
      rcode == 3  →  NXDOMAIN →  domain does not exist
      other       →  server error — do not cache
    """
    if len(data) < 12:
        raise ValueError(f"response too short: {len(data)} bytes (minimum 12)")

    txid, flags, qdcount, ancount, _nscount, _arcount = struct.unpack(
        "!HHHHHH", data[:12]
    )

    if txid != expected_txid:
        raise ValueError(
            f"TXID mismatch: expected {expected_txid:#06x}, got {txid:#06x} "
            f"— possible spoofed response"
        )

    if not (flags & 0x8000):
        raise ValueError("QR bit not set — packet is a query, not a response")

    rcode = flags & 0x000F

    # Skip question section
    offset = 12
    try:
        for _ in range(qdcount):
            offset = _skip_name(data, offset)
            offset += 4  # QTYPE + QCLASS

        answers: list[str] = []
        cnames:  list[str] = []

        for _ in range(ancount):
            offset, _name = _parse_name(data, offset)
            if offset + 10 > len(data):
                break
            rtype, _rclass, _ttl, rdlen = struct.unpack(
                "!HHIH", data[offset:offset + 10]
            )
            offset += 10

            if rtype == QTYPE_A and rdlen == 4:
                ip = ".".join(str(b) for b in data[offset:offset + 4])
                answers.append(ip)

            elif rtype == QTYPE_AAAA and rdlen == 16:
                raw = data[offset:offset + 16]
                groups = [f"{raw[i]:02x}{raw[i + 1]:02x}" for i in range(0, 16, 2)]
                answers.append(":".join(groups))

            elif rtype == QTYPE_CNAME:
                _, cname_target = _parse_name(data, offset)
                cnames.append(cname_target)

            offset += rdlen

    except (struct.error, IndexError) as exc:
        raise ValueError(f"malformed DNS response: {exc}") from exc

    return ParsedResponse(txid=txid, rcode=rcode, answers=answers, cnames=cnames)


# ── VULNERABLE response parser (VULN-005) ─────────────────────────────────────

def parse_response_no_validation(data: bytes) -> list[str]:
    """
    Parse a DNS response WITHOUT any security validation.

    VULN-005: No Response Validation (Cache Poisoning).

    Flaws (deliberate):
      ✗ No TXID check — accepts responses for queries this server never sent.
      ✗ No QR bit check — accepts query packets as if they were responses.
      ✗ No source IP check — caller must enforce this (the server does not).
      ✗ No rcode check — silently returns empty list on NXDOMAIN/SERVFAIL.

    An on-path or racing attacker can inject a forged UDP datagram that
    arrives before the legitimate upstream response.  Because no TXID
    match is performed, the forged answer is accepted and stored in the
    cache, redirecting all clients to the attacker's IP until TTL expiry
    (or indefinitely, since VulnerableCache has no TTL).

    Returns a list of IPv4 address strings, or [] on parse failure.

    This function is intentionally insecure.  Use parse_response() with
    expected_txid in all production code.
    """
    if len(data) < 12:
        return []
    try:
        _txid, flags, qdcount, ancount, _ns, _ar = struct.unpack(
            "!HHHHHH", data[:12]
        )
        # VULN-005: no TXID check, no QR bit check
        rcode = flags & 0x000F
        if rcode != RCODE_NOERROR:
            return []

        offset = 12
        for _ in range(qdcount):
            offset = _skip_name(data, offset)
            offset += 4

        answers: list[str] = []
        for _ in range(ancount):
            offset, _ = _parse_name(data, offset)
            if offset + 10 > len(data):
                break
            rtype, _rclass, _ttl, rdlen = struct.unpack(
                "!HHIH", data[offset:offset + 10]
            )
            offset += 10
            if rtype == QTYPE_A and rdlen == 4:
                ip = ".".join(str(b) for b in data[offset:offset + 4])
                answers.append(ip)
            offset += rdlen

        return answers

    except (struct.error, IndexError):
        return []


# ── Wire-format helpers ────────────────────────────────────────────────────────

def _encode_name(domain: str) -> bytes:
    """
    Encode a domain name as length-prefixed labels (RFC 1035 §3.1).

    "www.example.com" → b'\x03www\x07example\x03com\x00'

    Labels are downcased and the trailing dot is stripped before encoding.
    Raises ValueError if any label exceeds 63 bytes or the total name
    exceeds 253 characters (RFC 1035 §2.3.4 limits).
    """
    labels = domain.rstrip(".").lower().split(".")
    encoded = b""
    for label in labels:
        lb = label.encode("ascii")
        if len(lb) > 63:
            raise ValueError(f"DNS label too long ({len(lb)} > 63): {label!r}")
        encoded += bytes([len(lb)]) + lb
    if len(domain.rstrip(".")) > 253:
        raise ValueError(f"domain name too long ({len(domain)} > 253): {domain!r}")
    return encoded + b"\x00"


def _ip_to_rdata(value: str, qtype: int) -> bytes | None:
    try:
        if qtype == QTYPE_A:
            return IPv4Address(value).packed
        if qtype == QTYPE_AAAA:
            return IPv6Address(value).packed
    except ValueError:
        return None
    return None


def _skip_name(data: bytes, offset: int) -> int:
    """
    Advance past a DNS name (following compression pointers).

    Returns the offset of the first byte after the name.
    Does not decode labels — use _parse_name() when the string is needed.
    """
    while offset < len(data):
        length = data[offset]
        if length == 0:
            return offset + 1
        if (length & 0xC0) == 0xC0:   # compression pointer (RFC 1035 §4.1.4)
            return offset + 2
        offset += length + 1
    return offset


def _parse_name(data: bytes, offset: int) -> tuple[int, str]:
    """
    Decode a DNS name, following compression pointers.

    Returns (new_offset, name_string).

    new_offset advances past the *uncompressed* part of the name only
    (i.e., past the pointer byte, not to the pointer target).  This is
    the RFC 1035 §4.1.4 rule: the pointer always terminates the current
    name encoding — the byte after the pointer belongs to the *next* field.

    Pointer loop detection:
      visited tracks every offset we have followed.  A loop (pointer back
      to itself or to a previous pointer in the chain) raises ValueError
      rather than looping infinitely.
    """
    labels:  list[str] = []
    visited: set[int]  = set()

    while offset < len(data):
        if offset in visited:
            raise ValueError(f"DNS name compression loop at offset {offset}")
        visited.add(offset)

        length = data[offset]

        if length == 0:
            offset += 1
            break

        if (length & 0xC0) == 0xC0:
            if offset + 1 >= len(data):
                raise ValueError("truncated DNS compression pointer")
            ptr = ((length & 0x3F) << 8) | data[offset + 1]
            _, suffix = _parse_name(data, ptr)
            if suffix:
                labels.append(suffix)
            offset += 2
            break

        offset += 1
        if offset + length > len(data):
            raise ValueError(
                f"DNS label at offset {offset - 1} claims length {length} "
                f"but only {len(data) - offset} bytes remain"
            )
        labels.append(data[offset:offset + length].decode("ascii", errors="replace"))
        offset += length

    return offset, ".".join(labels)
