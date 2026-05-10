"""
Vulnerability catalog for dns-vuln.

Each entry documents:
  - VULN-ID     : short identifier referenced in code comments
  - Category    : CVE class / attack family
  - Description : what the flaw is
  - Impact      : realistic attack scenario
  - Mitigation  : how dns-secure fixes it

This module is pure documentation — no executable logic.
"""

VULNERABILITIES = {
    "VULN-001": {
        "name":       "Predictable Transaction IDs",
        "category":   "Kaminsky DNS Cache Poisoning (CVE-2008-1447 class)",
        "description": (
            "Transaction IDs are generated with a sequential counter (1, 2, 3…) "
            "instead of a cryptographically random source. An attacker who can "
            "observe or guess the ID range can race a forged response to the resolver "
            "before the legitimate authoritative server replies."
        ),
        "impact":     "Cache poisoning — redirect any domain to attacker-controlled IP",
        "mitigation": "dns-secure uses secrets.randbelow(65536) for every query",
    },
    "VULN-002": {
        "name":       "Fixed Source Port (No Port Randomization)",
        "category":   "Source Port Prediction (Kaminsky amplification)",
        "description": (
            "All outgoing UDP queries use the same source port (53). "
            "RFC 5452 requires random source port selection to add ~16 bits "
            "of entropy on top of the 16-bit TXID, making spoofing 65536× harder. "
            "With a fixed port, only the TXID must be guessed."
        ),
        "impact":     "Makes VULN-001 exploitable in ~65536 forged packets instead of ~4B",
        "mitigation": "dns-secure uses TCP-based DoT/DoH — source port is irrelevant",
    },
    "VULN-003": {
        "name":       "Open Recursive Resolver",
        "category":   "DNS Amplification DDoS (CVE-2006-0987 class)",
        "description": (
            "The server answers recursive queries from any source IP. "
            "An attacker can spoof the source IP of a victim and send small "
            "queries (ANY, TXT) that produce large responses (amplification factor "
            "up to 70×), flooding the victim with reflected DNS traffic."
        ),
        "impact":     "DDoS amplification — 1 Mbps attack traffic → 70 Mbps at victim",
        "mitigation": "Restrict recursion to known clients; enable Response Rate Limiting (RRL)",
    },
    "VULN-004": {
        "name":       "No Rate Limiting",
        "category":   "Resource Exhaustion / Amplification Enablement",
        "description": (
            "There is no per-source or per-query-type rate limit. "
            "A single client can saturate the resolver's network and CPU "
            "with thousands of queries per second."
        ),
        "impact":     "Resolver DoS; amplification attack enablement (see VULN-003)",
        "mitigation": "dns-secure uses a token bucket (100 req/s, burst 200)",
    },
    "VULN-005": {
        "name":       "No Response Validation (Cache Poisoning)",
        "category":   "Bailiwick Violation / Kaminsky Attack",
        "description": (
            "The server accepts any UDP response that arrives on port 53 "
            "without checking: (a) source IP, (b) source port, (c) TXID match. "
            "An attacker on the same network can inject forged responses "
            "that get cached and served to all clients."
        ),
        "impact":     "Arbitrary cache poisoning — full domain hijack",
        "mitigation": "dns-secure validates TXID and uses TCP (eliminates UDP spoofing entirely)",
    },
    "VULN-006": {
        "name":       "Cleartext UDP Transport",
        "category":   "On-path Eavesdropping / MITM",
        "description": (
            "All DNS queries and responses travel over UDP port 53 without "
            "any encryption. An on-path attacker (ISP, coffee-shop router, "
            "VPN provider) can read every domain name you look up and "
            "selectively modify responses."
        ),
        "impact":     "Privacy leak, selective censorship, on-path injection",
        "mitigation": "dns-secure uses DoH (HTTPS/TLS) and DoT (TLS port 853)",
    },
    "VULN-007": {
        "name":       "No DNSSEC Validation",
        "category":   "Cryptographic Bypass",
        "description": (
            "The resolver does not check DNSSEC signatures (DS, RRSIG, DNSKEY records). "
            "Even if an authoritative server signs its records, this resolver "
            "cannot distinguish a valid signed response from a forged one."
        ),
        "impact":     "Forged DNS responses accepted even for DNSSEC-signed zones",
        "mitigation": "dns-secure checks the AD (Authenticated Data) bit in DoH responses",
    },
    "VULN-008": {
        "name":       "Missing Negative Caching (NXDOMAIN Amplification)",
        "category":   "Resource Exhaustion",
        "description": (
            "NXDOMAIN responses are not cached. Every query for a non-existent "
            "domain triggers a full upstream lookup. An attacker can repeatedly "
            "query random subdomains to exhaust the resolver's upstream query budget "
            "and degrade service for legitimate users."
        ),
        "impact":     "Resolver slowdown; authoritative server overload",
        "mitigation": "dns-secure's SecureDNSCache.put_negative() caches NXDOMAIN for 60s",
    },
}


def print_vuln_summary() -> None:
    for vid, info in VULNERABILITIES.items():
        print(f"\n{'═'*70}")
        print(f"  {vid}: {info['name']}")
        print(f"  Category  : {info['category']}")
        print(f"  Impact    : {info['impact']}")
        print(f"  Mitigation: {info['mitigation']}")