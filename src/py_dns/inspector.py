"""DNS inspection, provider fingerprinting, and security posture checks."""

from __future__ import annotations

import re
import socket
import ssl
from dataclasses import dataclass
from html import unescape
from ipaddress import ip_address, ip_network
from urllib.parse import quote_plus

import dns.exception
import dns.query
import dns.resolver
import dns.zone
import httpx

from py_dns.doh import DoHAnswer, DoHClient, DoHResult

TYPE_NAME = {
    1: "A",
    2: "NS",
    5: "CNAME",
    6: "SOA",
    15: "MX",
    16: "TXT",
    28: "AAAA",
    43: "DS",
    46: "RRSIG",
    48: "DNSKEY",
    52: "TLSA",
    65: "HTTPS",
    257: "CAA",
}

DEFAULT_RECORD_TYPES = (
    "A",
    "AAAA",
    "CNAME",
    "NS",
    "SOA",
    "MX",
    "TXT",
    "CAA",
    "DS",
    "DNSKEY",
    "HTTPS",
)

SECURITY_RECORD_QUERIES = {
    "DMARC": ("_dmarc.{domain}", "TXT"),
    "MTA-STS": ("_mta-sts.{domain}", "TXT"),
    "TLS-RPT": ("_smtp._tls.{domain}", "TXT"),
    "BIMI": ("default._bimi.{domain}", "TXT"),
}

PASSIVE_SUBDOMAIN_PREFIXES = (
    "app",
    "api",
    "assets",
    "cdn",
    "dev",
    "direct",
    "internal",
    "origin",
    "portal",
    "stage",
    "staging",
    "test",
    "vpn",
    "www",
)

ORIGIN_CANDIDATE_PREFIXES = (
    "origin",
    "direct",
    "backend",
    "server",
    "app",
    "api",
    "staging",
    "stage",
    "dev",
)

ORIGIN_DISCOVERY_PREFIXES = (
    "origin",
    "origin-www",
    "direct",
    "backend",
    "server",
    "app",
    "api",
    "web",
    "www-origin",
    "lb",
    "elb",
    "loadbalancer",
    "prod",
    "production",
    "staging",
    "stage",
    "dev",
    "test",
    "old",
    "legacy",
    "internal",
    "vpn",
    "cpanel",
    "whm",
    "plesk",
    "mail",
    "ftp",
    "ssh",
)

DEFAULT_BRUTEFORCE_LABELS = (
    "www",
    "api",
    "app",
    "admin",
    "assets",
    "blog",
    "cdn",
    "dashboard",
    "dev",
    "docs",
    "mail",
    "origin",
    "portal",
    "stage",
    "staging",
    "status",
    "test",
    "vpn",
)

TAKEOVER_PROVIDER_SUFFIXES = {
    "AWS CloudFront": ("cloudfront.net",),
    "AWS S3 Website": ("s3-website", "s3.amazonaws.com"),
    "Azure App Service": ("azurewebsites.net",),
    "Azure Front Door": ("azurefd.net", "azureedge.net"),
    "GitHub Pages": ("github.io",),
    "Heroku": ("herokuapp.com", "herokudns.com"),
    "Netlify": ("netlify.app", "netlify.com"),
    "Pantheon": ("pantheonsite.io",),
    "Read the Docs": ("readthedocs.io",),
    "Shopify": ("myshopify.com",),
    "Vercel": ("vercel.app", "vercel-dns.com", "vercel-dns-0.com"),
}

PROVIDER_SUFFIXES = {
    "Akamai": ("akamai.net", "akamaiedge.net", "edgesuite.net", "edgekey.net", "akamaized.net"),
    "Alibaba Cloud": ("alicdn.com", "kunlunsl.com", "aliyuncs.com"),
    "AWS CloudFront": ("cloudfront.net",),
    "AWS Route 53": ("awsdns-", "route53.amazonaws.com"),
    "AWS": ("amazonaws.com", "elb.amazonaws.com"),
    "Azure": (
        "azure.com",
        "azure-dns.com",
        "azure-dns.info",
        "azure-dns.net",
        "azure-dns.org",
        "azureedge.net",
        "azurefd.net",
        "cloudapp.net",
        "trafficmanager.net",
    ),
    "Bunny": ("b-cdn.net", "bunnycdn.com", "bunny.net"),
    "CacheFly": ("cachefly.net",),
    "CDN77": ("cdn77.org", "cdn77.net"),
    "CDNetworks": ("cdngc.net", "cdnetworks.net"),
    "Cloudflare": ("cloudflare.com", "cloudflare.net", "cdn.cloudflare.net"),
    "Cloudflare for SaaS": ("cdn.cloudflare.net",),
    "DigitalOcean": ("digitaloceanspaces.com", "ondigitalocean.app"),
    "Edgio/Limelight": ("edgio.net", "llnwd.net", "footprint.net"),
    "Fastly": ("fastly.net", "fastlylb.net", "map.fastly.net"),
    "Gcore": ("gcorelabs.net", "gcdn.co"),
    "GitHub Pages": ("github.io", "github.com"),
    "Google": (
        "google.com",
        "googlehosted.com",
        "googleusercontent.com",
        "googledomains.com",
        "googledomains.com",
        "googlehosted.l.googleusercontent.com",
    ),
    "Google Cloud": ("googleapis.com", "ghs.googlehosted.com", "googleusercontent.com"),
    "Imperva": ("impervadns.net", "incapdns.net", "incapsula.com"),
    "KeyCDN": ("kxcdn.com", "keycdn.com"),
    "Leaseweb": ("lswcdn.net", "leasewebcdn.com"),
    "Linode/Akamai Cloud": ("linode.com", "linodeusercontent.com", "members.linode.com"),
    "Netlify": ("netlify.app", "netlify.com", "netlifyglobalcdn.com"),
    "NS1/IBM NS1 Connect": ("dns1.p", "nsone.net"),
    "Oracle Dyn": ("dynect.net", "oraclecloud.net"),
    "OVH": ("ovh.net", "ovh.ca"),
    "Sectigo DNS": ("sectigodns.com",),
    "Shopify": ("myshopify.com", "shops.myshopify.com"),
    "StackPath": ("stackpathdns.com", "stackpathcdn.com", "hwcdn.net"),
    "Tencent Cloud": ("dnsv1.com", "qcloudcdn.com", "tencent-cloud.net"),
    "Vercel": ("vercel-dns.com", "vercel-dns-0.com", "vercel.app", "now-dns.net"),
}

MAIL_PROVIDER_SUFFIXES = {
    "Fastmail": ("messagingengine.com",),
    "Google Workspace": ("google.com", "googlemail.com"),
    "Microsoft 365": ("outlook.com", "protection.outlook.com"),
    "Proton Mail": ("protonmail.ch", "protonmail.com",),
    "SendGrid": ("sendgrid.net",),
    "Zoho Mail": ("zoho.com", "zohomail.com"),
}

HTTP_HEADER_PROVIDERS = {
    "cf-ray": "Cloudflare",
    "cf-cache-status": "Cloudflare",
    "x-vercel-id": "Vercel",
    "x-nf-request-id": "Netlify",
    "x-fastly-request-id": "Fastly",
    "x-akamai-transformed": "Akamai",
    "x-akamai-request-id": "Akamai",
    "x-iinfo": "Imperva",
    "x-cdn": "CDN",
    "cdn-requestid": "Bunny",
    "x-gcore-request-id": "Gcore",
    "x-cdn77-cache": "CDN77",
    "x-cache": "AWS CloudFront/Akamai/Fastly",
    "x-amz-cf-id": "AWS CloudFront",
    "x-amz-cf-pop": "AWS CloudFront",
    "x-azure-ref": "Azure",
    "x-azure-fdid": "Azure",
    "x-served-by": "Fastly/Netlify",
    "server": "server-header",
}

EDGE_PROVIDERS = {
    "Akamai",
    "AWS CloudFront",
    "Azure",
    "Bunny",
    "CDN",
    "CDN77",
    "CDNetworks",
    "Cloudflare",
    "Cloudflare for SaaS",
    "Edgio/Limelight",
    "Fastly",
    "Gcore",
    "Google Cloud",
    "Imperva",
    "KeyCDN",
    "Netlify",
    "StackPath",
    "Vercel",
}

CLOUDFLARE_NETWORKS = tuple(
    ip_network(network)
    for network in (
        "173.245.48.0/20",
        "103.21.244.0/22",
        "103.22.200.0/22",
        "103.31.4.0/22",
        "141.101.64.0/18",
        "108.162.192.0/18",
        "190.93.240.0/20",
        "188.114.96.0/20",
        "197.234.240.0/22",
        "198.41.128.0/17",
        "162.158.0.0/15",
        "104.16.0.0/13",
        "104.24.0.0/14",
        "172.64.0.0/13",
        "131.0.72.0/22",
        "2400:cb00::/32",
        "2606:4700::/32",
        "2803:f800::/32",
        "2405:b500::/32",
        "2405:8100::/32",
        "2a06:98c0::/29",
        "2c0f:f248::/32",
    )
)


@dataclass(frozen=True)
class Detection:
    provider: str
    reason: str
    source: str = "dns"
    confidence: str = "medium"


@dataclass(frozen=True)
class Finding:
    severity: str
    check: str
    status: str
    evidence: str
    impact: str
    recommendation: str
    validation: str


@dataclass(frozen=True)
class HttpProbe:
    url: str
    status_code: int | None
    headers: tuple[tuple[str, str], ...]
    error: str | None = None
    title: str | None = None


@dataclass(frozen=True)
class ReconRecord:
    source: str
    category: str
    name: str
    value: str
    status: str = "observed"
    evidence: str = ""


@dataclass(frozen=True)
class OriginCandidate:
    hostname: str
    addresses: tuple[str, ...]
    source: str
    confidence: str
    evidence: str
    edge_provider: str | None = None
    validation_status: str = "not-tested"
    validation_evidence: str = ""


@dataclass(frozen=True)
class MailProfile:
    receives_mail: bool
    sends_mail: bool
    null_mx: bool
    mx_hosts: tuple[str, ...]
    provider: str | None
    management: str
    evidence: str


@dataclass(frozen=True)
class Inspection:
    domain: str
    results: tuple[DoHResult, ...]
    security_results: tuple[DoHResult, ...]
    detections: tuple[Detection, ...]
    findings: tuple[Finding, ...]
    http_probe: HttpProbe | None = None
    osint_records: tuple[ReconRecord, ...] = ()
    subdomains: tuple[str, ...] = ()
    zone_transfer_records: tuple[ReconRecord, ...] = ()
    origin_candidates: tuple[OriginCandidate, ...] = ()
    mail_profile: MailProfile | None = None

    @property
    def all_results(self) -> tuple[DoHResult, ...]:
        return self.results + self.security_results


def inspect_domain(
    domain: str,
    *,
    record_types: tuple[str, ...] = DEFAULT_RECORD_TYPES,
    client: DoHClient | None = None,
    http_probe: bool = True,
    passive_osint: bool = True,
    active_checks: bool = True,
    max_subdomains: int = 100,
) -> Inspection:
    owns_client = client is None
    doh = client or DoHClient()
    domain = domain.rstrip(".").lower()
    try:
        results = tuple(
            result
            for record_type in record_types
            if (result := doh.lookup(domain, record_type)) is not None
        )
        security_results = _lookup_security_records(doh, domain)
        probe = probe_http(domain) if http_probe else None
        detections = detect_services(results + security_results, probe)
        osint_records, subdomains = collect_passive_osint(domain, max_subdomains=max_subdomains) if passive_osint else ((), ())
        active_records = collect_active_dns_records(domain) if active_checks else ()
        origin_intel_records = collect_origin_intelligence(domain, probe) if active_checks else ()
        zone_transfer_records = attempt_zone_transfers(domain) if active_checks else ()
        origin_candidates = find_origin_candidates(
            domain,
            subdomains,
            doh,
            detections=detections,
            protected_probe=probe,
            recon_records=origin_intel_records,
            validate_http=http_probe,
        ) if _edge_providers(detections) else ()
        mail_profile = classify_mail_profile(results, security_results, detections)
        findings = analyze_security(
            domain,
            results,
            security_results,
            detections,
            mail_profile=mail_profile,
            active_dns_records=active_records,
            zone_transfer_records=zone_transfer_records,
            origin_candidates=origin_candidates,
        )
        return Inspection(
            domain,
            results,
            security_results,
            detections,
            findings,
            probe,
            osint_records + active_records + origin_intel_records,
            subdomains,
            zone_transfer_records,
            origin_candidates,
            mail_profile,
        )
    finally:
        if owns_client:
            doh.close()


def detect_services(
    results: tuple[DoHResult, ...],
    http_probe: HttpProbe | None = None,
) -> tuple[Detection, ...]:
    detections: dict[tuple[str, str], Detection] = {}
    for result in results:
        for answer in result.answers:
            _detect_by_suffix(answer, detections)
            _detect_cloudflare_ip(answer, detections)
    if http_probe is not None:
        _detect_http_headers(http_probe, detections)
    return tuple(sorted(detections.values(), key=lambda d: (d.provider, d.source, d.reason)))


def analyze_security(
    domain: str,
    results: tuple[DoHResult, ...],
    security_results: tuple[DoHResult, ...],
    detections: tuple[Detection, ...],
    *,
    mail_profile: MailProfile | None = None,
    active_dns_records: tuple[ReconRecord, ...] = (),
    zone_transfer_records: tuple[ReconRecord, ...] = (),
    origin_candidates: tuple[OriginCandidate, ...] = (),
) -> tuple[Finding, ...]:
    answers = _answers_by_type(results)
    security = {result.record_type: result for result in security_results}
    mail_profile = mail_profile or classify_mail_profile(results, security_results, detections)
    findings: list[Finding] = []

    if not answers.get("A") and not answers.get("AAAA"):
        findings.append(
            _finding(
                "high",
                "Address records",
                "missing",
                "No A or AAAA answers",
                "Clients cannot reach the hostname; stale names can also hide abandoned assets.",
                "Publish A/AAAA records for an active service or remove the hostname.",
                f"dig A {domain} +short; dig AAAA {domain} +short should return active service IPs or both records should intentionally remain absent.",
            )
        )
    elif not answers.get("AAAA"):
        findings.append(
            _finding(
                "info",
                "IPv6",
                "missing",
                "No AAAA record",
                "IPv6-only or IPv6-preferred clients may fall back to slower IPv4 paths.",
                "Add an AAAA record if the service and upstream provider support IPv6.",
                f"dig AAAA {domain} +short should return the expected IPv6 address after rollout.",
            )
        )

    findings.extend(_address_posture_findings(domain, answers.get("A", ()) + answers.get("AAAA", ())))
    findings.extend(_nameserver_posture_findings(domain, answers.get("NS", ())))
    findings.extend(_soa_posture_findings(domain, answers.get("SOA", ())))
    findings.extend(_ttl_posture_findings(domain, results))

    if not answers.get("CAA"):
        findings.append(
            _finding(
                "medium",
                "CAA",
                "missing",
                "No CAA records",
                "Any public CA may issue certificates for the domain if normal validation succeeds.",
                "Publish CAA records for the certificate authorities you actually use.",
                f"dig CAA {domain} +short should show only approved issuers such as issue/issuewild entries.",
            )
        )
    else:
        findings.extend(_caa_posture_findings(domain, answers.get("CAA", ())))

    if not answers.get("DS") and not answers.get("DNSKEY"):
        findings.append(
            _finding(
                "medium",
                "DNSSEC",
                "not detected",
                "No DS/DNSKEY answers from resolver",
                "Resolvers cannot cryptographically validate the zone, leaving DNS answers dependent on transport/upstream trust.",
                "Enable DNSSEC signing at the DNS provider and publish the DS record at the registrar.",
                f"dig DS {domain} +dnssec +short and dig DNSKEY {domain} +dnssec +short should return records; validating resolvers should set AD.",
            )
        )

    txt_values = tuple(answer.data for answer in answers.get("TXT", ()))
    spf = [value for value in txt_values if _is_spf(value)]
    dmarc = _txt_values(security.get("DMARC"))

    if mail_profile.null_mx:
        if not spf or not any("-all" in value.lower() for value in spf):
            findings.append(
                _finding(
                    "low",
                    "Mail posture",
                    "receiving disabled",
                    mail_profile.evidence,
                    "The domain publishes a null MX, but an explicit SPF deny policy makes spoofing intent clearer to receivers.",
                    "Keep the null MX and publish v=spf1 -all if the domain should never send mail.",
                    f"dig MX {domain} +short should show 0 . and dig TXT {domain} +short should show v=spf1 -all.",
                )
            )
    elif not mail_profile.receives_mail and not mail_profile.sends_mail:
        pass
    elif mail_profile.receives_mail and not spf:
        findings.append(
            _finding(
                "high",
                "SPF",
                "missing",
                f"{mail_profile.evidence}; no SPF TXT found",
                "Attackers can more easily spoof mail using this domain, and receivers have less sender authorization signal.",
                _mail_recommendation(
                    mail_profile,
                    "Publish exactly one SPF TXT record authorizing legitimate outbound mail sources.",
                ),
                f"dig TXT {domain} +short should return one v=spf1 record ending in -all or ~all.",
            )
        )
    if len(spf) > 1:
        findings.append(
            _finding(
                "high",
                "SPF",
                "multiple",
                f"{len(spf)} SPF records found",
                "Multiple SPF records cause SPF permerror at receivers, which can break legitimate mail and weaken anti-spoofing.",
                "Consolidate all mechanisms into exactly one SPF TXT record.",
                f"dig TXT {domain} +short | grep -i 'v=spf1' should print exactly one line.",
            )
        )
    findings.extend(_spf_posture_findings(domain, tuple(spf)))
    if any("+all" in value.lower() for value in spf):
        findings.append(
            _finding(
                "critical",
                "SPF",
                "unsafe",
                "SPF contains +all",
                "+all authorizes every sender on the internet and effectively disables SPF protection.",
                "Replace +all with -all or ~all after confirming all legitimate senders are included.",
                f"dig TXT {domain} +short | grep -i 'v=spf1' should not contain +all.",
            )
        )
    if any(" ptr" in value.lower() for value in spf):
        findings.append(
            _finding(
                "medium",
                "SPF",
                "weak",
                "SPF uses ptr mechanism",
                "The SPF ptr mechanism is slow, unreliable, and discouraged; it can cause lookup failures.",
                "Replace ptr with explicit ip4/ip6/include/a/mx mechanisms.",
                f"dig TXT {domain} +short | grep -i 'v=spf1' should not contain the ptr mechanism.",
            )
        )

    if mail_profile.receives_mail and not dmarc:
        findings.append(
            _finding(
                "high",
                "DMARC",
                "missing",
                f"{mail_profile.evidence}; _dmarc TXT not found",
                "Receivers lack a domain-level policy for handling failed SPF/DKIM alignment, increasing spoofing risk.",
                _mail_recommendation(
                    mail_profile,
                    "Publish DMARC with rua reporting, then move toward p=quarantine or p=reject.",
                ),
                f"dig TXT _dmarc.{domain} +short should return one v=DMARC1 record.",
            )
        )
    elif dmarc and (mail_profile.receives_mail or mail_profile.sends_mail):
        if len(dmarc) > 1:
            findings.append(
                _finding(
                    "high",
                    "DMARC",
                    "multiple",
                    f"{len(dmarc)} DMARC TXT records found",
                    "Multiple DMARC records cause receivers to ignore or error on the policy.",
                    "Publish exactly one TXT record at _dmarc with all intended DMARC tags.",
                    f"dig TXT _dmarc.{domain} +short should print exactly one v=DMARC1 record.",
                )
            )
        dmarc_text = " ".join(dmarc).lower()
        if "p=none" in dmarc_text:
            findings.append(
                _finding(
                    "medium",
                    "DMARC",
                    "monitor-only",
                    dmarc[0],
                    "DMARC is collecting reports but not asking receivers to block or quarantine spoofed mail.",
                    _mail_recommendation(
                        mail_profile,
                        "Move to p=quarantine or p=reject after confirming legitimate mail alignment.",
                    ),
                    f"dig TXT _dmarc.{domain} +short should show p=quarantine or p=reject.",
                )
            )
        if "sp=none" in dmarc_text:
            findings.append(
                _finding(
                    "low",
                    "DMARC",
                    "subdomains monitor-only",
                    dmarc[0],
                    "Subdomain mail spoofing can remain in monitoring mode even if the organizational domain is stricter.",
                    "Set sp=quarantine or sp=reject if subdomains should inherit enforcement.",
                    f"dig TXT _dmarc.{domain} +short should show an intentional sp= policy.",
                )
            )
        pct_value = _dmarc_pct(dmarc_text)
        if pct_value is not None and pct_value < 100:
            findings.append(
                _finding(
                    "low",
                    "DMARC",
                    "partial enforcement",
                    dmarc[0],
                    "Only a portion of failing messages are requested for enforcement.",
                    "Move pct to 100 after monitoring confirms legitimate mail alignment.",
                    f"dig TXT _dmarc.{domain} +short should show pct=100 or omit pct once rollout is complete.",
                )
            )
        if "rua=" not in dmarc_text:
            findings.append(
                _finding(
                    "low",
                    "DMARC",
                    "no aggregate reporting",
                    dmarc[0],
                    "You lose visibility into spoofing attempts and legitimate mail alignment failures.",
                    _mail_recommendation(
                        mail_profile,
                        "Add rua=mailto:... to receive aggregate reports.",
                    ),
                    f"dig TXT _dmarc.{domain} +short should include a rua= reporting URI.",
                )
            )
        if "ruf=" in dmarc_text:
            findings.append(
                _finding(
                    "info",
                    "DMARC forensic reports",
                    "enabled",
                    dmarc[0],
                    "Forensic reports can contain message samples or personal data depending on receiver behavior.",
                    "Confirm ruf destinations are monitored and approved for potentially sensitive report contents.",
                    f"dig TXT _dmarc.{domain} +short should only include ruf= if forensic reporting is intentional.",
                )
            )

    mta_sts = _txt_values(security.get("MTA-STS"))
    tls_rpt = _txt_values(security.get("TLS-RPT"))
    if mail_profile.receives_mail and not mta_sts:
        severity = "low" if mail_profile.management == "external-mail-provider" else "medium"
        findings.append(
            _finding(
                severity,
                "MTA-STS",
                "missing",
                f"{mail_profile.evidence}; _mta-sts TXT not found",
                "Inbound mail delivery can be downgraded to plaintext SMTP if a sender is attacked on path.",
                _mail_recommendation(
                    mail_profile,
                    "Add an MTA-STS TXT record and serve a valid HTTPS policy at /.well-known/mta-sts.txt.",
                ),
                f"dig TXT _mta-sts.{domain} +short should return v=STSv1, and https://mta-sts.{domain}/.well-known/mta-sts.txt should be valid.",
            )
        )
    elif mail_profile.receives_mail and not any(_clean_txt(value).lower().startswith("v=stsv1") for value in mta_sts):
        findings.append(
            _finding(
                "medium",
                "MTA-STS",
                "invalid marker",
                mta_sts[0],
                "Senders may ignore MTA-STS when the DNS policy marker is malformed.",
                "Publish a TXT record beginning with v=STSv1 at _mta-sts.",
                f"dig TXT _mta-sts.{domain} +short should begin with v=STSv1.",
            )
        )
    if mail_profile.receives_mail and not tls_rpt:
        findings.append(
            _finding(
                "low",
                "TLS-RPT",
                "missing",
                f"{mail_profile.evidence}; _smtp._tls TXT not found",
                "You will not receive aggregate reports about SMTP TLS failures or MTA-STS policy problems.",
                _mail_recommendation(
                    mail_profile,
                    "Add TLS-RPT with a monitored rua destination.",
                ),
                f"dig TXT _smtp._tls.{domain} +short should return v=TLSRPTv1 with rua=mailto: or rua=https:.",
            )
        )
    elif mail_profile.receives_mail:
        tls_rpt_text = " ".join(_clean_txt(value).lower() for value in tls_rpt)
        if "v=tlsrptv1" not in tls_rpt_text or "rua=" not in tls_rpt_text:
            findings.append(
                _finding(
                    "low",
                    "TLS-RPT",
                    "incomplete",
                    tls_rpt[0],
                    "SMTP TLS failure reports may not be delivered or recognized.",
                    "Publish TLS-RPT with v=TLSRPTv1 and a monitored rua destination.",
                    f"dig TXT _smtp._tls.{domain} +short should include v=TLSRPTv1 and rua=.",
                )
            )

    bimi = _txt_values(security.get("BIMI"))
    if bimi and not any(_clean_txt(value).lower().startswith("v=bimi1") for value in bimi):
        findings.append(
            _finding(
                "low",
                "BIMI",
                "invalid marker",
                bimi[0],
                "Mailbox providers may ignore malformed BIMI records.",
                "Publish BIMI TXT records beginning with v=BIMI1 only after DMARC enforcement is ready.",
                f"dig TXT default._bimi.{domain} +short should begin with v=BIMI1 when BIMI is used.",
            )
        )
    if bimi and (not dmarc or "p=none" in " ".join(dmarc).lower()):
        findings.append(
            _finding(
                "medium",
                "BIMI",
                "prereq failed",
                bimi[0],
                "Mailbox providers may ignore BIMI when DMARC is not enforced, so brand indicators will not reliably display.",
                "Enforce DMARC with p=quarantine or p=reject before relying on BIMI.",
                f"dig TXT _dmarc.{domain} +short should show p=quarantine or p=reject before BIMI is considered healthy.",
            )
        )

    cname_answers = answers.get("CNAME", ())
    for answer in cname_answers:
        target = answer.data.rstrip(".").lower()
        for provider, suffixes in TAKEOVER_PROVIDER_SUFFIXES.items():
            if any(suffix in target for suffix in suffixes):
                findings.append(
                    _finding(
                        "medium",
                        "Dangling CNAME",
                        "manual verification",
                        f"{answer.name} points to {target} ({provider})",
                        "If the target resource is unclaimed or deleted, an attacker may be able to claim it and serve content for the subdomain.",
                        "Confirm the target resource is claimed in the provider account; remove stale records.",
                        f"dig CNAME {answer.name} +short should point to a live claimed resource; provider control panel should show {answer.name.rstrip('.')} attached.",
                    )
                )

    if any(d.provider == "Cloudflare" for d in detections) and not answers.get("CAA"):
        findings.append(
            _finding(
                "low",
                "Cloudflare hygiene",
                "missing CAA",
                "Cloudflare edge detected without CAA",
                "Certificate issuance is less constrained than it could be for a proxied domain.",
                "Consider CAA records for your selected certificate authorities.",
                f"dig CAA {domain} +short should list only approved issuers.",
            )
        )

    wildcard_records = tuple(
        record
        for record in active_dns_records
        if record.category == "wildcard-dns" and record.status == "resolved"
    )
    if wildcard_records:
        findings.append(
            _finding(
                "medium",
                "Wildcard DNS",
                "enabled",
                "; ".join(f"{record.name} -> {record.value}" for record in wildcard_records[:3]),
                "Wildcard DNS can mask typos, make asset inventory noisy, and route unexpected hostnames to production services.",
                "Confirm the wildcard is intentional and that the destination safely handles unknown hostnames.",
                f"dig A definitely-not-a-real-hostname-validate.{domain} +short should return no answer unless wildcard DNS is explicitly required.",
            )
        )

    if zone_transfer_records:
        nameservers = sorted({record.source.removeprefix("AXFR ") for record in zone_transfer_records})
        findings.append(
            _finding(
                "critical",
                "Zone transfer",
                "allowed",
                f"AXFR returned records from {', '.join(nameservers)}",
                "Public zone transfers expose the zone inventory and make recon materially easier for attackers.",
                "Disable AXFR for untrusted clients on authoritative nameservers; allow transfers only from approved secondary DNS IPs with TSIG where supported.",
                f"dig AXFR {domain} @{nameservers[0]} should return Transfer failed or be refused from an untrusted network.",
            )
        )

    if origin_candidates:
        hostnames = ", ".join(candidate.hostname for candidate in origin_candidates[:5])
        edge_provider_text = ", ".join(
            sorted({candidate.edge_provider or "edge provider" for candidate in origin_candidates})
        )
        findings.append(
            _finding(
                "medium",
                "Origin exposure",
                "possible",
                f"Potential non-edge endpoints for {edge_provider_text}: {hostnames}",
                "If any candidate is a true web origin, direct access may bypass edge protections, WAF policy, rate limiting, and logging assumptions.",
                "Verify ownership of each candidate, restrict origin ingress to trusted edge/provider ranges where applicable, and remove stale direct DNS records.",
                "Confirm each candidate with asset inventory, application logs, and approved direct-origin testing before changing firewall policy; DNS/HTTP metadata alone is not proof of origin.",
            )
        )

    if not findings:
        findings.append(
            _finding(
                "info",
                "Baseline",
                "clean",
                domain,
                "No immediate impact identified by the current scanner checks.",
                "Keep monitoring DNS drift and rerun scans after DNS/provider changes.",
                f"py-dns inspect {domain} should continue to show no medium/high/critical findings.",
            )
        )
    return tuple(findings)


def collect_passive_osint(
    domain: str,
    *,
    max_subdomains: int = 100,
    timeout: float = 6.0,
) -> tuple[tuple[ReconRecord, ...], tuple[str, ...]]:
    records = list(_search_dorks(domain))
    ct_records, subdomains = _crtsh_lookup(domain, max_subdomains=max_subdomains, timeout=timeout)
    records.extend(ct_records)
    records.extend(_external_osint_sources(domain))
    return tuple(records), subdomains


def collect_active_dns_records(domain: str, timeout: float = 3.0) -> tuple[ReconRecord, ...]:
    records: list[ReconRecord] = []
    resolver = dns.resolver.Resolver()
    resolver.timeout = timeout
    resolver.lifetime = timeout
    for name, qtype, category in (
        (domain, "NS", "dig-ns"),
        (domain, "SOA", "dig-soa"),
        (domain, "TXT", "nslookup-spf"),
        (f"_dmarc.{domain}", "TXT", "nslookup-dmarc"),
    ):
        try:
            answers = resolver.resolve(name, qtype, raise_on_no_answer=False)
        except (dns.exception.DNSException, OSError) as exc:
            records.append(
                ReconRecord(
                    "system-resolver",
                    category,
                    name,
                    "",
                    "error",
                    str(exc),
                )
            )
            continue
        if not answers.rrset:
            records.append(ReconRecord("system-resolver", category, name, "", "no-answer"))
            continue
        for answer in answers:
            value = answer.to_text().strip()
            if category == "nslookup-spf" and "v=spf1" not in value.lower():
                continue
            if category == "nslookup-dmarc" and "v=dmarc1" not in value.lower():
                continue
            records.append(ReconRecord("system-resolver", category, name, value))
    wildcard_seed = sum((index + 1) * ord(char) for index, char in enumerate(domain)) % 10_000_000
    wildcard_label = f"py-dns-validation-{wildcard_seed}.{domain}"
    for qtype in ("A", "AAAA"):
        try:
            answers = resolver.resolve(wildcard_label, qtype, raise_on_no_answer=False)
        except (dns.exception.DNSException, OSError):
            continue
        if not answers.rrset:
            continue
        values = tuple(answer.to_text().strip() for answer in answers)
        if values:
            records.append(
                ReconRecord(
                    "system-resolver",
                    "wildcard-dns",
                    wildcard_label,
                    ", ".join(values),
                    "resolved",
                    f"Random validation hostname returned {qtype} answers.",
                )
            )
    return tuple(records)


def collect_origin_intelligence(domain: str, probe: HttpProbe | None) -> tuple[ReconRecord, ...]:
    records: list[ReconRecord] = []
    if probe is not None:
        if probe.title:
            encoded_title = quote_plus(probe.title)
            records.extend(
                (
                    ReconRecord(
                        "Censys",
                        "http-title-pivot",
                        domain,
                        f'https://search.censys.io/search?resource=hosts&q=services.http.response.html_title%3A"{encoded_title}"',
                        "reference",
                        "Manual pivot for hosts with the same HTTP title.",
                    ),
                    ReconRecord(
                        "URLScan",
                        "http-title-pivot",
                        domain,
                        f'https://urlscan.io/search/#{quote_plus(f"page.title:{probe.title}")}',
                        "reference",
                        "Manual pivot for indexed pages with the same title.",
                    ),
                )
            )
        records.extend(_csp_origin_records(domain, probe))
    cert_records, cert_names = _tls_certificate_records(domain)
    records.extend(cert_records)
    for cert_name in cert_names:
        records.append(
            ReconRecord(
                "Censys",
                "certificate-name-pivot",
                cert_name,
                f"https://search.censys.io/search?resource=hosts&q={quote_plus(cert_name)}",
                "reference",
                "Manual certificate/SAN reuse pivot for authorized infrastructure review.",
            )
        )
    return tuple(records)


def attempt_zone_transfers(domain: str, timeout: float = 4.0) -> tuple[ReconRecord, ...]:
    records: list[ReconRecord] = []
    resolver = dns.resolver.Resolver()
    resolver.timeout = timeout
    resolver.lifetime = timeout
    try:
        ns_answers = resolver.resolve(domain, "NS")
    except (dns.exception.DNSException, OSError):
        return ()

    for ns_answer in ns_answers:
        ns_name = ns_answer.to_text().rstrip(".")
        try:
            ns_ips = resolver.resolve(ns_name, "A")
        except (dns.exception.DNSException, OSError):
            continue
        for ns_ip in ns_ips:
            try:
                zone = dns.zone.from_xfr(
                    dns.query.xfr(str(ns_ip), domain, lifetime=timeout, relativize=False)
                )
            except (dns.exception.DNSException, OSError, EOFError):
                continue
            for name, node in zone.nodes.items():
                for rdataset in node.rdatasets:
                    records.append(
                        ReconRecord(
                            f"AXFR {ns_name}",
                            "zone-transfer",
                            name.to_text(),
                            rdataset.to_text(),
                            "allowed",
                            f"nameserver {ns_ip}",
                        )
                    )
                    if len(records) >= 500:
                        return tuple(records)
    return tuple(records)


def find_origin_candidates(
    domain: str,
    subdomains: tuple[str, ...],
    doh: DoHClient,
    *,
    detections: tuple[Detection, ...] = (),
    protected_probe: HttpProbe | None = None,
    recon_records: tuple[ReconRecord, ...] = (),
    validate_http: bool = True,
) -> tuple[OriginCandidate, ...]:
    edge_providers = _edge_providers(detections) or ("edge-provider",)
    names = _origin_candidate_names(domain, subdomains)
    names.update(
        record.name
        for record in recon_records
        if record.category == "csp-hostname" and record.name.endswith(f".{domain}")
    )

    candidates: list[OriginCandidate] = []
    direct_candidates = _origin_candidates_from_recon(edge_providers, recon_records)
    candidates.extend(direct_candidates)
    for name in sorted(names)[:80]:
        addresses: list[str] = []
        for qtype in ("A", "AAAA"):
            result = doh.lookup(name, qtype)
            if result is None or result.status != 0:
                continue
            for answer in result.answers:
                if answer.type in {1, 28} and not _is_known_edge_address(answer.data, edge_providers):
                    addresses.append(answer.data)
        if not addresses:
            continue

        validation_status = "not-tested"
        validation_evidence = ""
        if validate_http:
            candidate_probe = probe_http(name)
            validation_status, validation_evidence = _compare_origin_http_probe(
                protected_probe,
                candidate_probe,
            )

        candidates.append(
            OriginCandidate(
                name,
                tuple(sorted(set(addresses))),
                _origin_candidate_source(name, domain, subdomains),
                _origin_candidate_confidence(name, validation_status),
                _origin_candidate_evidence(edge_providers, validation_status),
                ", ".join(edge_providers),
                validation_status,
                validation_evidence,
            )
        )
    return tuple(candidates)


def _edge_providers(detections: tuple[Detection, ...]) -> tuple[str, ...]:
    return tuple(
        sorted(
            {
                detection.provider
                for detection in detections
                if detection.provider in EDGE_PROVIDERS
                or any(provider in detection.provider for provider in EDGE_PROVIDERS)
            }
        )
    )


def _origin_candidates_from_recon(
    edge_providers: tuple[str, ...],
    records: tuple[ReconRecord, ...],
) -> tuple[OriginCandidate, ...]:
    candidates: list[OriginCandidate] = []
    for record in records:
        if record.category not in {"csp-ip-leak", "certificate-ip-san"}:
            continue
        values = tuple(
            value.strip()
            for value in re.split(r"[, ]+", record.value)
            if value.strip() and _is_ip_address(value.strip())
        )
        if not values:
            continue
        candidates.append(
            OriginCandidate(
                record.name,
                tuple(sorted(set(values))),
                record.category,
                "medium",
                f"{record.category} exposed address material in {record.source}; owner validation required.",
                ", ".join(edge_providers),
                "metadata-leak",
                record.evidence,
            )
        )
    return tuple(candidates)


def _origin_candidate_names(domain: str, subdomains: tuple[str, ...]) -> set[str]:
    names = {f"{prefix}.{domain}" for prefix in ORIGIN_DISCOVERY_PREFIXES}
    for subdomain in subdomains:
        subdomain = subdomain.rstrip(".").lower()
        if not subdomain.endswith(f".{domain}"):
            continue
        labels = subdomain.removesuffix(f".{domain}").split(".")
        first_label = labels[0]
        if first_label in ORIGIN_DISCOVERY_PREFIXES or any(
            marker in first_label
            for marker in ("origin", "direct", "backend", "server", "stage", "dev", "old")
        ):
            names.add(subdomain)
        for prefix in ("origin", "direct"):
            names.add(f"{prefix}.{subdomain}")
    return names


def _origin_candidate_source(name: str, domain: str, subdomains: tuple[str, ...]) -> str:
    if name in subdomains:
        return "certificate-transparency"
    if name.endswith(f".{domain}"):
        return "dns-label-heuristic"
    return "passive-dns"


def _origin_candidate_confidence(name: str, validation_status: str) -> str:
    if validation_status == "http-similar":
        return "medium"
    if name.split(".", 1)[0] in {"origin", "direct", "backend", "www-origin"}:
        return "low-medium"
    return "low"


def _origin_candidate_evidence(edge_providers: tuple[str, ...], validation_status: str) -> str:
    provider_text = ", ".join(edge_providers)
    if validation_status == "http-similar":
        return f"Candidate resolves outside known {provider_text} edge ranges and returned similar HTTPS metadata."
    if validation_status == "http-reachable":
        return f"Candidate resolves outside known {provider_text} edge ranges and responded to HTTPS HEAD."
    return f"Candidate hostname pattern resolves outside known {provider_text} edge ranges; manual ownership validation required."


def _compare_origin_http_probe(
    protected_probe: HttpProbe | None,
    candidate_probe: HttpProbe,
) -> tuple[str, str]:
    if candidate_probe.error:
        return "http-error", candidate_probe.error
    if candidate_probe.status_code is None:
        return "not-tested", "No HTTP status returned."
    if protected_probe is None or protected_probe.status_code is None or protected_probe.error:
        return "http-reachable", f"{candidate_probe.url} returned HTTP {candidate_probe.status_code}."
    shared_headers = _shared_http_header_names(protected_probe, candidate_probe)
    if protected_probe.status_code == candidate_probe.status_code and shared_headers:
        return (
            "http-similar",
            f"Protected and candidate endpoints both returned HTTP {candidate_probe.status_code}; shared headers: {', '.join(shared_headers)}.",
        )
    if protected_probe.status_code == candidate_probe.status_code:
        return (
            "http-reachable",
            f"Protected and candidate endpoints both returned HTTP {candidate_probe.status_code}.",
        )
    return (
        "http-reachable",
        f"{candidate_probe.url} returned HTTP {candidate_probe.status_code}; protected endpoint returned HTTP {protected_probe.status_code}.",
    )


def _shared_http_header_names(left: HttpProbe, right: HttpProbe) -> tuple[str, ...]:
    left_names = {name for name, _ in left.headers}
    right_names = {name for name, _ in right.headers}
    ignored = {"date", "server", "x-cache", "cf-ray", "cf-cache-status"}
    return tuple(sorted((left_names & right_names) - ignored)[:5])


def _is_known_edge_address(value: str, providers: tuple[str, ...]) -> bool:
    try:
        addr = ip_address(value)
    except ValueError:
        return False
    for provider in providers:
        if "Cloudflare" in provider and any(addr in network for network in CLOUDFLARE_NETWORKS):
            return True
    return False


def brute_force_subdomains(
    domain: str,
    seeds: tuple[str, ...],
    doh: DoHClient,
    *,
    labels: tuple[str, ...] = DEFAULT_BRUTEFORCE_LABELS,
    max_candidates: int = 200,
) -> tuple[ReconRecord, ...]:
    domain = domain.rstrip(".").lower()
    seed_names = [domain]
    seed_names.extend(seed.rstrip(".").lower() for seed in seeds if seed.rstrip(".").lower().endswith(f".{domain}"))
    candidates: list[str] = []
    seen: set[str] = set()
    for seed in seed_names:
        for label in labels:
            label = label.strip().strip(".").lower()
            if not label:
                continue
            candidate = f"{label}.{seed}"
            if candidate in seen:
                continue
            seen.add(candidate)
            candidates.append(candidate)
            if len(candidates) >= max_candidates:
                break
        if len(candidates) >= max_candidates:
            break

    records: list[ReconRecord] = []
    for candidate in candidates:
        addresses: list[str] = []
        for qtype in ("A", "AAAA"):
            result = doh.lookup(candidate, qtype)
            if result is None or result.status != 0:
                continue
            addresses.extend(
                answer.data
                for answer in result.answers
                if answer.type in {1, 28}
            )
        if addresses:
            records.append(
                ReconRecord(
                    "bruteforce",
                    "subdomain-bruteforce",
                    candidate,
                    ", ".join(sorted(set(addresses))),
                    "resolved",
                    "Resolved from bounded label brute force seeded by gathered domains.",
                )
            )
    return tuple(records)


def classify_mail_profile(
    results: tuple[DoHResult, ...],
    security_results: tuple[DoHResult, ...],
    detections: tuple[Detection, ...],
) -> MailProfile:
    answers = _answers_by_type(results)
    security = {result.record_type: result for result in security_results}
    mx_hosts = tuple(
        target
        for answer in answers.get("MX", ())
        if (target := _mx_target(answer.data)) is not None
    )
    null_mx = bool(mx_hosts) and all(host == "." for host in mx_hosts)
    txt_values = tuple(answer.data for answer in answers.get("TXT", ()))
    spf_values = tuple(value for value in txt_values if _is_spf(value))
    dmarc_values = _txt_values(security.get("DMARC"))
    receives_mail = bool(mx_hosts) and not null_mx
    sends_mail = any("-all" not in value.lower() for value in spf_values)
    provider = _detect_mail_provider(mx_hosts)

    if null_mx:
        management = "mail-disabled"
        evidence = "Null MX advertises that the domain does not accept mail"
    elif provider:
        management = "external-mail-provider"
        evidence = f"MX delegates mail to {provider}: {', '.join(mx_hosts)}"
    elif receives_mail:
        management = "domain-mail-enabled"
        evidence = f"MX records present: {', '.join(mx_hosts)}"
    elif any(detection.provider == "Linode/Akamai Cloud" for detection in detections):
        management = "web-host-mail-out-of-scope"
        evidence = "Linode/Akamai Cloud hosting detected and no receiving-mail MX records were found"
    elif spf_values or dmarc_values:
        management = "send-only-or-policy-only"
        evidence = "Mail authentication policy exists without receiving-mail MX records"
    else:
        management = "no-mail-signals"
        evidence = "No MX, SPF, or DMARC mail signals were detected"

    return MailProfile(
        receives_mail=receives_mail,
        sends_mail=sends_mail,
        null_mx=null_mx,
        mx_hosts=mx_hosts,
        provider=provider,
        management=management,
        evidence=evidence,
    )


def probe_http(domain: str, timeout: float = 4.0) -> HttpProbe:
    url = f"https://{domain}"
    try:
        response = httpx.get(url, timeout=timeout, follow_redirects=True)
        interesting = tuple(
            (key.lower(), value)
            for key, value in response.headers.items()
            if key.lower() in HTTP_HEADER_PROVIDERS
            or key.lower().startswith(("cf-", "x-"))
            or key.lower()
            in {
                "content-security-policy",
                "content-security-policy-report-only",
                "report-to",
                "reporting-endpoints",
                "location",
            }
        )
        return HttpProbe(
            str(response.url),
            response.status_code,
            interesting,
            title=_html_title(response.text),
        )
    except httpx.HTTPError as exc:
        return HttpProbe(url, None, (), str(exc))


def _csp_origin_records(domain: str, probe: HttpProbe) -> tuple[ReconRecord, ...]:
    records: list[ReconRecord] = []
    for header, value in probe.headers:
        if header not in {
            "content-security-policy",
            "content-security-policy-report-only",
            "report-to",
            "reporting-endpoints",
        }:
            continue
        ips = tuple(sorted(set(_ip_literals(value))))
        hostnames = tuple(sorted(set(_hostnames_from_policy(value, domain))))
        if ips:
            records.append(
                ReconRecord(
                    "https-header",
                    "csp-ip-leak",
                    domain,
                    ", ".join(ips),
                    "observed",
                    f"{header} contains IP literals.",
                )
            )
        for hostname in hostnames:
            records.append(
                ReconRecord(
                    "https-header",
                    "csp-hostname",
                    hostname,
                    value[:160],
                    "observed",
                    f"{header} references hostname that may be worth DNS validation.",
                )
            )
    return tuple(records)


def _tls_certificate_records(domain: str, timeout: float = 4.0) -> tuple[tuple[ReconRecord, ...], tuple[str, ...]]:
    try:
        context = ssl.create_default_context()
        with (
            socket.create_connection((domain, 443), timeout=timeout) as raw_sock,
            context.wrap_socket(raw_sock, server_hostname=domain) as tls_sock,
        ):
            cert = tls_sock.getpeercert()
    except (OSError, ssl.SSLError, ValueError):
        return (), ()

    names: list[str] = []
    ips: list[str] = []
    for key, value in cert.get("subjectAltName", ()):
        normalized = str(value).strip().lower().lstrip("*.").rstrip(".")
        if not normalized:
            continue
        if key.lower() == "dns":
            names.append(normalized)
        elif key.lower() == "ip address":
            ips.append(normalized)

    records: list[ReconRecord] = []
    if names:
        records.append(
            ReconRecord(
                "tls-certificate",
                "certificate-san",
                domain,
                ", ".join(sorted(set(names))[:50]),
                "observed",
                "SubjectAltName DNS entries from the presented certificate.",
            )
        )
    if ips:
        records.append(
            ReconRecord(
                "tls-certificate",
                "certificate-ip-san",
                domain,
                ", ".join(sorted(set(ips))),
                "observed",
                "SubjectAltName IP address entries from the presented certificate.",
            )
        )
    return tuple(records), tuple(sorted(set(names)))


def _html_title(text: str) -> str | None:
    match = re.search(r"<title[^>]*>(.*?)</title>", text, re.IGNORECASE | re.DOTALL)
    if not match:
        return None
    title = re.sub(r"\s+", " ", unescape(match.group(1))).strip()
    return title[:160] or None


def _ip_literals(value: str) -> tuple[str, ...]:
    candidates = re.findall(
        r"(?<![\w:])(?:\d{1,3}\.){3}\d{1,3}(?![\w.])|(?<![\w:])(?:[a-f0-9]{0,4}:){2,}[a-f0-9]{0,4}(?![\w:])",
        value,
        re.IGNORECASE,
    )
    return tuple(candidate for candidate in candidates if _is_ip_address(candidate))


def _hostnames_from_policy(value: str, domain: str) -> tuple[str, ...]:
    hosts: list[str] = []
    for match in re.findall(r"https?://([^/\s;,\"]+)|\b([A-Za-z0-9_.-]+\.[A-Za-z]{2,})\b", value):
        host = (match[0] or match[1]).split(":", 1)[0].strip().lower().lstrip("*.").rstrip(".")
        if host and host != domain and host.endswith(f".{domain}"):
            hosts.append(host)
    return tuple(hosts)


def _is_ip_address(value: str) -> bool:
    try:
        ip_address(value)
    except ValueError:
        return False
    return True


def _address_posture_findings(domain: str, addresses: tuple[DoHAnswer, ...]) -> list[Finding]:
    findings: list[Finding] = []
    for answer in addresses:
        try:
            address = ip_address(answer.data)
        except ValueError:
            continue
        if address.is_private or address.is_loopback or address.is_link_local or address.is_multicast:
            findings.append(
                _finding(
                    "high",
                    "Public address hygiene",
                    "non-public address",
                    f"{answer.name} returns {answer.data}",
                    "Public DNS that returns private, loopback, link-local, or multicast addresses can leak internal naming assumptions and break clients outside the private network.",
                    "Remove the record from public DNS or split-horizon it so only trusted internal resolvers return internal addresses.",
                    f"dig A {domain} +short and dig AAAA {domain} +short from an external network should not return private or special-use addresses.",
                )
            )
    return findings


def _nameserver_posture_findings(domain: str, ns_answers: tuple[DoHAnswer, ...]) -> list[Finding]:
    if len(ns_answers) == 1:
        return [
            _finding(
                "medium",
                "Nameserver redundancy",
                "single nameserver",
                ns_answers[0].data,
                "A single authoritative nameserver creates an avoidable DNS availability dependency.",
                "Publish at least two authoritative nameservers on independent infrastructure where your DNS provider supports it.",
                f"dig NS {domain} +short should return two or more expected authoritative nameservers.",
            )
        ]
    if len(ns_answers) > 1 and len({_registrable_hint(answer.data) for answer in ns_answers}) == 1:
        return [
            _finding(
                "low",
                "Nameserver diversity",
                "same provider suffix",
                ", ".join(answer.data for answer in ns_answers),
                "Nameservers appear concentrated under one provider suffix; this is common for managed DNS, but it is still a provider availability dependency.",
                "Decide whether single-provider managed DNS is acceptable for the domain's availability requirements.",
                f"dig NS {domain} +short should match the approved DNS architecture and provider inventory.",
            )
        ]
    return []


def _soa_posture_findings(domain: str, soa_answers: tuple[DoHAnswer, ...]) -> list[Finding]:
    findings: list[Finding] = []
    for soa in soa_answers[:1]:
        parts = soa.data.split()
        if len(parts) < 7:
            continue
        try:
            refresh, retry, expire, minimum = (int(parts[index]) for index in (3, 4, 5, 6))
        except ValueError:
            continue
        if expire < 604800:
            findings.append(
                _finding(
                    "low",
                    "SOA timers",
                    "short expire",
                    soa.data,
                    "Secondary nameservers may stop serving the zone quickly during an upstream outage.",
                    "Review SOA expire/refresh/retry values against your DNS provider's recommended defaults.",
                    f"dig SOA {domain} +short should show an expire value appropriate for the zone, commonly at least several days.",
                )
            )
        if minimum > 86400:
            findings.append(
                _finding(
                    "low",
                    "Negative caching",
                    "long SOA minimum",
                    soa.data,
                    "NXDOMAIN or no-data mistakes can persist at resolvers longer than intended.",
                    "Lower the SOA minimum/negative TTL if operational rollback speed matters.",
                    f"dig SOA {domain} +short should show a negative cache TTL aligned with your change process.",
                )
            )
        if retry >= refresh:
            findings.append(
                _finding(
                    "low",
                    "SOA timers",
                    "retry not below refresh",
                    soa.data,
                    "Secondary nameserver retry behavior may be slower than intended after failed refreshes.",
                    "Set retry lower than refresh unless the DNS provider manages these values for you.",
                    f"dig SOA {domain} +short should show retry lower than refresh.",
                )
            )
    return findings


def _ttl_posture_findings(domain: str, results: tuple[DoHResult, ...]) -> list[Finding]:
    findings: list[Finding] = []
    for result in results:
        if result.record_type not in {"A", "AAAA", "CNAME", "MX", "NS"} or not result.answers:
            continue
        ttl = result.min_ttl
        if 0 < ttl < 60:
            findings.append(
                _finding(
                    "low",
                    "TTL",
                    "very low",
                    f"{result.record_type} minimum TTL is {ttl}",
                    "Very low TTLs increase resolver load and can make transient DNS provider issues more visible to clients.",
                    "Use very low TTLs only during planned migrations; otherwise raise TTLs to an operationally reasonable value.",
                    f"dig {result.record_type} {domain} +ttlunits should show the intended TTL after propagation.",
                )
            )
        elif ttl > 86400:
            findings.append(
                _finding(
                    "low",
                    "TTL",
                    "very high",
                    f"{result.record_type} minimum TTL is {ttl}",
                    "Very high TTLs slow incident response and rollback when a record is wrong or a provider migration is needed.",
                    "Lower TTLs ahead of migrations and keep production TTLs aligned with your rollback expectations.",
                    f"dig {result.record_type} {domain} +ttlunits should show a TTL that matches the change-management plan.",
                )
            )
    return findings


def _caa_posture_findings(domain: str, caa_answers: tuple[DoHAnswer, ...]) -> list[Finding]:
    values = tuple(answer.data.lower() for answer in caa_answers)
    findings: list[Finding] = []
    if not any("issuewild" in value for value in values):
        findings.append(
            _finding(
                "low",
                "CAA wildcard policy",
                "not constrained",
                "CAA records exist, but no issuewild tag was found",
                "Wildcard certificate issuance may be less explicit than intended.",
                "Add issuewild records that either authorize the expected CA or deny wildcard issuance with issuewild ';'.",
                f"dig CAA {domain} +short should show an intentional issuewild policy.",
            )
        )
    if any("iodef" in value and "mailto:" not in value and "https:" not in value for value in values):
        findings.append(
            _finding(
                "low",
                "CAA reporting",
                "unusual iodef",
                "; ".join(values),
                "CAA incident reporting may not reach a monitored destination.",
                "Use mailto: or https: iodef destinations that route to a monitored security mailbox or endpoint.",
                f"dig CAA {domain} +short should show monitored iodef destinations if CAA reporting is used.",
            )
        )
    return findings


def _spf_posture_findings(domain: str, spf_values: tuple[str, ...]) -> list[Finding]:
    findings: list[Finding] = []
    for value in spf_values:
        normalized = f" {_clean_txt(value).lower()} "
        if not any(term in normalized for term in (" -all ", " ~all ", " ?all ", " +all ")):
            findings.append(
                _finding(
                    "medium",
                    "SPF",
                    "missing all mechanism",
                    value,
                    "Receivers may treat the SPF policy as neutral or malformed, reducing sender authorization value.",
                    "End the SPF record with an intentional all mechanism, usually -all after all legitimate senders are authorized.",
                    f"dig TXT {domain} +short | grep -i 'v=spf1' should show exactly one SPF record with an all mechanism.",
                )
            )
        if " ?all " in normalized:
            findings.append(
                _finding(
                    "low",
                    "SPF",
                    "neutral all",
                    value,
                    "?all tells receivers to make no SPF authorization decision for non-matching senders.",
                    "Use ~all during transition or -all once legitimate sources are known.",
                    f"dig TXT {domain} +short | grep -i 'v=spf1' should not end with ?all unless that is intentional.",
                )
            )
        lookup_count = _spf_dns_lookup_count(value)
        if lookup_count > 10:
            findings.append(
                _finding(
                    "high",
                    "SPF",
                    "too many DNS lookups",
                    f"{lookup_count} estimated lookup mechanisms in {value}",
                    "SPF evaluation can return permerror when the DNS lookup limit is exceeded, causing legitimate mail failures and weaker anti-spoofing.",
                    "Flatten or reduce include/a/mx/ptr/exists/redirect mechanisms until the SPF policy stays under the 10 lookup limit.",
                    f"Use a dedicated SPF checker or expand includes to confirm {domain}'s SPF record stays within the 10 lookup limit.",
                )
            )
        if len(value) > 255:
            findings.append(
                _finding(
                    "medium",
                    "SPF",
                    "long TXT segment risk",
                    f"{len(value)} characters",
                    "Long SPF records are often split incorrectly by DNS control panels, which can break SPF parsing.",
                    "Confirm TXT string segmentation in the authoritative DNS provider or reduce the SPF record length.",
                    f"dig TXT {domain} +short should return one syntactically valid SPF record as interpreted by receivers.",
                )
            )
    return findings


def _spf_dns_lookup_count(value: str) -> int:
    count = 0
    for token in _clean_txt(value).lower().split():
        mechanism = token.lstrip("+-~?")
        if mechanism in {"a", "mx", "ptr"} or mechanism.startswith(("include:", "a:", "mx:", "exists:", "redirect=")):
            count += 1
    return count


def _dmarc_pct(value: str) -> int | None:
    for part in value.split(";"):
        key, _, raw_value = part.strip().partition("=")
        if key == "pct":
            try:
                return int(raw_value.strip().strip('"'))
            except ValueError:
                return None
    return None


def _registrable_hint(name: str) -> str:
    labels = name.rstrip(".").lower().split(".")
    return ".".join(labels[-2:]) if len(labels) >= 2 else name.rstrip(".").lower()


def _clean_txt(value: str) -> str:
    return value.strip().strip('"')


def _mail_recommendation(mail_profile: MailProfile, recommendation: str) -> str:
    if mail_profile.management == "external-mail-provider" and mail_profile.provider:
        return f"{recommendation} This is a {mail_profile.provider}/DNS configuration item, not a web-server or Linode host finding."
    if mail_profile.management == "web-host-mail-out-of-scope":
        return f"{recommendation} Treat this as DNS/mail policy only; do not configure mail services on the web host."
    return recommendation


def _finding(
    severity: str,
    check: str,
    status: str,
    evidence: str,
    impact: str,
    recommendation: str,
    validation: str,
) -> Finding:
    return Finding(
        severity=severity,
        check=check,
        status=status,
        evidence=evidence,
        impact=impact,
        recommendation=recommendation,
        validation=validation,
    )


def format_inspection(inspection: Inspection) -> str:
    lines = [f";; py-dns inspection for {inspection.domain}", ""]
    if not inspection.all_results:
        lines.append(";; no DNS responses from configured DoH upstreams")
        lines.append(";; detections: none")
        lines.append("")
        _append_plain_recon(lines, inspection)
        lines.extend(_format_findings(inspection.findings))
        return "\n".join(lines).rstrip()

    for result in inspection.all_results:
        status = _rcode_name(result.status)
        flag_text = _flag_text(result)
        lines.append(f";; {result.record_type} via {result.upstream}: {status}{flag_text}")
        if not result.answers:
            lines.append(";;   no answers")
            continue
        for answer in result.answers:
            lines.append(
                f"{answer.name:<36} {answer.ttl:<6} IN {TYPE_NAME.get(answer.type, answer.type)!s:<8} {answer.data}"
            )
        lines.append("")

    if inspection.detections:
        lines.append(";; detections")
        for detection in inspection.detections:
            lines.append(f";;   {detection.provider}: {detection.reason} [{detection.confidence}]")
    else:
        lines.append(";; detections: none")

    lines.append("")
    if inspection.mail_profile:
        lines.append(";; mail profile")
        lines.append(f";;   management: {inspection.mail_profile.management}")
        lines.append(f";;   provider: {inspection.mail_profile.provider or '-'}")
        lines.append(f";;   receives_mail: {inspection.mail_profile.receives_mail}")
        lines.append(f";;   evidence: {inspection.mail_profile.evidence}")
        lines.append("")
    _append_plain_recon(lines, inspection)
    lines.extend(_format_findings(inspection.findings))
    return "\n".join(lines).rstrip()


def _format_findings(findings: tuple[Finding, ...]) -> list[str]:
    lines = [";; findings"]
    for finding in findings:
        lines.append(f";;   {finding.severity.upper():<8} {finding.check}: {finding.status} - {finding.evidence}")
        lines.append(f";;            impact: {finding.impact}")
        lines.append(f";;            remediate: {finding.recommendation}")
        lines.append(f";;            validate: {finding.validation}")
    return lines


def _append_plain_recon(lines: list[str], inspection: Inspection) -> None:
    if inspection.subdomains:
        lines.append(";; subdomains")
        for subdomain in inspection.subdomains[:50]:
            lines.append(f";;   {subdomain}")
        if len(inspection.subdomains) > 50:
            lines.append(f";;   ... {len(inspection.subdomains) - 50} more")
        lines.append("")
    if inspection.origin_candidates:
        lines.append(";; passive origin exposure candidates")
        for candidate in inspection.origin_candidates:
            validation = (
                f"; validation={candidate.validation_status} ({candidate.validation_evidence})"
                if candidate.validation_evidence
                else f"; validation={candidate.validation_status}"
            )
            lines.append(
                f";;   {candidate.hostname}: {', '.join(candidate.addresses)} "
                f"[{candidate.confidence}; provider={candidate.edge_provider or '-'}{validation}]"
            )
        lines.append("")
    if inspection.zone_transfer_records:
        lines.append(";; zone transfer")
        lines.append(f";;   AXFR returned {len(inspection.zone_transfer_records)} records")
        lines.append("")


def _lookup_security_records(doh: DoHClient, domain: str) -> tuple[DoHResult, ...]:
    results = []
    for name, (template, record_type) in SECURITY_RECORD_QUERIES.items():
        result = doh.lookup(template.format(domain=domain), record_type)
        if result is not None:
            results.append(
                DoHResult(
                    domain=result.domain,
                    record_type=name,
                    upstream=result.upstream,
                    status=result.status,
                    answers=result.answers,
                    authenticated_data=result.authenticated_data,
                    recursion_available=result.recursion_available,
                    checking_disabled=result.checking_disabled,
                )
            )
    return tuple(results)


def _mx_target(value: str) -> str | None:
    parts = value.strip().strip('"').split()
    if not parts:
        return None
    target = parts[-1].rstrip(".").lower()
    return "." if target == "" else target


def _is_spf(value: str) -> bool:
    return value.strip().strip('"').lower().startswith("v=spf1")


def _detect_mail_provider(mx_hosts: tuple[str, ...]) -> str | None:
    for host in mx_hosts:
        if host == ".":
            continue
        for provider, suffixes in MAIL_PROVIDER_SUFFIXES.items():
            if any(_matches_suffix(host, suffix) for suffix in suffixes):
                return provider
    return None


def _search_dorks(domain: str) -> tuple[ReconRecord, ...]:
    queries = (
        ("google", f'site:{domain} -www.{domain}'),
        ("google", f'site:*.{domain} -www.{domain}'),
        ("bing", f'site:{domain} -www.{domain}'),
        ("yahoo", f'site:{domain} -www.{domain}'),
    )
    base_urls = {
        "google": "https://www.google.com/search?q=",
        "bing": "https://www.bing.com/search?q=",
        "yahoo": "https://search.yahoo.com/search?p=",
    }
    return tuple(
        ReconRecord(
            engine,
            "search-dork",
            query,
            f"{base_urls[engine]}{quote_plus(query)}",
            "reference",
            "Manual search URL; search engines generally block reliable automated scraping.",
        )
        for engine, query in queries
    )


def _crtsh_lookup(
    domain: str,
    *,
    max_subdomains: int,
    timeout: float,
) -> tuple[tuple[ReconRecord, ...], tuple[str, ...]]:
    url = f"https://crt.sh/?q=%25.{domain}&output=json"
    try:
        response = httpx.get(url, timeout=timeout, follow_redirects=True)
        response.raise_for_status()
        rows = response.json()
    except (httpx.HTTPError, ValueError, TypeError) as exc:
        return (
            (
                ReconRecord(
                    "crt.sh",
                    "certificate-transparency",
                    domain,
                    url,
                    "error",
                    str(exc),
                ),
            ),
            (),
        )

    names: set[str] = set()
    for row in rows if isinstance(rows, list) else []:
        raw_names = str(row.get("name_value", ""))
        for raw_name in raw_names.splitlines():
            name = raw_name.lower().strip().lstrip("*.").rstrip(".")
            if name == domain or name.endswith(f".{domain}"):
                names.add(name)
    subdomains = tuple(sorted(names - {domain}))[:max_subdomains]
    records = tuple(
        ReconRecord("crt.sh", "certificate-transparency", subdomain, "certificate subject/SAN")
        for subdomain in subdomains
    )
    return records, subdomains


def _external_osint_sources(domain: str) -> tuple[ReconRecord, ...]:
    return (
        ReconRecord(
            "VirusTotal",
            "external-osint",
            domain,
            f"https://www.virustotal.com/gui/domain/{domain}/relations",
            "reference",
            "API-key backed enrichment can be added later; URL included for manual authorized review.",
        ),
        ReconRecord(
            "DNSDumpster",
            "external-osint",
            domain,
            "https://dnsdumpster.com/",
            "reference",
            "Interactive service; no stable public API is used by this tool.",
        ),
        ReconRecord(
            "Netcraft",
            "external-osint",
            domain,
            f"https://searchdns.netcraft.com/?restriction=site+contains&host={quote_plus(domain)}",
            "reference",
            "Manual OSINT pivot for hosting and certificate observations.",
        ),
        ReconRecord(
            "Censys",
            "external-osint",
            domain,
            f"https://search.censys.io/search?resource=hosts&q={quote_plus(domain)}",
            "reference",
            "Manual host/certificate/header pivot for authorized origin exposure review.",
        ),
        ReconRecord(
            "URLScan",
            "external-osint",
            domain,
            f"https://urlscan.io/search/#{quote_plus(f'domain:{domain}')}",
            "reference",
            "Manual URLScan pivot for page titles, requests, CSP, and related hostnames.",
        ),
    )


def _answers_by_type(results: tuple[DoHResult, ...]) -> dict[str, tuple[DoHAnswer, ...]]:
    output: dict[str, list[DoHAnswer]] = {}
    for result in results:
        for answer in result.answers:
            output.setdefault(TYPE_NAME.get(answer.type, str(answer.type)), []).append(answer)
    return {key: tuple(value) for key, value in output.items()}


def _txt_values(result: DoHResult | None) -> tuple[str, ...]:
    if result is None:
        return ()
    return tuple(answer.data.strip() for answer in result.answers if answer.type == 16)


def _detect_by_suffix(answer: DoHAnswer, detections: dict[tuple[str, str], Detection]) -> None:
    value = answer.data.rstrip(".").lower()
    for provider, suffixes in PROVIDER_SUFFIXES.items():
        for suffix in suffixes:
            if _matches_suffix(value, suffix):
                reason = f"{TYPE_NAME.get(answer.type, answer.type)} references {suffix}"
                detections.setdefault(
                    (provider, reason),
                    Detection(provider, reason, "dns", "high"),
                )


def _detect_cloudflare_ip(answer: DoHAnswer, detections: dict[tuple[str, str], Detection]) -> None:
    if answer.type not in {1, 28}:
        return
    if _is_cloudflare_address(answer.data):
        reason = f"{answer.data} is in a published Cloudflare range"
        detections.setdefault(("Cloudflare", reason), Detection("Cloudflare", reason, "ip", "high"))


def _is_cloudflare_address(value: str) -> bool:
    try:
        addr = ip_address(value)
    except ValueError:
        return False
    return any(addr in network for network in CLOUDFLARE_NETWORKS)


def _detect_http_headers(probe: HttpProbe, detections: dict[tuple[str, str], Detection]) -> None:
    for key, value in probe.headers:
        provider = HTTP_HEADER_PROVIDERS.get(key)
        if not provider:
            continue
        lower_value = value.lower()
        if key == "server":
            if "cloudflare" in lower_value:
                provider = "Cloudflare"
            elif "akamai" in lower_value:
                provider = "Akamai"
            elif "cloudfront" in lower_value:
                provider = "AWS CloudFront"
            elif "fastly" in lower_value:
                provider = "Fastly"
            elif "bunny" in lower_value:
                provider = "Bunny"
            elif "gcore" in lower_value:
                provider = "Gcore"
            elif "imperva" in lower_value or "incapsula" in lower_value:
                provider = "Imperva"
            elif "google" in lower_value:
                provider = "Google"
            else:
                continue
        reason = f"HTTP header {key}: {value[:80]}"
        detections.setdefault((provider, reason), Detection(provider, reason, "http", "medium"))


def _matches_suffix(value: str, suffix: str) -> bool:
    suffix = suffix.lower()
    if suffix.startswith("dns1.p"):
        return value.startswith(suffix)
    return value == suffix or value.endswith(f".{suffix}") or suffix in value


def _flag_text(result: DoHResult) -> str:
    flags = []
    if result.authenticated_data:
        flags.append("ad")
    if result.recursion_available:
        flags.append("ra")
    if result.checking_disabled:
        flags.append("cd")
    return f" flags={','.join(flags)}" if flags else ""


def _rcode_name(status: int) -> str:
    return {
        0: "NOERROR",
        1: "FORMERR",
        2: "SERVFAIL",
        3: "NXDOMAIN",
        4: "NOTIMP",
        5: "REFUSED",
    }.get(status, f"RCODE-{status}")
