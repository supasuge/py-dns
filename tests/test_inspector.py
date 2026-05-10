from py_dns.doh import DoHAnswer, DoHResult
from py_dns.inspector import (
    Inspection,
    OriginCandidate,
    ReconRecord,
    analyze_security,
    brute_force_subdomains,
    classify_mail_profile,
    detect_services,
    format_inspection,
)


def test_detects_cloudflare_by_ip_range_and_cname() -> None:
    result = DoHResult(
        domain="example.com",
        record_type="A",
        upstream="test",
        status=0,
        answers=(
            DoHAnswer("example.com.", 1, 300, "104.16.1.2"),
            DoHAnswer("www.example.com.", 5, 300, "target.cdn.cloudflare.net."),
        ),
        authenticated_data=True,
        recursion_available=True,
        checking_disabled=False,
    )

    detections = detect_services((result,))

    assert any(detection.provider == "Cloudflare" for detection in detections)


def test_detects_common_cdn_and_platform_suffixes() -> None:
    result = DoHResult(
        domain="www.example.com",
        record_type="CNAME",
        upstream="test",
        status=0,
        answers=(
            DoHAnswer("www.example.com.", 5, 300, "dualstack.example.cloudfront.net."),
            DoHAnswer("app.example.com.", 5, 300, "cname.vercel-dns-0.com."),
            DoHAnswer("cdn.example.com.", 5, 300, "example.map.fastly.net."),
        ),
        authenticated_data=False,
        recursion_available=True,
        checking_disabled=False,
    )

    providers = {detection.provider for detection in detect_services((result,))}

    assert {"AWS CloudFront", "Vercel", "Fastly"}.issubset(providers)


def test_detects_linode_dns_provider_context() -> None:
    result = DoHResult(
        domain="example.com",
        record_type="NS",
        upstream="test",
        status=0,
        answers=(DoHAnswer("example.com.", 2, 300, "ns1.linode.com."),),
        authenticated_data=False,
        recursion_available=True,
        checking_disabled=False,
    )

    providers = {detection.provider for detection in detect_services((result,))}

    assert "Linode/Akamai Cloud" in providers


def test_format_inspection_includes_dnssec_and_detection() -> None:
    result = DoHResult(
        domain="example.com",
        record_type="A",
        upstream="test",
        status=0,
        answers=(DoHAnswer("example.com.", 1, 300, "104.16.1.2"),),
        authenticated_data=True,
        recursion_available=True,
        checking_disabled=False,
    )

    output = format_inspection(
        Inspection("example.com", (result,), (), detect_services((result,)), ())
    )

    assert "flags=ad,ra" in output
    assert "Cloudflare" in output


def test_security_findings_flag_missing_email_auth_and_caa() -> None:
    base = (
        DoHResult(
            domain="example.com",
            record_type="MX",
            upstream="test",
            status=0,
            answers=(DoHAnswer("example.com.", 15, 300, "10 mail.example.com."),),
            authenticated_data=False,
            recursion_available=True,
            checking_disabled=False,
        ),
    )

    findings = analyze_security("example.com", base, (), ())
    checks = {finding.check: finding.status for finding in findings}

    assert checks["SPF"] == "missing"
    assert checks["DMARC"] == "missing"
    assert checks["CAA"] == "missing"


def test_external_mail_provider_context_downgrades_hosting_assumptions() -> None:
    results = (
        DoHResult(
            domain="example.com",
            record_type="MX",
            upstream="test",
            status=0,
            answers=(DoHAnswer("example.com.", 15, 300, "10 mail.protonmail.ch."),),
            authenticated_data=False,
            recursion_available=True,
            checking_disabled=False,
        ),
        DoHResult(
            domain="example.com",
            record_type="TXT",
            upstream="test",
            status=0,
            answers=(DoHAnswer("example.com.", 16, 300, '"v=spf1 include:_spf.protonmail.ch ~all"'),),
            authenticated_data=False,
            recursion_available=True,
            checking_disabled=False,
        ),
    )
    security = (
        DoHResult(
            domain="_dmarc.example.com",
            record_type="DMARC",
            upstream="test",
            status=0,
            answers=(DoHAnswer("_dmarc.example.com.", 16, 300, '"v=DMARC1; p=quarantine"'),),
            authenticated_data=False,
            recursion_available=True,
            checking_disabled=False,
        ),
    )

    mail_profile = classify_mail_profile(results, security, ())
    findings = analyze_security("example.com", results, security, (), mail_profile=mail_profile)
    by_check = {finding.check: finding for finding in findings}

    assert mail_profile.management == "external-mail-provider"
    assert mail_profile.provider == "Proton Mail"
    assert "SPF" not in by_check
    assert by_check["MTA-STS"].severity == "low"
    assert "not a web-server or Linode host finding" in by_check["MTA-STS"].recommendation


def test_null_mx_does_not_emit_missing_mail_provider_findings() -> None:
    results = (
        DoHResult(
            domain="example.com",
            record_type="MX",
            upstream="test",
            status=0,
            answers=(DoHAnswer("example.com.", 15, 300, "0 ."),),
            authenticated_data=False,
            recursion_available=True,
            checking_disabled=False,
        ),
        DoHResult(
            domain="example.com",
            record_type="TXT",
            upstream="test",
            status=0,
            answers=(DoHAnswer("example.com.", 16, 300, '"v=spf1 -all"'),),
            authenticated_data=False,
            recursion_available=True,
            checking_disabled=False,
        ),
    )

    security = (
        DoHResult(
            domain="_dmarc.example.com",
            record_type="DMARC",
            upstream="test",
            status=0,
            answers=(DoHAnswer("_dmarc.example.com.", 16, 300, '"v=DMARC1;p=reject"'),),
            authenticated_data=False,
            recursion_available=True,
            checking_disabled=False,
        ),
    )

    findings = analyze_security("example.com", results, security, ())
    checks = {finding.check for finding in findings}

    assert "SPF" not in checks
    assert "DMARC" not in checks
    assert "MTA-STS" not in checks
    assert "TLS-RPT" not in checks


def test_findings_include_impact_remediation_and_validation() -> None:
    findings = analyze_security("example.com", (), (), ())

    assert findings
    assert all(finding.impact for finding in findings)
    assert all(finding.recommendation for finding in findings)
    assert all(finding.validation for finding in findings)

    output = format_inspection(Inspection("example.com", (), (), (), findings))

    assert "impact:" in output
    assert "remediate:" in output
    assert "validate:" in output


def test_security_findings_flag_zone_transfer_and_origin_candidates() -> None:
    findings = analyze_security(
        "example.com",
        (),
        (),
        (),
        zone_transfer_records=(
            ReconRecord("AXFR ns1.example.com", "zone-transfer", "www.example.com.", "A 192.0.2.10"),
        ),
        origin_candidates=(
            OriginCandidate(
                "origin.example.com",
                ("192.0.2.20",),
                "passive-dns",
                "low",
                "test evidence",
            ),
        ),
    )
    checks = {finding.check: finding.status for finding in findings}

    assert checks["Zone transfer"] == "allowed"
    assert checks["Origin exposure"] == "possible"


def test_plain_format_includes_recon_sections() -> None:
    inspection = Inspection(
        "example.com",
        (),
        (),
        (),
        (),
        None,
        (ReconRecord("crt.sh", "certificate-transparency", "www.example.com", "certificate"),),
        ("www.example.com",),
        (),
        (
            OriginCandidate(
                "origin.example.com",
                ("192.0.2.20",),
                "passive-dns",
                "low",
                "test evidence",
            ),
        ),
    )

    output = format_inspection(inspection)

    assert "subdomains" in output
    assert "passive origin exposure candidates" in output


class FakeDoHClient:
    def lookup(self, domain: str, record_type: str = "A") -> DoHResult | None:
        if domain == "api.example.com" and record_type == "A":
            return DoHResult(
                domain=domain,
                record_type=record_type,
                upstream="test",
                status=0,
                answers=(DoHAnswer("api.example.com.", 1, 300, "192.0.2.10"),),
                authenticated_data=False,
                recursion_available=True,
                checking_disabled=False,
            )
        return DoHResult(
            domain=domain,
            record_type=record_type,
            upstream="test",
            status=3,
            answers=(),
            authenticated_data=False,
            recursion_available=True,
            checking_disabled=False,
        )


def test_bruteforce_subdomains_returns_resolved_candidates_only() -> None:
    records = brute_force_subdomains(
        "example.com",
        (),
        FakeDoHClient(),  # type: ignore[arg-type]
        labels=("api", "dev"),
        max_candidates=5,
    )

    assert len(records) == 1
    assert records[0].name == "api.example.com"
    assert records[0].value == "192.0.2.10"
