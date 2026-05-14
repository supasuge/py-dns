from py_dns.doh import DoHAnswer, DoHResult
from py_dns.inspector import (
    Detection,
    HttpProbe,
    Inspection,
    OriginCandidate,
    ReconRecord,
    analyze_security,
    brute_force_subdomains,
    classify_mail_profile,
    collect_origin_intelligence,
    detect_services,
    find_origin_candidates,
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


def test_security_findings_flag_dns_posture_misconfigurations() -> None:
    results = (
        DoHResult(
            domain="example.com",
            record_type="A",
            upstream="test",
            status=0,
            answers=(DoHAnswer("example.com.", 1, 30, "10.0.0.5"),),
            authenticated_data=False,
            recursion_available=True,
            checking_disabled=False,
        ),
        DoHResult(
            domain="example.com",
            record_type="NS",
            upstream="test",
            status=0,
            answers=(DoHAnswer("example.com.", 2, 300, "ns1.example.net."),),
            authenticated_data=False,
            recursion_available=True,
            checking_disabled=False,
        ),
        DoHResult(
            domain="example.com",
            record_type="SOA",
            upstream="test",
            status=0,
            answers=(
                DoHAnswer(
                    "example.com.",
                    6,
                    300,
                    "ns1.example.net. hostmaster.example.com. 1 3600 7200 86400 172800",
                ),
            ),
            authenticated_data=False,
            recursion_available=True,
            checking_disabled=False,
        ),
    )

    findings = analyze_security("example.com", results, (), ())
    checks = {finding.check: finding.status for finding in findings}

    assert checks["Public address hygiene"] == "non-public address"
    assert checks["Nameserver redundancy"] == "single nameserver"
    assert checks["SOA timers"] == "retry not below refresh"
    assert checks["Negative caching"] == "long SOA minimum"
    assert checks["TTL"] == "very low"


def test_security_findings_flag_richer_mail_policy_issues() -> None:
    results = (
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
        DoHResult(
            domain="example.com",
            record_type="TXT",
            upstream="test",
            status=0,
            answers=(
                DoHAnswer(
                    "example.com.",
                    16,
                    300,
                    '"v=spf1 include:a.example include:b.example include:c.example include:d.example include:e.example include:f.example include:g.example include:h.example include:i.example include:j.example include:k.example ?all"',
                ),
            ),
            authenticated_data=False,
            recursion_available=True,
            checking_disabled=False,
        ),
        DoHResult(
            domain="example.com",
            record_type="CAA",
            upstream="test",
            status=0,
            answers=(DoHAnswer("example.com.", 257, 300, '0 issue "letsencrypt.org"'),),
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
            answers=(DoHAnswer("_dmarc.example.com.", 16, 300, '"v=DMARC1; p=none; sp=none; pct=50"'),),
            authenticated_data=False,
            recursion_available=True,
            checking_disabled=False,
        ),
        DoHResult(
            domain="_mta-sts.example.com",
            record_type="MTA-STS",
            upstream="test",
            status=0,
            answers=(DoHAnswer("_mta-sts.example.com.", 16, 300, '"bad=marker"'),),
            authenticated_data=False,
            recursion_available=True,
            checking_disabled=False,
        ),
        DoHResult(
            domain="_smtp._tls.example.com",
            record_type="TLS-RPT",
            upstream="test",
            status=0,
            answers=(DoHAnswer("_smtp._tls.example.com.", 16, 300, '"v=TLSRPTv1"'),),
            authenticated_data=False,
            recursion_available=True,
            checking_disabled=False,
        ),
    )

    findings = analyze_security("example.com", results, security, ())
    statuses = {(finding.check, finding.status) for finding in findings}

    assert ("CAA wildcard policy", "not constrained") in statuses
    assert ("SPF", "neutral all") in statuses
    assert ("SPF", "too many DNS lookups") in statuses
    assert ("DMARC", "monitor-only") in statuses
    assert ("DMARC", "subdomains monitor-only") in statuses
    assert ("DMARC", "partial enforcement") in statuses
    assert ("MTA-STS", "invalid marker") in statuses
    assert ("TLS-RPT", "incomplete") in statuses


def test_security_findings_flag_wildcard_dns_validation_record() -> None:
    findings = analyze_security(
        "example.com",
        (),
        (),
        (),
        active_dns_records=(
            ReconRecord(
                "system-resolver",
                "wildcard-dns",
                "py-dns-validation-1.example.com",
                "192.0.2.10",
                "resolved",
            ),
        ),
    )
    checks = {finding.check: finding.status for finding in findings}

    assert checks["Wildcard DNS"] == "enabled"


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


class FakeOriginDoHClient:
    def lookup(self, domain: str, record_type: str = "A") -> DoHResult | None:
        if domain == "origin.example.com" and record_type == "A":
            return DoHResult(
                domain=domain,
                record_type=record_type,
                upstream="test",
                status=0,
                answers=(DoHAnswer("origin.example.com.", 1, 300, "203.0.113.10"),),
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


def test_origin_candidates_support_non_cloudflare_edge_providers() -> None:
    candidates = find_origin_candidates(
        "example.com",
        ("origin.example.com",),
        FakeOriginDoHClient(),  # type: ignore[arg-type]
        detections=(Detection("Fastly", "HTTP header x-fastly-request-id", "http", "medium"),),
        validate_http=False,
    )

    assert len(candidates) == 1
    assert candidates[0].hostname == "origin.example.com"
    assert candidates[0].edge_provider == "Fastly"
    assert candidates[0].validation_status == "not-tested"


def test_origin_candidate_format_includes_provider_and_validation() -> None:
    inspection = Inspection(
        "example.com",
        (),
        (),
        (),
        (),
        None,
        (),
        (),
        (),
        (
            OriginCandidate(
                "origin.example.com",
                ("203.0.113.10",),
                "dns-label-heuristic",
                "medium",
                "candidate evidence",
                "Fastly",
                "http-similar",
                "same status and shared headers",
            ),
        ),
    )

    output = format_inspection(inspection)

    assert "provider=Fastly" in output
    assert "validation=http-similar" in output


def test_origin_http_probe_comparison_can_raise_candidate_confidence(monkeypatch) -> None:
    from py_dns import inspector

    def fake_probe(domain: str, timeout: float = 4.0) -> HttpProbe:
        return HttpProbe(
            f"https://{domain}",
            200,
            (("x-app-version", "1"),),
        )

    monkeypatch.setattr(inspector, "probe_http", fake_probe)
    candidates = find_origin_candidates(
        "example.com",
        ("origin.example.com",),
        FakeOriginDoHClient(),  # type: ignore[arg-type]
        detections=(Detection("AWS CloudFront", "x-amz-cf-id", "http", "medium"),),
        protected_probe=HttpProbe("https://example.com", 200, (("x-app-version", "1"),)),
        validate_http=True,
    )

    assert candidates[0].confidence == "medium"
    assert candidates[0].validation_status == "http-similar"


def test_origin_intelligence_extracts_csp_ips_and_title_pivots(monkeypatch) -> None:
    from py_dns import inspector

    monkeypatch.setattr(inspector, "_tls_certificate_records", lambda domain: ((), ()))
    records = collect_origin_intelligence(
        "example.com",
        HttpProbe(
            "https://example.com",
            200,
            (
                (
                    "content-security-policy",
                    "default-src 'self'; report-uri http://203.0.113.25/csp; img-src https://backend.example.com",
                ),
            ),
            title="Example Portal",
        ),
    )
    categories = {record.category for record in records}

    assert "csp-ip-leak" in categories
    assert "csp-hostname" in categories
    assert "http-title-pivot" in categories


def test_origin_candidates_include_csp_ip_leaks() -> None:
    candidates = find_origin_candidates(
        "example.com",
        (),
        FakeOriginDoHClient(),  # type: ignore[arg-type]
        detections=(Detection("Cloudflare", "cf-ray", "http", "medium"),),
        recon_records=(
            ReconRecord(
                "https-header",
                "csp-ip-leak",
                "example.com",
                "203.0.113.25",
                "observed",
                "content-security-policy contains IP literals",
            ),
        ),
        validate_http=False,
    )

    assert any(candidate.source == "csp-ip-leak" for candidate in candidates)
    assert any("203.0.113.25" in candidate.addresses for candidate in candidates)


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
