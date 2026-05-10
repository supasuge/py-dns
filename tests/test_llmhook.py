from py_dns.doh import DoHAnswer, DoHResult
from py_dns.inspector import Detection, Finding, Inspection, OriginCandidate, ReconRecord
from py_dns.llmhook import build_report_payload, render_report_markdown


def test_build_report_payload_includes_recon_and_origin_context() -> None:
    inspection = Inspection(
        "example.com",
        (
            DoHResult(
                domain="example.com",
                record_type="A",
                upstream="test",
                status=0,
                answers=(DoHAnswer("example.com.", 1, 300, "104.16.1.2"),),
                authenticated_data=True,
                recursion_available=True,
                checking_disabled=False,
            ),
        ),
        (),
        (Detection("Cloudflare", "test", "ip", "high"),),
        (
            Finding(
                "medium",
                "Origin exposure",
                "possible",
                "origin.example.com",
                "impact",
                "recommendation",
                "validation",
            ),
        ),
        None,
        (ReconRecord("crt.sh", "certificate-transparency", "origin.example.com", "certificate"),),
        ("origin.example.com",),
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

    payload = build_report_payload(inspection)

    assert payload["analysis_rules"]["origin_candidates_are_not_confirmed_origin_ips"] is True
    assert payload["origin_candidates"][0]["hostname"] == "origin.example.com"
    assert payload["findings"][0]["check"] == "Origin exposure"


def test_render_report_markdown_outputs_step_by_step_plan() -> None:
    markdown = render_report_markdown(
        {
            "risk_summary": {
                "overall_risk": "medium",
                "summary": "DNS posture needs follow-up.",
                "confidence": "high",
            },
            "priority_actions": [
                {
                    "priority": 1,
                    "severity": "medium",
                    "title": "Validate origin candidate",
                    "evidence": "origin.example.com resolved.",
                    "steps": ["Confirm asset ownership.", "Restrict origin ingress if confirmed."],
                    "validation": ["Review logs.", "Retest DNS."],
                }
            ],
            "validation_plan": ["Run py-dns inspect example.com."],
            "operator_notes": ["DNS evidence alone is not proof of origin."],
        }
    )

    assert "GPT DNS Remediation Plan" in markdown
    assert "Confirm asset ownership" in markdown
    assert "DNS evidence alone is not proof" in markdown
