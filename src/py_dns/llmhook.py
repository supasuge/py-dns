"""OpenAI-backed DNS remediation report hook."""

from __future__ import annotations

import json
from dataclasses import asdict, dataclass
from typing import Any, Literal, cast

from openai import OpenAI, OpenAIError

from py_dns.inspector import Inspection

DEFAULT_MODEL = "gpt-5.5"
ReasoningEffort = Literal["low", "medium", "high", "xhigh"]
Verbosity = Literal["low", "medium", "high"]
ServiceTier = Literal["auto", "priority"]
DEFAULT_REASONING_EFFORT: ReasoningEffort = "low"
DEFAULT_VERBOSITY: Verbosity = "medium"

REPORT_SCHEMA: dict[str, Any] = {
    "type": "object",
    "additionalProperties": False,
    "required": ["risk_summary", "priority_actions", "validation_plan", "operator_notes"],
    "properties": {
        "risk_summary": {
            "type": "object",
            "additionalProperties": False,
            "required": ["overall_risk", "summary", "confidence"],
            "properties": {
                "overall_risk": {"type": "string", "enum": ["critical", "high", "medium", "low", "info"]},
                "summary": {"type": "string"},
                "confidence": {"type": "string", "enum": ["high", "medium", "low"]},
            },
        },
        "priority_actions": {
            "type": "array",
            "items": {
                "type": "object",
                "additionalProperties": False,
                "required": ["priority", "severity", "title", "evidence", "steps", "validation"],
                "properties": {
                    "priority": {"type": "integer"},
                    "severity": {"type": "string", "enum": ["critical", "high", "medium", "low", "info"]},
                    "title": {"type": "string"},
                    "evidence": {"type": "string"},
                    "steps": {"type": "array", "items": {"type": "string"}},
                    "validation": {"type": "array", "items": {"type": "string"}},
                },
            },
        },
        "validation_plan": {"type": "array", "items": {"type": "string"}},
        "operator_notes": {"type": "array", "items": {"type": "string"}},
    },
}

SYSTEM_INSTRUCTIONS = """
You are a defensive DNS security analyst producing an actionable remediation plan
for an authorized assessment. Use only the evidence in the provided scan payload.
Do not invent vulnerabilities, do not claim an origin IP is confirmed from DNS
alone, and avoid exploit instructions. When Cloudflare or another edge provider
is detected, treat non-edge addresses as passive exposure candidates that need
owner validation before firewall or DNS changes. Respect the mail_profile field:
external hosted mail findings are DNS/mail-provider tasks, not web-server or VPS
host vulnerabilities.
""".strip()


@dataclass(frozen=True)
class LLMReport:
    model: str
    service_tier: str
    reasoning_effort: str
    markdown: str
    raw: dict[str, Any]


class LLMReportError(RuntimeError):
    """Raised when the OpenAI report hook cannot produce a report."""


def generate_remediation_report(
    inspection: Inspection,
    *,
    model: str = DEFAULT_MODEL,
    fast_mode: bool = True,
    reasoning_effort: ReasoningEffort = DEFAULT_REASONING_EFFORT,
    verbosity: Verbosity = DEFAULT_VERBOSITY,
    client: OpenAI | None = None,
) -> LLMReport:
    """Analyze an inspection with GPT-5.5 and return a markdown remediation plan.

    Current OpenAI guidance recommends GPT-5.5 through the Responses API, with
    `reasoning.effort` for latency/intelligence tradeoffs and `text.verbosity`
    for output length. The public Responses API service tier values do not use a
    literal "fast" value, so fast mode here means low reasoning effort plus the
    priority service tier when requested.
    """

    owns_client = client is None
    openai_client = client or OpenAI()
    service_tier: ServiceTier = "priority" if fast_mode else "auto"
    payload = build_report_payload(inspection)
    create_response = cast(Any, openai_client.responses.create)

    try:
        response = create_response(
            model=model,
            instructions=SYSTEM_INSTRUCTIONS,
            input=json.dumps(payload, sort_keys=True),
            reasoning={"effort": reasoning_effort},
            text={
                "verbosity": verbosity,
                "format": {
                    "type": "json_schema",
                    "name": "dns_remediation_report",
                    "strict": True,
                    "schema": REPORT_SCHEMA,
                },
            },
            service_tier=service_tier,
            store=False,
        )
    except OpenAIError as exc:
        raise LLMReportError(str(exc)) from exc
    finally:
        if owns_client:
            close = getattr(openai_client, "close", None)
            if callable(close):
                close()

    try:
        report_json = json.loads(response.output_text)
    except (AttributeError, json.JSONDecodeError) as exc:
        raise LLMReportError("OpenAI response did not contain schema-valid JSON text") from exc

    return LLMReport(
        model=model,
        service_tier=service_tier,
        reasoning_effort=reasoning_effort,
        markdown=render_report_markdown(report_json),
        raw=report_json,
    )


def build_report_payload(inspection: Inspection) -> dict[str, Any]:
    """Convert an Inspection into compact JSON for the model hook."""

    return {
        "domain": inspection.domain,
        "dns_results": [
            {
                "query": result.record_type,
                "status": result.status,
                "upstream": result.upstream,
                "answers": [asdict(answer) for answer in result.answers],
                "flags": {
                    "authenticated_data": result.authenticated_data,
                    "recursion_available": result.recursion_available,
                    "checking_disabled": result.checking_disabled,
                },
            }
            for result in inspection.all_results
        ],
        "detections": [asdict(detection) for detection in inspection.detections],
        "findings": [asdict(finding) for finding in inspection.findings],
        "subdomains": list(inspection.subdomains[:100]),
        "osint_records": [asdict(record) for record in inspection.osint_records[:150]],
        "zone_transfer_records": [asdict(record) for record in inspection.zone_transfer_records[:50]],
        "origin_candidates": [asdict(candidate) for candidate in inspection.origin_candidates],
        "mail_profile": asdict(inspection.mail_profile) if inspection.mail_profile else None,
        "http_probe": asdict(inspection.http_probe) if inspection.http_probe else None,
        "analysis_rules": {
            "origin_candidates_are_not_confirmed_origin_ips": True,
            "only_authorized_defensive_remediation": True,
            "prioritize_direct_step_by_step_fixes": True,
        },
    }


def render_report_markdown(report: dict[str, Any]) -> str:
    summary = report["risk_summary"]
    lines = [
        "# GPT DNS Remediation Plan",
        "",
        f"Overall risk: {summary['overall_risk']} ({summary['confidence']} confidence)",
        "",
        summary["summary"],
        "",
        "## Priority Actions",
    ]

    for action in sorted(report["priority_actions"], key=lambda item: item["priority"]):
        lines.extend(
            [
                "",
                f"{action['priority']}. {action['title']} [{action['severity']}]",
                f"Evidence: {action['evidence']}",
                "Steps:",
            ]
        )
        lines.extend(f"- {step}" for step in action["steps"])
        lines.append("Validation:")
        lines.extend(f"- {step}" for step in action["validation"])

    lines.extend(["", "## Validation Plan"])
    lines.extend(f"- {step}" for step in report["validation_plan"])

    if report["operator_notes"]:
        lines.extend(["", "## Operator Notes"])
        lines.extend(f"- {note}" for note in report["operator_notes"])

    return "\n".join(lines).strip()
