"""Typer/Rich command-line interface for the DNS resolver and scanner."""

from __future__ import annotations

import logging
import re
from datetime import datetime
from pathlib import Path
from shutil import get_terminal_size
from typing import Annotated, Any

import typer
from rich.console import Console
from rich.markdown import Markdown
from rich.panel import Panel
from rich.table import Table

from py_dns.doh import DoHClient
from py_dns.inspector import (
    TYPE_NAME,
    Inspection,
    ReconRecord,
    brute_force_subdomains,
    format_inspection,
    inspect_domain,
)
from py_dns.llmhook import DEFAULT_MODEL, LLMReportError, generate_remediation_report
from py_dns.resolver import SecureResolver, SecureUDPServer
from py_dns.vulns import VULNERABILITIES

console = Console(soft_wrap=True)
app = typer.Typer(
    name="py-dns",
    help="Secure local DNS resolver and DNS security scanner.",
    no_args_is_help=True,
)


def _setup(verbose: bool) -> None:
    logging.basicConfig(
        level=logging.DEBUG if verbose else logging.WARNING,
        format="%(asctime)s  %(levelname)-8s  %(message)s",
    )
    if not verbose:
        logging.getLogger("httpx").setLevel(logging.WARNING)


@app.command()
def serve(
    host: Annotated[str, typer.Option(help="UDP bind host.")] = "127.0.0.1",
    port: Annotated[int, typer.Option(help="UDP bind port.")] = 5353,
    verbose: Annotated[bool, typer.Option("--verbose", "-v", help="Enable debug logs.")] = False,
) -> None:
    """Run a local secure UDP DNS resolver."""
    _setup(verbose)
    SecureUDPServer(host=host, port=port).serve_forever()


@app.command()
def resolve(
    domain: Annotated[str, typer.Argument(help="Domain to resolve.")],
    record_type: Annotated[
        str,
        typer.Option("--type", "-t", help="Record type.", case_sensitive=False),
    ] = "A",
    verbose: Annotated[bool, typer.Option("--verbose", "-v", help="Enable debug logs.")] = False,
) -> None:
    """Resolve one A or AAAA record through the secure chain."""
    _setup(verbose)
    record_type = record_type.upper()
    if record_type not in {"A", "AAAA"}:
        raise typer.BadParameter("resolve currently supports A and AAAA")
    with SecureResolver() as resolver:
        answer = resolver.resolve(domain, record_type)

    table = _table("Resolution", show_header=True, header_style="bold cyan")
    table.add_column("Domain")
    table.add_column("Type")
    table.add_column("Answer")
    table.add_row(domain, record_type, answer or "[yellow]NXDOMAIN/NOANSWER[/yellow]")
    console.print(table)
    raise typer.Exit(0 if answer else 2)


@app.command()
def inspect(
    domain: Annotated[str, typer.Argument(help="Domain to inspect.")],
    skip_http: Annotated[bool, typer.Option("--no-http", help="Skip HTTPS header probe.")] = False,
    skip_osint: Annotated[bool, typer.Option("--no-osint", help="Skip passive OSINT and CT lookups.")] = False,
    skip_active: Annotated[bool, typer.Option("--no-active", help="Skip active DNS checks and AXFR attempts.")] = False,
    max_subdomains: Annotated[int, typer.Option(help="Maximum CT subdomains to keep.")] = 100,
    ai_report: Annotated[bool, typer.Option("--ai-report", help="Ask GPT-5.5 to write a remediation plan.")] = False,
    ai_model: Annotated[str, typer.Option(help="OpenAI model for --ai-report.")] = DEFAULT_MODEL,
    ai_slow: Annotated[bool, typer.Option("--ai-slow", help="Use automatic service tier and medium reasoning instead of fast mode.")] = False,
    output_file: Annotated[bool, typer.Option("--output", "-o", help="Write the complete plain-text report to report-MMDDHHmm-{domain}.txt.")] = False,
    bruteforce_subdomains: Annotated[bool, typer.Option("--bruteforce-subdomains", "--bf", help="Resolve bounded subdomain guesses seeded by gathered domains, then scan each resolved host separately.")] = False,
    subdomain_wordlist: Annotated[Path | None, typer.Option("--subdomain-wordlist", "-w", help="Optional newline-delimited subdomain label wordlist for --bruteforce-subdomains.")] = None,
    max_bruteforce: Annotated[int, typer.Option(help="Maximum brute-force candidates to resolve.")] = 200,
    max_scanned_subdomains: Annotated[int, typer.Option(help="Maximum gathered/bruteforced subdomains to scan separately.")] = 25,
    plain: Annotated[bool, typer.Option(help="Print dig-like plain text instead of Rich tables.")] = False,
    verbose: Annotated[bool, typer.Option("--verbose", "-v", help="Enable debug logs.")] = False,
) -> None:
    """Run detailed DNS/security/provider inspection."""
    _setup(verbose)
    inspection = inspect_domain(
        domain,
        http_probe=not skip_http,
        passive_osint=not skip_osint,
        active_checks=not skip_active,
        max_subdomains=max_subdomains,
    )
    subdomain_inspections: list[Inspection] = []
    brute_records: tuple[ReconRecord, ...] = ()
    if bruteforce_subdomains:
        labels = _load_subdomain_labels(subdomain_wordlist)
        with DoHClient() as doh:
            brute_records = brute_force_subdomains(
                inspection.domain,
                inspection.subdomains,
                doh,
                labels=labels,
                max_candidates=max_bruteforce,
            )
        scan_targets = _subdomain_scan_targets(
            inspection.domain,
            inspection.subdomains,
            brute_records,
            max_scanned_subdomains,
        )
        for target in scan_targets:
            subdomain_inspections.append(
                inspect_domain(
                    target,
                    http_probe=not skip_http,
                    passive_osint=False,
                    active_checks=not skip_active,
                    max_subdomains=0,
                )
            )

    report_markdown = None
    if ai_report:
        try:
            report = generate_remediation_report(
                inspection,
                model=ai_model,
                fast_mode=not ai_slow,
                reasoning_effort="medium" if ai_slow else "low",
            )
            report_markdown = report.markdown
        except LLMReportError as exc:
            report_markdown = f"# GPT DNS Remediation Plan\n\nOpenAI report generation failed: {exc}"

    output_path = None
    if output_file:
        output_path = _write_text_report(
            inspection,
            subdomain_inspections,
            report_markdown,
            brute_records,
        )

    if plain:
        console.print(_format_complete_plain_report(inspection, subdomain_inspections, report_markdown, brute_records))
        if output_path:
            console.print(f"\nReport written to {output_path}")
        return
    render_complete_report(inspection, subdomain_inspections, report_markdown, brute_records)
    if output_path:
        console.print(f"\n[green]Report written to[/green] {output_path}")


def render_complete_report(
    inspection: Inspection,
    subdomain_inspections: list[Inspection],
    report_markdown: str | None,
    brute_records: tuple[ReconRecord, ...],
) -> None:
    render_inspection(inspection)
    if brute_records:
        _render_bruteforce_summary(brute_records)
    for subdomain_inspection in subdomain_inspections:
        console.rule(f"Subdomain scan: {subdomain_inspection.domain}")
        render_inspection(subdomain_inspection)
    if report_markdown:
        console.print(Panel(Markdown(report_markdown), title="GPT Remediation Plan", border_style="yellow"))


def _format_complete_plain_report(
    inspection: Inspection,
    subdomain_inspections: list[Inspection],
    report_markdown: str | None,
    brute_records: tuple[ReconRecord, ...],
) -> str:
    sections = [format_inspection(inspection)]
    if brute_records:
        sections.append(_format_bruteforce_records(brute_records))
    sections.extend(format_inspection(subdomain_inspection) for subdomain_inspection in subdomain_inspections)
    if report_markdown:
        sections.append(report_markdown)
    return ("\n\n".join(section.strip() for section in sections if section)).strip()


def _write_text_report(
    inspection: Inspection,
    subdomain_inspections: list[Inspection],
    report_markdown: str | None,
    brute_records: tuple[ReconRecord, ...],
) -> Path:
    timestamp = datetime.now().strftime("%m%d%H%M")
    safe_domain = re.sub(r"[^A-Za-z0-9_.-]+", "_", inspection.domain)
    path = Path(f"report-{timestamp}-{safe_domain}.txt")
    path.write_text(
        _format_complete_plain_report(inspection, subdomain_inspections, report_markdown, brute_records) + "\n",
        encoding="utf-8",
    )
    return path


def _load_subdomain_labels(path: Path | None) -> tuple[str, ...]:
    if path is None:
        from py_dns.inspector import DEFAULT_BRUTEFORCE_LABELS

        return DEFAULT_BRUTEFORCE_LABELS
    return tuple(
        line.strip().strip(".").lower()
        for line in path.read_text(encoding="utf-8").splitlines()
        if line.strip() and not line.lstrip().startswith("#")
    )


def _subdomain_scan_targets(
    domain: str,
    ct_subdomains: tuple[str, ...],
    brute_records: tuple[ReconRecord, ...],
    limit: int,
) -> list[str]:
    targets: list[str] = []
    seen: set[str] = {domain}
    for candidate in (*ct_subdomains, *(record.name for record in brute_records)):
        candidate = candidate.rstrip(".").lower()
        if candidate in seen or not candidate.endswith(f".{domain}"):
            continue
        seen.add(candidate)
        targets.append(candidate)
        if len(targets) >= limit:
            break
    return targets


def _format_bruteforce_records(records: tuple[ReconRecord, ...]) -> str:
    lines = [";; subdomain brute force"]
    for record in records:
        lines.append(f";;   {record.name}: {record.value} [{record.status}]")
    return "\n".join(lines)


def _render_bruteforce_summary(records: tuple[ReconRecord, ...]) -> None:
    table = _table("Subdomain Brute Force Results", header_style="bold cyan")
    table.add_column("Hostname", overflow="fold", ratio=2)
    table.add_column("Addresses", overflow="fold", ratio=3)
    table.add_column("Status", no_wrap=True)
    for record in records:
        table.add_row(record.name, record.value, record.status)
    console.print(table)


@app.command()
def dig(
    domain: Annotated[str, typer.Argument(help="Domain to inspect.")],
    skip_http: Annotated[bool, typer.Option("--no-http", help="Skip HTTPS header probe.")] = False,
    plain: Annotated[bool, typer.Option(help="Print dig-like plain text instead of Rich tables.")] = False,
    verbose: Annotated[bool, typer.Option("--verbose", "-v", help="Enable debug logs.")] = False,
) -> None:
    """Alias for inspect."""
    inspect(
        domain=domain,
        skip_http=skip_http,
        skip_osint=False,
        skip_active=False,
        max_subdomains=100,
        ai_report=False,
        ai_model=DEFAULT_MODEL,
        ai_slow=False,
        output_file=False,
        bruteforce_subdomains=False,
        subdomain_wordlist=None,
        max_bruteforce=200,
        max_scanned_subdomains=25,
        plain=plain,
        verbose=verbose,
    )


@app.command("list-vulns")
def list_vulns() -> None:
    """Print the educational DNS vulnerability catalog."""
    table = _table("DNS Vulnerability Catalog", header_style="bold red")
    table.add_column("ID", style="bold")
    table.add_column("Name")
    table.add_column("Impact")
    table.add_column("Mitigation")
    for vuln_id, info in VULNERABILITIES.items():
        table.add_row(vuln_id, info["name"], info["impact"], info["mitigation"])
    console.print(table)


def _table(title: str, **kwargs: Any) -> Table:
    width = _render_width()
    return Table(
        title=title,
        expand=width >= 96,
        width=width,
        safe_box=True,
        **kwargs,
    )


def _render_width() -> int:
    detected = get_terminal_size((100, 24)).columns
    return max(72, min(detected, 160))


def _fold_width(divisor: int = 3, *, minimum: int = 18, maximum: int = 60) -> int:
    return max(minimum, min(console.width // divisor, maximum))


def render_inspection(inspection: Inspection) -> None:
    console.print(Panel.fit(f"[bold]DNS security scan[/bold]\n{inspection.domain}", border_style="cyan"))
    _render_records(inspection)
    _render_detections(inspection)
    _render_mail_profile(inspection)
    _render_recon(inspection)
    _render_origin_candidates(inspection)
    _render_findings(inspection)
    _render_remediation(inspection)
    _render_http_probe(inspection)


def _render_records(inspection: Inspection) -> None:
    table = _table("DNS Answers", header_style="bold cyan", show_lines=False)
    table.add_column("Query")
    table.add_column("Status")
    table.add_column("Flags")
    table.add_column("Name", overflow="fold", max_width=_fold_width(3))
    table.add_column("TTL", justify="right")
    table.add_column("Type")
    table.add_column("Data", overflow="fold", max_width=_fold_width(2, maximum=80))

    for result in inspection.all_results:
        flags = []
        if result.authenticated_data:
            flags.append("AD")
        if result.recursion_available:
            flags.append("RA")
        if result.checking_disabled:
            flags.append("CD")
        if result.answers:
            for answer in result.answers:
                table.add_row(
                    result.record_type,
                    _rcode_name(result.status),
                    ",".join(flags) or "-",
                    answer.name,
                    str(answer.ttl),
                    str(TYPE_NAME.get(answer.type, answer.type)),
                    answer.data,
                )
        else:
            table.add_row(result.record_type, _rcode_name(result.status), ",".join(flags) or "-", "-", "-", "-", "no answers")
    console.print(table)


def _render_detections(inspection: Inspection) -> None:
    table = _table("Provider And Service Detections", header_style="bold green")
    table.add_column("Provider")
    table.add_column("Source")
    table.add_column("Confidence")
    table.add_column("Evidence", overflow="fold", max_width=_fold_width(2, maximum=80))
    if inspection.detections:
        for detection in inspection.detections:
            table.add_row(detection.provider, detection.source, detection.confidence, detection.reason)
    else:
        table.add_row("-", "-", "-", "No provider fingerprints detected")
    console.print(table)


def _render_mail_profile(inspection: Inspection) -> None:
    if inspection.mail_profile is None:
        return
    profile = inspection.mail_profile
    table = _table("Mail Hosting Context", header_style="bold cyan")
    table.add_column("Management")
    table.add_column("Provider")
    table.add_column("Receives Mail")
    table.add_column("Sends Mail")
    table.add_column("Evidence", overflow="fold", max_width=_fold_width(2, maximum=80))
    table.add_row(
        profile.management,
        profile.provider or "-",
        "yes" if profile.receives_mail else "no",
        "yes" if profile.sends_mail else "no",
        profile.evidence,
    )
    console.print(table)


def _render_recon(inspection: Inspection) -> None:
    table = _table("Passive And Active Recon", header_style="bold cyan")
    table.add_column("Source")
    table.add_column("Category")
    table.add_column("Name", overflow="fold", max_width=_fold_width(3))
    table.add_column("Status")
    table.add_column("Value", overflow="fold", max_width=_fold_width(2, maximum=80))

    records = inspection.osint_records[:30]
    if not records and not inspection.zone_transfer_records:
        table.add_row("-", "-", "-", "-", "No recon records collected")
        console.print(table)
        return
    for record in records:
        table.add_row(record.source, record.category, record.name, record.status, record.value or record.evidence or "-")
    if len(inspection.osint_records) > len(records):
        table.add_row("-", "summary", "additional records", "observed", f"{len(inspection.osint_records) - len(records)} more records not shown")
    if inspection.subdomains:
        table.add_row("crt.sh", "subdomains", inspection.domain, "observed", f"{len(inspection.subdomains)} unique CT subdomains")
    if inspection.zone_transfer_records:
        table.add_row("AXFR", "zone-transfer", inspection.domain, "allowed", f"{len(inspection.zone_transfer_records)} records returned")
    console.print(table)


def _render_origin_candidates(inspection: Inspection) -> None:
    if not inspection.origin_candidates:
        return
    table = _table("Passive Origin Exposure Candidates", header_style="bold red")
    table.add_column("Hostname")
    table.add_column("Addresses", overflow="fold", max_width=_fold_width(3))
    table.add_column("Confidence")
    table.add_column("Evidence", overflow="fold", max_width=_fold_width(2, maximum=80))
    for candidate in inspection.origin_candidates:
        table.add_row(candidate.hostname, ", ".join(candidate.addresses), candidate.confidence, candidate.evidence)
    console.print(table)


def _render_findings(inspection: Inspection) -> None:
    table = _table("Security Findings", header_style="bold magenta")
    table.add_column("Severity", no_wrap=True)
    table.add_column("Check", no_wrap=True)
    table.add_column("Status", no_wrap=True)
    table.add_column("Potential Security Impact", overflow="fold", max_width=_fold_width(3))
    table.add_column("Evidence", overflow="fold", max_width=_fold_width(3))
    for finding in inspection.findings:
        table.add_row(
            _severity_style(finding.severity),
            finding.check,
            finding.status,
            finding.impact,
            finding.evidence,
        )
    console.print(table)


def _render_remediation(inspection: Inspection) -> None:
    table = _table("Actionable Remediation And Validation", header_style="bold yellow")
    table.add_column("Check", no_wrap=True)
    table.add_column("Remediation", overflow="fold", max_width=_fold_width(2, maximum=80))
    table.add_column("Validation", overflow="fold", max_width=_fold_width(2, maximum=80))
    for finding in inspection.findings:
        table.add_row(finding.check, finding.recommendation, finding.validation)
    console.print(table)


def _render_http_probe(inspection: Inspection) -> None:
    if inspection.http_probe is None:
        return
    probe = inspection.http_probe
    table = _table("HTTPS Edge Probe", header_style="bold blue")
    table.add_column("URL")
    table.add_column("Status")
    table.add_column("Headers", overflow="fold", max_width=_fold_width(2, maximum=80))
    if probe.error:
        table.add_row(probe.url, "error", probe.error)
    else:
        headers = "\n".join(f"{key}: {value}" for key, value in probe.headers) or "No edge headers"
        table.add_row(probe.url, str(probe.status_code), headers)
    console.print(table)


def _severity_style(severity: str) -> str:
    return {
        "critical": "[bold red]critical[/bold red]",
        "high": "[red]high[/red]",
        "medium": "[yellow]medium[/yellow]",
        "low": "[blue]low[/blue]",
        "info": "[dim]info[/dim]",
    }.get(severity, severity)


def _rcode_name(status: int) -> str:
    return {
        0: "NOERROR",
        1: "FORMERR",
        2: "SERVFAIL",
        3: "NXDOMAIN",
        4: "NOTIMP",
        5: "REFUSED",
    }.get(status, f"RCODE-{status}")


def main() -> None:
    app()


if __name__ == "__main__":
    main()
