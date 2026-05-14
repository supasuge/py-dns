# py-dns

`py-dns` is a Python DNS security and enumeration tool with two operating surfaces:

- a secure local DNS resolver that uses a cache, `/etc/hosts`, DNS-over-HTTPS, and DNS-over-TLS;
- a DNS reconnaissance CLI that collects DNS, passive OSINT, certificate transparency, zone-transfer, provider, mail-security, Cloudflare/origin-exposure, subdomain, and GPT-generated remediation context.

The tool is intended for authorized defensive assessment and education. It does not prove account ownership, asset ownership, or origin exposure by itself. Findings are evidence-based and should be validated against the owner’s DNS provider, hosting provider, mail provider, firewall policy, and asset inventory.

## Installation

Requirements:

- Python `>=3.13`
- `uv`
- Network access for live DNS, DoH, CT, HTTP header, OpenAI, and optional brute-force checks
- `OPENAI_API_KEY` only when using `--ai-report`

Install dependencies:

```bash
uv sync
```

Install development dependencies:

```bash
uv sync --extra dev
```

Run the CLI from the repo:

```bash
uv run py-dns --help
```

Install the tool and make it globally accessible from your `$PATH`:

```bash
cd py-dns
uv tool install .
```

Optional OpenAI setup for GPT remediation reports:

```bash
export OPENAI_API_KEY="sk-..."
uv run py-dns inspect example.com --ai-report
```

## Commands

Top-level commands:

```bash
uv run py-dns serve
uv run py-dns resolve example.com
uv run py-dns inspect example.com
uv run py-dns dig example.com
uv run py-dns list-vulns
```

`dig` is an alias for `inspect` essentially but slightly easier to use.

By default, `inspect` runs the broad reconnaissance profile: DNS records, HTTPS metadata, passive OSINT references, certificate transparency, wildcard DNS validation, AXFR attempts, bounded subdomain brute forcing, CDN/provider detection, and origin-candidate validation. Use `--no-http`, `--no-osint`, `--no-active`, or `--no-bruteforce-subdomains` to reduce scan scope.

## GitHub Pages Web Interface

A static browser interface is available in `docs/` for GitHub Pages:

```text
docs/index.html
docs/styles.css
docs/app.js
```

It uses browser-side DNS-over-HTTPS lookups against `dns.google`, so it can run from GitHub Pages without a Python server. The page performs harmless DNS reads for address, NS, SOA, MX, TXT, CAA, DNSSEC, DMARC, MTA-STS, TLS-RPT, BIMI, wildcard-DNS posture, CDN detection, and common origin-candidate labels. It also prints CLI validation commands for deeper checks that require Python, local DNS tooling, passive OSINT, provider detection, certificate transparency, AXFR attempts, provider-aware origin-candidate validation, and bounded subdomain brute forcing.

Preview locally:

```bash
python -m http.server 8080 --directory docs
```

Then open `http://127.0.0.1:8080`.

Publish with GitHub Pages:

1. Commit and push the `docs/` directory.
2. In GitHub, open the repository settings.
3. Go to **Pages**.
4. Set **Source** to **Deploy from a branch**.
5. Select the branch that contains the site and choose the `/docs` folder.
6. Save the settings and wait for GitHub to publish the Pages URL.

Makefile helpers:

```bash
make sync
make install
make uninstall
make inspect DOMAIN=example.com
make inspect-light DOMAIN=example.com
make web PORT=8080
make check
```

## Secure Resolver

The resolver path is implemented by `SecureResolver` and `SecureUDPServer`.

Resolution order:

1. `SecureCacheHandler`
2. `HostsFileHandler`
3. `DoHHandler`
4. `DoTHandler`

Technical behavior:

- Cache keys are `(domain, record_type)`.
- Positive answers are cached with DNS TTLs when available.
- Negative answers use a `NegativeEntry` sentinel with a shorter negative TTL.
- The cache evicts expired records first, then least-recently inserted entries.
- Rate limiting uses a token bucket before cache misses proceed down the resolver chain.
- `/etc/hosts` is checked for A records before network resolution.
- DoH uses `httpx` with HTTP/2, TLS certificate validation, and JSON DNS APIs.
- DoH upstreams are Cloudflare and Google by default.
- DoT is the encrypted fallback over TLS port `853`.
- The UDP server only answers IN-class A and AAAA questions.

**Run the resolver**:

```bash
uv run py-dns serve --host 127.0.0.1 --port 5353
```

> Note:
> Running a local resolver isn't necessary nor required, it very simply just ensure's your DNS queries are encrypted via DoH/DoT (DNS over HTTPS takes precedence, if not available falls back to DNS over TLS).

Query it:

```bash
dig @127.0.0.1 -p 5353 example.com A
dig @127.0.0.1 -p 5353 example.com AAAA
```

Binding to port `53` usually requires privileges:

```bash
sudo uv run py-dns serve --host 0.0.0.0 --port 53
```

Resolve through the secure chain without running the UDP server:

```bash
uv run py-dns resolve example.com
uv run py-dns resolve example.com --type AAAA
```

`resolve` currently supports `A` and `AAAA`.

## Inspector Pipeline

`py-dns inspect DOMAIN` performs a multi-source DNS security inspection.

The main scan does these steps:

1. Normalizes the domain by stripping a trailing dot and lowercasing it.
2. Queries the default DNS record set through DoH.
3. Queries extra mail/security records through DoH.
4. Optionally probes HTTPS metadata, headers, CSP, title, and TLS certificate SANs.
5. Detects providers and hosted services from DNS suffixes, IP ranges, and HTTP headers.
6. Optionally collects passive OSINT and certificate transparency names.
7. Optionally performs low-volume active DNS checks and AXFR attempts.
8. If a CDN/edge provider is detected, resolves provider-aware origin-exposure candidate hostnames.
9. Classifies mail hosting context.
10. Runs harmless DNS posture validation, including wildcard-DNS probes with a deterministic random-looking hostname.
11. Generates findings with severity, evidence, impact, remediation, and validation steps.
12. Optionally performs bounded subdomain brute forcing and scans each selected subdomain separately.
13. Optionally sends the structured inspection payload to GPT-5.5 for an actionable remediation plan.

Default DoH record types:

```text
A, AAAA, CNAME, NS, SOA, MX, TXT, CAA, DS, DNSKEY, HTTPS
```

Security record lookups:

```text
_dmarc.DOMAIN TXT
_mta-sts.DOMAIN TXT
_smtp._tls.DOMAIN TXT
default._bimi.DOMAIN TXT
```

Active DNS checks:

```text
DOMAIN NS
DOMAIN SOA
DOMAIN TXT filtered for SPF
_dmarc.DOMAIN TXT filtered for DMARC
py-dns-validation-*.DOMAIN A/AAAA wildcard checks
AXFR attempts against authoritative nameserver A addresses
```

Expanded posture checks include:

- public DNS returning private, loopback, link-local, multicast, or other special-use addresses;
- single authoritative nameserver and same-suffix nameserver concentration;
- SOA timer issues, including short expire, long negative-cache minimum, and retry values not below refresh;
- very low or very high TTLs on common externally visible records;
- missing CAA, missing `issuewild`, and unusual CAA `iodef` destinations;
- missing, multiple, permissive, neutral, lookup-heavy, or deprecated SPF mechanisms;
- missing, duplicate, monitor-only, partial, and no-reporting DMARC policies;
- missing or malformed MTA-STS, TLS-RPT, and BIMI records;
- wildcard DNS that resolves a validation hostname;
- manual-verification hints for dangling provider CNAMEs, public AXFR, and potential CDN origin exposure.

Passive OSINT collection:

- Google search dork reference URLs
- Bing search dork reference URLs
- Yahoo search dork reference URLs
- `crt.sh` JSON certificate transparency lookup
- VirusTotal domain relations reference URL
- DNSDumpster reference
- Netcraft search reference URL

Search engines and some OSINT sources are exposed as reference pivots instead of scraped aggressively.

## Provider Detection

Provider detection uses evidence-based heuristics:

- CNAME/NS/SOA/TXT/other answer suffix matching
- Cloudflare published IPv4/IPv6 network ranges
- HTTPS response headers such as `cf-ray`, `x-vercel-id`, `x-nf-request-id`, `x-amz-cf-id`, `x-azure-ref`, and selected `server` values

Current provider fingerprints include:

```text
Akamai
Alibaba Cloud
AWS
AWS CloudFront
AWS Route 53
Azure
Bunny
CacheFly
CDN77
CDNetworks
Cloudflare
Cloudflare for SaaS
DigitalOcean
Edgio/Limelight
Fastly
Gcore
GitHub Pages
Google
Google Cloud
Imperva
KeyCDN
Leaseweb
Linode/Akamai Cloud
Netlify
NS1/IBM NS1 Connect
Oracle Dyn
OVH
Sectigo DNS
Shopify
StackPath
Tencent Cloud
Vercel
```

Detection is not proof that the assessor controls the account or that the provider is the only hosting layer.

## Mail Hosting Context

Mail findings are gated by a `MailProfile` classifier so web-hosting context is not confused with mail-hosting responsibility.

The classifier derives:

- whether the domain receives mail;
- whether SPF suggests outbound sending;
- whether the domain publishes null MX;
- MX hostnames;
- recognized external mail provider;
- management mode;
- evidence string.

Recognized mail providers:

```text
Fastmail
Google Workspace
Microsoft 365
Proton Mail
SendGrid
Zoho Mail
```

Management modes:

```text
mail-disabled
external-mail-provider
domain-mail-enabled
web-host-mail-out-of-scope
send-only-or-policy-only
no-mail-signals
```

Important behavior:

- `MX 0 .` is treated as null MX.
- Null-MX domains with `v=spf1 -all` are not flagged as missing SPF, DMARC, MTA-STS, or TLS-RPT.
- External mail providers, such as Proton Mail, are reported as DNS/mail-provider configuration context, not web-server or Linode VPS findings.
- MTA-STS findings are lowered to `low` when mail is delegated to a recognized external provider.

## CDN And Origin Exposure

When a CDN or edge provider is detected, the tool tries provider-aware origin-exposure discovery by resolving candidate hostnames such as:

```text
origin.DOMAIN
origin-www.DOMAIN
direct.DOMAIN
backend.DOMAIN
server.DOMAIN
web.DOMAIN
lb.DOMAIN
elb.DOMAIN
app.DOMAIN
api.DOMAIN
staging.DOMAIN
stage.DOMAIN
dev.DOMAIN
old.DOMAIN
legacy.DOMAIN
internal.DOMAIN
```

It also considers gathered certificate transparency names whose first label matches origin-like patterns and adds `origin.`/`direct.` variants for selected CT names.

The tool reports origin-exposure candidates when A or AAAA records resolve outside known edge ranges for providers it can classify. For Cloudflare, published IPv4/IPv6 ranges are used to suppress normal proxied edge addresses. For other providers, hostname/provider evidence and candidate DNS resolution are reported with lower confidence unless HTTPS metadata also looks similar.

When HTTPS probing is enabled, the scanner sends bounded HTTPS requests to candidate hostnames and compares status/header metadata with the protected hostname. It also collects CSP/reporting headers, HTML titles, and TLS certificate SAN metadata for additional authorized pivots. It does not brute force HTTP paths, exploit services, or prove bypass. Treat every candidate as an owner-validation item and confirm with asset inventory, application logs, and approved direct-origin testing before firewall, DNS, or application changes.

```text
                         normal protected request path

  browser / client
        |
        | 1. DNS lookup for www.example.com
        v
  public DNS returns CDN edge address
        |
        | 2. HTTPS request
        v
  +-------------------+       3. cache miss / dynamic request       +----------------------+
  | CDN / edge proxy  | ------------------------------------------> | origin web server    |
  | Cloudflare/Fastly |                                             | real hosting IP      |
  | CloudFront/Akamai | <------------------------------------------ | app/API/backend      |
  +-------------------+       4. response cached/proxied            +----------------------+
        |
        v
  client sees CDN IPs, CDN TLS, CDN WAF/rate-limit behavior


                         defensive origin-exposure checks

  py-dns inspect DOMAIN
        |
        +--> current DNS: A/AAAA/CNAME/MX/TXT/CAA/NS/SOA/HTTPS
        +--> passive pivots: CT names, search URLs, Censys, URLScan, Netcraft, VT
        +--> origin labels: origin, direct, backend, server, web, lb, old, legacy...
        +--> mail and side services: MX hosts, TXT metadata, CSP hostnames
        +--> TLS certificate SANs and certificate reuse pivots
        +--> CSP/report-uri/report-to IP or backend hostname leaks
        +--> wildcard DNS and AXFR validation
        |
        v
  candidate origin observations
        |
        +--> suppress known CDN edge ranges where available
        +--> compare HTTPS status/header/title metadata
        +--> report as candidate, not proof
        |
        v
  defender validates with inventory, logs, firewall policy, and provider console
```

Origin recon methods implemented:

- current A, AAAA, CNAME, MX, TXT, CAA, NS, SOA, HTTPS, DS, and DNSKEY lookups;
- certificate transparency subdomain collection through `crt.sh`;
- Censys, URLScan, Netcraft, VirusTotal, DNSDumpster, and search-engine reference pivots;
- HTTP title pivots for Censys and URLScan;
- TLS certificate SAN collection and certificate-name pivots;
- CSP, CSP report-only, `report-to`, and `reporting-endpoints` parsing for raw IPs and internal hostnames;
- provider-aware origin label resolution for common backend naming patterns;
- CT-derived origin/direct variants;
- MX and side-service review where non-CDN services may expose infrastructure;
- wildcard DNS validation using deterministic random-looking labels;
- AXFR attempts against authoritative nameservers;
- HTTPS metadata comparison for candidate origin hostnames.

## Zone Transfer Checks

When active checks are enabled, the tool:

1. Resolves authoritative NS records.
2. Resolves A records for those nameservers.
3. Attempts AXFR against each nameserver IP.
4. Records up to `500` returned zone-transfer records.

If AXFR succeeds, the tool creates a critical `Zone transfer` finding because public zone transfer exposes zone inventory.

Disable active checks:

```bash
uv run py-dns inspect example.com --no-active
```

## Subdomain Enumeration

Passive subdomain enumeration uses `crt.sh`:

```bash
uv run py-dns inspect example.com --max-subdomains 250
```

Disable passive OSINT and CT:

```bash
uv run py-dns inspect example.com --no-osint
```

Enable bounded brute forcing:

```bash
uv run py-dns inspect example.com --bruteforce-subdomains
```

The brute-force pass:

1. Starts with the root domain.
2. Adds previously gathered CT subdomains as seeds.
3. Combines each seed with a label list.
4. Resolves A and AAAA records through DoH.
5. Keeps only resolved hostnames.
6. Scans gathered and resolved subdomains separately up to `--max-scanned-subdomains`.

Default brute-force labels:

```text
www, api, app, admin, assets, blog, cdn, dashboard, dev, docs, mail, origin,
portal, stage, staging, status, test, vpn
```

Use a custom wordlist:

```bash
uv run py-dns inspect example.com \
  --bruteforce-subdomains \
  --subdomain-wordlist ./subdomains.txt
```

Limit resolution volume:

```bash
uv run py-dns inspect example.com \
  --bruteforce-subdomains \
  --max-bruteforce 500 \
  --max-scanned-subdomains 50
```

## GPT Remediation Hook

`--ai-report` calls `src/py_dns/llmhook.py`.

The hook:

1. Converts the `Inspection` object into compact JSON.
2. Includes DNS results, detections, findings, subdomains, OSINT records, zone-transfer records, origin candidates, mail profile, HTTP probe data, and analysis rules.
3. Calls the OpenAI Responses API.
4. Uses model `gpt-5.5` by default.
5. Uses structured outputs with a strict JSON schema.
6. Renders the returned JSON as a Markdown remediation report.

Fast mode behavior:

- `--ai-report` uses `reasoning.effort = low`.
- It requests `service_tier = priority`.
- It uses `text.verbosity = medium`.

Slower mode:

```bash
uv run py-dns inspect example.com --ai-report --ai-slow
```

`--ai-slow` uses medium reasoning and automatic service tier.

The GPT instructions explicitly state:

- use only the supplied scan evidence;
- do not invent vulnerabilities;
- do not claim passive origin candidates are confirmed origins;
- treat external hosted mail findings as DNS/mail-provider work, not web-server or VPS vulnerabilities.

## Report Output

Rich terminal output:

```bash
uv run py-dns inspect example.com
```

Plain output:

```bash
uv run py-dns inspect example.com --plain
```

Write a report file:

```bash
uv run py-dns inspect example.com -o
```

The output path is:

```text
report-MMDDHHmm-{domain}.txt
```

Example:

```text
report-05101100-example.com.txt
```

`-o` writes the complete plain-text report, including subdomain scan sections and the GPT remediation plan when `--ai-report` is used.

## Terminal Rendering

Rich tables are generated with terminal-width-aware settings:

- the console uses soft wrapping;
- tables use the detected terminal width;
- table width is bounded between `72` and `160` columns;
- wide columns use folded overflow;
- repeated long values, such as DNSKEY, HTTPS, SOA, and certificate evidence, are folded instead of expanding the table beyond the terminal.

For logs, CI, or very narrow terminals, prefer:

```bash
uv run py-dns inspect example.com --plain
```

## Comprehensive Usage

Basic scan:

```bash
uv run py-dns inspect example.com
```

Plain scan:

```bash
uv run py-dns inspect example.com --plain
```

Write a text report:

```bash
uv run py-dns inspect example.com -o
```

Skip HTTPS header probe:

```bash
uv run py-dns inspect example.com --no-http
```

Skip OSINT and CT:

```bash
uv run py-dns inspect example.com --no-osint
```

Skip active DNS checks and AXFR attempts:

```bash
uv run py-dns inspect example.com --no-active
```

Increase CT subdomain retention:

```bash
uv run py-dns inspect example.com --max-subdomains 500
```

Enable brute-force subdomain expansion:

```bash
uv run py-dns inspect example.com --bruteforce-subdomains
```

Use brute forcing with a wordlist:

```bash
uv run py-dns inspect example.com --bruteforce-subdomains -w ./subdomains.txt
```

Limit brute-force and follow-up scan volume:

```bash
uv run py-dns inspect example.com \
  --bruteforce-subdomains \
  --max-bruteforce 100 \
  --max-scanned-subdomains 10
```

Generate a GPT remediation report:

```bash
uv run py-dns inspect example.com --ai-report
```

Generate a GPT report and write everything to a text file:

```bash
uv run py-dns inspect example.com --ai-report -o
```

Use a different OpenAI model:

```bash
uv run py-dns inspect example.com --ai-report --ai-model gpt-5.5
```

Use slower AI mode:

```bash
uv run py-dns inspect example.com --ai-report --ai-slow
```

Run the local secure resolver:

```bash
uv run py-dns serve --host 127.0.0.1 --port 5353
```

Resolve through the secure chain:

```bash
uv run py-dns resolve example.com --type A
uv run py-dns resolve example.com --type AAAA
```

Show vulnerability catalog:

```bash
uv run py-dns list-vulns
```

## Output Sections

Rich output may contain:

- DNS Answers
- Provider And Service Detections
- Mail Hosting Context
- Passive And Active Recon
- Passive Origin Exposure Candidates
- Security Findings
- Actionable Remediation And Validation
- HTTPS Edge Probe
- Subdomain Brute Force Results
- Subdomain scan sections
- GPT Remediation Plan

Plain output uses dig-like sections beginning with `;;`.

## Findings

Current findings include:

- missing A/AAAA records;
- missing IPv6;
- missing CAA;
- missing DNSSEC DS/DNSKEY;
- missing SPF for mail-enabled domains;
- multiple SPF records;
- unsafe SPF `+all`;
- weak SPF `ptr`;
- missing DMARC for mail-enabled domains;
- DMARC monitor-only policy;
- DMARC without aggregate reporting;
- missing MTA-STS for mail-enabled domains;
- missing TLS-RPT for mail-enabled domains;
- BIMI without enforced DMARC;
- dangling CNAME manual-verification candidates;
- Cloudflare hygiene missing CAA;
- allowed public AXFR;
- passive origin-exposure candidates.

Each finding contains:

- severity;
- check name;
- status;
- evidence;
- potential security impact;
- remediation;
- validation command or validation process.

## Usage

```bash
py-dns
                                                                                                                                  
 Usage: py-dns [OPTIONS] COMMAND [ARGS]...                                                                                        
                                                                                                                                  
 Secure local DNS resolver and DNS security scanner.                                                                              
                                                                                                                                  
╭─ Options ──────────────────────────────────────────────────────────────────────────────────────────────────────────────────────╮
│ --install-completion          Install completion for the current shell.                                                        │
│ --show-completion             Show completion for the current shell, to copy it or customize the installation.                 │
│ --help                        Show this message and exit.                                                                      │
╰────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────╯
╭─ Commands ─────────────────────────────────────────────────────────────────────────────────────────────────────────────────────╮
│ serve       Run a local secure UDP DNS resolver.                                                                               │
│ resolve     Resolve one A or AAAA record through the secure chain.                                                             │
│ inspect     Run detailed DNS/security/provider inspection.                                                                     │
│ dig         Alias for inspect.                                                                                                 │
│ list-vulns  Print the educational DNS vulnerability catalog.                                                                   │
╰────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────╯
```

**inspect**

```bash
py-dns inspect --help

 Usage: py-dns inspect [OPTIONS] DOMAIN

 Run detailed DNS/security/provider inspection.

╭─ Arguments ───────────────────────────────────────────────────────────────────────────────────╮
│ *    domain      TEXT  Domain to inspect. [required]                                          │
╰───────────────────────────────────────────────────────────────────────────────────────────────╯
╭─ Options ─────────────────────────────────────────────────────────────────────────────────────╮
│ --no-http                                                Skip HTTPS header probe.             │
│ --no-osint                                               Skip passive OSINT and CT lookups.   │
│ --no-active                                              Skip active DNS checks and AXFR      │
│                                                          attempts.                            │
│ --max-subdomains                                INTEGER  Maximum CT subdomains to keep.       │
│                                                          [default: 100]                       │
│ --ai-report                                              Ask GPT-5.5 to write a remediation   │
│                                                          plan.                                │
│ --ai-model                                      TEXT     OpenAI model for --ai-report.        │
│                                                          [default: gpt-5.5]                   │
│ --ai-slow                                                Use automatic service tier and       │
│                                                          medium reasoning instead of fast     │
│                                                          mode.                                │
│ --output                      -o                         Write the complete plain-text report │
│                                                          to report-MMDDHHmm-{domain}.txt.     │
│ --bruteforce-subdomains,--bf                             Resolve bounded subdomain guesses    │
│                                                          seeded by gathered domains, then     │
│                                                          scan each resolved host separately.  │
│ --subdomain-wordlist          -w                PATH     Optional newline-delimited subdomain │
│                                                          label wordlist for                   │
│                                                          --bruteforce-subdomains.             │
│ --max-bruteforce                                INTEGER  Maximum brute-force candidates to    │
│                                                          resolve.                             │
│                                                          [default: 200]                       │
│ --max-scanned-subdomains                        INTEGER  Maximum gathered/bruteforced         │
│                                                          subdomains to scan separately.       │
│                                                          [default: 25]                        │
│ --plain                           --no-plain             Print dig-like plain text instead of │
│                                                          Rich tables.                         │
│                                                          [default: no-plain]                  │
│ --verbose                     -v                         Enable debug logs.                   │
│ --help                                                   Show this message and exit.          │
╰───────────────────────────────────────────────────────────────────────────────────────
```

## Project Layout

```text
src/py_dns/cache.py         TTL-aware positive/negative DNS cache
src/py_dns/doh.py           DNS-over-HTTPS client
src/py_dns/dot.py           DNS-over-TLS client
src/py_dns/handlers.py      secure resolver chain handlers
src/py_dns/inspector.py     DNS recon, OSINT, provider detection, findings
src/py_dns/llmhook.py       OpenAI GPT remediation report hook
src/py_dns/main.py          Typer/Rich CLI
src/py_dns/packet.py        DNS packet encode/decode helpers
src/py_dns/rate_limiter.py  token bucket rate limiter
src/py_dns/resolver.py      public resolver API and UDP server
src/py_dns/vulns.py         educational vulnerability catalog
tests/                      pytest test suite
```

## Development

Install development dependencies:

```bash
uv sync --extra dev
```

Run tests:

```bash
uv run pytest
```

Run lint:

```bash
uv run ruff check .
```

Run type checks:

```bash
uv run --extra dev mypy src tests
```

Run all validation commands:

```bash
uv run ruff check .
uv run pytest
uv run --extra dev mypy src tests
```

## Contributing

Contributions should preserve the defensive, authorized-assessment scope.

Guidelines:

- Add tests for new scanner behavior.
- Keep active probing bounded by explicit CLI options and conservative defaults.
- Prefer passive evidence over aggressive probing.
- Do not label inferred origin candidates as confirmed origin IPs.
- Do not conflate web hosting, DNS hosting, and mail hosting responsibilities.
- Keep provider fingerprints evidence-based and explainable.
- Keep remediation text actionable and validation-focused.
- Run `ruff`, `pytest`, and `mypy` before submitting changes.

Suggested contribution workflow:

```bash
git checkout -b feature/my-change
uv sync --extra dev
uv run ruff check .
uv run pytest
uv run --extra dev mypy src tests
```

## TODO

Planned improvements:

- Add first-class JSON output.
- Add a machine-readable report schema.
- Add configurable DoH upstreams from CLI flags or config.
- Add richer CT sources beyond `crt.sh`.
- Add optional VirusTotal API integration when an API key is provided.
- Add optional DNSDumpster/Netcraft integrations if stable APIs or approved scraping strategies are available.
- Add DKIM selector discovery with a bounded selector list.
- Add DNSSEC validation beyond resolver-returned DS/DNSKEY/AD signals.
- Add resolver concurrency for bounded subdomain scanning.
- Add per-source timeout and retry configuration.
- Add provider-specific guidance for Cloudflare, Linode/Akamai Cloud, Proton Mail, Google Workspace, and Microsoft 365.

## Security And Ethics

Use this tool only on domains and infrastructure you own or are authorized to assess.

The tool performs network queries and HTTP requests. `--bruteforce-subdomains`, `--max-bruteforce`, and `--max-scanned-subdomains` can increase query volume. Keep limits appropriate for the target and authorization scope.

CDN origin candidates are DNS and HTTP metadata observations, not proof of bypass. Validate against asset inventory and logs before making changes.

## License

MIT. See `LICENSE.txt`.
