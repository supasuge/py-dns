const RECORD_TYPES = ["A", "AAAA", "CNAME", "NS", "SOA", "MX", "TXT", "CAA", "DS", "DNSKEY"];
const ORIGIN_PREFIXES = ["origin", "direct", "backend", "server", "app", "api", "staging", "stage", "dev", "old"];
const SECURITY_QUERIES = [
  ["DMARC", "_dmarc.{domain}", "TXT"],
  ["MTA-STS", "_mta-sts.{domain}", "TXT"],
  ["TLS-RPT", "_smtp._tls.{domain}", "TXT"],
  ["BIMI", "default._bimi.{domain}", "TXT"],
];

const form = document.querySelector("#scan-form");
const target = document.querySelector("#target");
const recordCount = document.querySelector("#record-count");
const findingCount = document.querySelector("#finding-count");
const statusText = document.querySelector("#status");
const findingsEl = document.querySelector("#findings");
const originsEl = document.querySelector("#origins");
const recordsEl = document.querySelector("#records");
const validationEl = document.querySelector("#validation");
const copyButton = document.querySelector("#copy-report");

let lastReport = "";

form.addEventListener("submit", async (event) => {
  event.preventDefault();
  const domain = normalizeDomain(new FormData(form).get("domain"));
  if (!domain) return;
  setStatus("Scanning");
  target.textContent = domain;
  copyButton.disabled = true;
  findingsEl.className = "empty";
  findingsEl.textContent = "Querying DNS-over-HTTPS records...";
  originsEl.replaceChildren();
  recordsEl.replaceChildren();

  try {
    const results = await scanDomain(domain);
    const analysis = analyze(domain, results);
    render(domain, results, analysis.findings, analysis.originCandidates, analysis.edgeProviders);
    setStatus("Complete");
  } catch (error) {
    setStatus("Error");
    findingsEl.className = "empty";
    findingsEl.textContent = error instanceof Error ? error.message : "Scan failed.";
  }
});

copyButton.addEventListener("click", async () => {
  if (!lastReport) return;
  await navigator.clipboard.writeText(lastReport);
  copyButton.textContent = "Copied";
  setTimeout(() => {
    copyButton.textContent = "Copy report";
  }, 1200);
});

function normalizeDomain(value) {
  return String(value || "")
    .trim()
    .replace(/^https?:\/\//i, "")
    .replace(/\/.*$/, "")
    .replace(/\.$/, "")
    .toLowerCase();
}

async function scanDomain(domain) {
  const lookups = RECORD_TYPES.map((type) => lookup(domain, type, type));
  for (const [label, template, type] of SECURITY_QUERIES) {
    lookups.push(lookup(template.replace("{domain}", domain), type, label));
  }
  for (const prefix of ORIGIN_PREFIXES) {
    const name = `${prefix}.${domain}`;
    lookups.push(lookup(name, "A", `ORIGIN-A:${name}`));
    lookups.push(lookup(name, "AAAA", `ORIGIN-AAAA:${name}`));
  }
  const wildcard = `py-dns-validation-${stableSeed(domain)}.${domain}`;
  lookups.push(lookup(wildcard, "A", "WILDCARD-A"));
  lookups.push(lookup(wildcard, "AAAA", "WILDCARD-AAAA"));
  return Promise.all(lookups);
}

async function lookup(name, type, label) {
  const url = new URL("https://dns.google/resolve");
  url.searchParams.set("name", name);
  url.searchParams.set("type", type);
  url.searchParams.set("cd", "0");
  const response = await fetch(url);
  if (!response.ok) throw new Error(`DoH lookup failed for ${name} ${type}`);
  const data = await response.json();
  return {
    name,
    type,
    label,
    status: data.Status,
    ad: Boolean(data.AD),
    answers: Array.isArray(data.Answer) ? data.Answer : [],
  };
}

function analyze(domain, results) {
  const findings = [];
  const byLabel = Object.fromEntries(results.map((result) => [result.label, result]));
  const answers = (label) => byLabel[label]?.answers || [];
  const txt = answers("TXT").map((answer) => cleanTxt(answer.data));
  const spf = txt.filter((value) => value.toLowerCase().startsWith("v=spf1"));
  const dmarc = answers("DMARC").map((answer) => cleanTxt(answer.data));
  const mx = answers("MX");
  const edgeProviders = detectEdgeProviders(results);
  const originCandidates = originCandidatesFor(results, edgeProviders);

  if (!answers("A").length && !answers("AAAA").length) {
    add(findings, "high", "Address records", "No A or AAAA records returned.", "Publish active address records or remove stale DNS.");
  }
  if (!answers("AAAA").length) {
    add(findings, "info", "IPv6", "No AAAA record returned.", "Add IPv6 if the service and provider support it.");
  }
  for (const answer of [...answers("A"), ...answers("AAAA")]) {
    if (isSpecialAddress(answer.data)) {
      add(findings, "high", "Public address hygiene", `${answer.name} returns ${answer.data}.`, "Remove private or special-use addresses from public DNS.");
    }
  }
  if (answers("NS").length === 1) {
    add(findings, "medium", "Nameserver redundancy", `Single NS: ${answers("NS")[0].data}.`, "Use at least two authoritative nameservers.");
  }
  if (!answers("CAA").length) {
    add(findings, "medium", "CAA", "No CAA records returned.", "Publish CAA records for approved certificate authorities.");
  } else if (!answers("CAA").some((answer) => answer.data.toLowerCase().includes("issuewild"))) {
    add(findings, "low", "CAA wildcard policy", "CAA exists but no issuewild policy was found.", "Add an explicit issuewild policy.");
  }
  if (!answers("DS").length && !answers("DNSKEY").length) {
    add(findings, "medium", "DNSSEC", "No DS/DNSKEY records returned.", "Enable DNSSEC signing and publish DS at the registrar.");
  }
  if (mx.length && !spf.length) {
    add(findings, "high", "SPF", "MX exists but no SPF record was found.", "Publish exactly one SPF TXT record.");
  }
  if (spf.length > 1) {
    add(findings, "high", "SPF", `${spf.length} SPF records were found.`, "Consolidate SPF into one TXT record.");
  }
  for (const value of spf) {
    const lower = ` ${value.toLowerCase()} `;
    if (lower.includes(" +all ")) add(findings, "critical", "SPF", "SPF contains +all.", "Replace +all with ~all or -all.");
    if (lower.includes(" ptr ")) add(findings, "medium", "SPF", "SPF uses ptr.", "Replace ptr with explicit mechanisms.");
    if (lower.includes(" ?all ")) add(findings, "low", "SPF", "SPF ends neutrally with ?all.", "Use ~all or -all when ready.");
    const lookupCount = spfLookupCount(value);
    if (lookupCount > 10) add(findings, "high", "SPF", `Estimated ${lookupCount} DNS lookup mechanisms.`, "Reduce SPF DNS lookups below 10.");
  }
  if (mx.length && !dmarc.length) {
    add(findings, "high", "DMARC", "MX exists but no DMARC record was found.", "Publish DMARC and move toward quarantine or reject.");
  }
  if (dmarc.length > 1) {
    add(findings, "high", "DMARC", `${dmarc.length} DMARC records were found.`, "Publish exactly one DMARC TXT record.");
  }
  const dmarcText = dmarc.join(" ").toLowerCase();
  if (dmarcText.includes("p=none")) add(findings, "medium", "DMARC", "DMARC is monitor-only.", "Move to quarantine or reject after validation.");
  if (dmarcText.includes("sp=none")) add(findings, "low", "DMARC", "Subdomain policy is monitor-only.", "Set sp=quarantine or sp=reject when appropriate.");
  if (dmarcText && !dmarcText.includes("rua=")) add(findings, "low", "DMARC", "No aggregate reporting destination.", "Add a monitored rua destination.");
  if (mx.length && !answers("MTA-STS").length) {
    add(findings, "medium", "MTA-STS", "No _mta-sts TXT record was found.", "Add MTA-STS DNS and HTTPS policy.");
  }
  if (mx.length && !answers("TLS-RPT").length) {
    add(findings, "low", "TLS-RPT", "No TLS-RPT record was found.", "Add SMTP TLS reporting.");
  }
  if (answers("BIMI").length && (!dmarcText || dmarcText.includes("p=none"))) {
    add(findings, "medium", "BIMI", "BIMI exists without enforced DMARC.", "Enforce DMARC before relying on BIMI.");
  }
  if (answers("WILDCARD-A").length || answers("WILDCARD-AAAA").length) {
    add(findings, "medium", "Wildcard DNS", "Random validation hostname resolved.", "Confirm wildcard DNS is intentional and safely routed.");
  }
  if (originCandidates.length) {
    add(findings, "medium", "Origin exposure", `${originCandidates.length} candidate hostnames resolved outside known edge ranges.`, "Validate ownership and restrict origin ingress to approved CDN ranges.");
  }
  if (!findings.length) {
    add(findings, "info", "Baseline", "No medium/high browser findings detected.", "Run the CLI for provider detection, AXFR attempts, CT, and subdomain checks.");
  }
  return { findings, originCandidates, edgeProviders };
}

function add(findings, severity, check, evidence, recommendation) {
  findings.push({ severity, check, evidence, recommendation });
}

function render(domain, results, findings, originCandidates, edgeProviders) {
  const answerRows = results.flatMap((result) =>
    result.label.startsWith("ORIGIN-") ? [] : result.answers.map((answer) => ({ ...answer, label: result.label, ad: result.ad })),
  );
  recordCount.textContent = String(answerRows.length);
  findingCount.textContent = String(findings.length);
  findingsEl.className = "findings-list";
  findingsEl.replaceChildren(
    ...findings.map((finding) => {
      const row = document.createElement("article");
      row.className = "finding";
      row.innerHTML = `
        <span class="severity ${finding.severity}">${finding.severity}</span>
        <div>
          <h3>${escapeHtml(finding.check)}</h3>
          <p>${escapeHtml(finding.evidence)}</p>
          <p>${escapeHtml(finding.recommendation)}</p>
        </div>`;
      return row;
    }),
  );
  recordsEl.replaceChildren(
    ...(answerRows.length ? answerRows : [{ label: "-", name: domain, type: "-", TTL: "-", data: "No answers returned" }]).map((answer) => {
      const row = document.createElement("div");
      row.className = "record-row";
      row.innerHTML = `<strong>${escapeHtml(answer.label)}</strong><p><code>${escapeHtml(answer.name)} ${escapeHtml(String(answer.TTL))} ${escapeHtml(String(answer.type))} ${escapeHtml(answer.data)}</code></p>`;
      return row;
    }),
  );
  originsEl.replaceChildren(
    ...(originCandidates.length ? originCandidates : [{ name: "-", addresses: ["No origin candidates resolved"], provider: edgeProviders.join(", ") || "-" }]).map((candidate) => {
      const row = document.createElement("div");
      row.className = "record-row";
      row.innerHTML = `<strong>${escapeHtml(candidate.provider || "-")}</strong><p><code>${escapeHtml(candidate.name)} ${escapeHtml(candidate.addresses.join(", "))}</code></p>`;
      return row;
    }),
  );
  const commands = [
    `uv run py-dns inspect ${domain} --bruteforce-subdomains --plain`,
    `dig NS ${domain} +short`,
    `dig CAA ${domain} +short`,
    `dig TXT ${domain} +short`,
    `dig TXT _dmarc.${domain} +short`,
    `dig AXFR ${domain} @$(dig NS ${domain} +short | head -n 1)`,
    `dig A py-dns-validation-${stableSeed(domain)}.${domain} +short`,
    `dig A origin.${domain} +short`,
    `curl -I https://origin.${domain}`,
  ];
  validationEl.textContent = commands.join("\n");
  lastReport = [
    `py-dns web report for ${domain}`,
    "",
    "Findings:",
    ...findings.map((finding) => `- ${finding.severity.toUpperCase()} ${finding.check}: ${finding.evidence} ${finding.recommendation}`),
    "",
    "Origin candidates:",
    ...(originCandidates.length ? originCandidates.map((candidate) => `- ${candidate.provider}: ${candidate.name} -> ${candidate.addresses.join(", ")}`) : ["- none"]),
    "",
    "Validation:",
    ...commands,
  ].join("\n");
  copyButton.disabled = false;
}

function setStatus(value) {
  statusText.textContent = value;
}

function cleanTxt(value) {
  return String(value || "").replace(/^"|"$/g, "");
}

function spfLookupCount(value) {
  return cleanTxt(value)
    .toLowerCase()
    .split(/\s+/)
    .filter((token) => {
      const mechanism = token.replace(/^[+~?-]/, "");
      return ["a", "mx", "ptr"].includes(mechanism) || /^(include:|a:|mx:|exists:|redirect=)/.test(mechanism);
    }).length;
}

function detectEdgeProviders(results) {
  const providers = new Set();
  for (const result of results) {
    for (const answer of result.answers || []) {
      const value = String(answer.data || "").toLowerCase();
      if (value.includes("cloudflare") || isCloudflareAddress(value)) providers.add("Cloudflare");
      if (value.includes("cloudfront.net")) providers.add("AWS CloudFront");
      if (value.includes("fastly.net")) providers.add("Fastly");
      if (value.includes("akamai") || value.includes("edgesuite.net") || value.includes("edgekey.net")) providers.add("Akamai");
      if (value.includes("azurefd.net") || value.includes("azureedge.net")) providers.add("Azure");
      if (value.includes("b-cdn.net") || value.includes("bunnycdn.com")) providers.add("Bunny");
      if (value.includes("cdn77.net") || value.includes("cdn77.org")) providers.add("CDN77");
      if (value.includes("incapdns.net") || value.includes("impervadns.net")) providers.add("Imperva");
      if (value.includes("vercel")) providers.add("Vercel");
      if (value.includes("netlify")) providers.add("Netlify");
    }
  }
  return [...providers];
}

function originCandidatesFor(results, edgeProviders) {
  if (!edgeProviders.length) return [];
  const byName = new Map();
  for (const result of results) {
    if (!result.label.startsWith("ORIGIN-")) continue;
    for (const answer of result.answers || []) {
      const value = String(answer.data || "");
      if (!isKnownEdgeAddress(value, edgeProviders)) {
        const candidate = byName.get(result.name) || { name: result.name, addresses: [], provider: edgeProviders.join(", ") };
        candidate.addresses.push(value);
        byName.set(result.name, candidate);
      }
    }
  }
  return [...byName.values()].map((candidate) => ({
    ...candidate,
    addresses: [...new Set(candidate.addresses)].sort(),
  }));
}

function isKnownEdgeAddress(value, edgeProviders) {
  return edgeProviders.includes("Cloudflare") && isCloudflareAddress(value);
}

function isCloudflareAddress(value) {
  return /^(173\.245\.|103\.21\.|103\.22\.|103\.31\.|141\.101\.|108\.162\.|190\.93\.|188\.114\.|197\.234\.|198\.41\.|162\.158\.|104\.1[6-9]\.|104\.2[0-7]\.|172\.6[4-9]\.|172\.7[0-1]\.|131\.0\.72\.)/.test(value);
}

function isSpecialAddress(value) {
  if (/^(10\.|127\.|169\.254\.|192\.168\.)/.test(value)) return true;
  if (/^172\.(1[6-9]|2\d|3[0-1])\./.test(value)) return true;
  if (/^(0\.|224\.|255\.)/.test(value)) return true;
  if (/^(::1|fc|fd|fe80)/i.test(value)) return true;
  return false;
}

function stableSeed(domain) {
  return [...domain].reduce((sum, char, index) => sum + (index + 1) * char.charCodeAt(0), 0) % 10000000;
}

function escapeHtml(value) {
  return String(value).replace(/[&<>"']/g, (char) => ({
    "&": "&amp;",
    "<": "&lt;",
    ">": "&gt;",
    '"': "&quot;",
    "'": "&#039;",
  })[char]);
}
