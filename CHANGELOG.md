# Changelog

## Unreleased

- Added provider-aware CDN origin-candidate discovery for common edge providers, including Cloudflare, Fastly, AWS CloudFront, Akamai, Azure edge services, Bunny, CDN77, Gcore, Imperva, Netlify, and Vercel.
- Expanded origin discovery labels to include origin, direct, backend, server, web, load balancer, environment, legacy, and internal naming patterns.
- Added certificate-transparency-derived origin candidate expansion with `origin.` and `direct.` variants for selected names.
- Added optional harmless HTTPS metadata validation for origin candidates, including status/header comparison against the protected hostname.
- Added CSP/reporting-endpoint parsing for IP literals and backend hostnames that may disclose origin infrastructure.
- Added HTTP title pivots for Censys and URLScan.
- Added TLS certificate SAN collection and certificate-name pivots for authorized certificate reuse investigation.
- Made the default CLI inspection profile broad by enabling bounded subdomain brute forcing unless `--no-bruteforce-subdomains` is set.
- Extended origin candidate reports with edge provider, confidence, validation status, and validation evidence.
- Added browser-side GitHub Pages origin-candidate checks for common labels using DNS-over-HTTPS.
- Added a `Makefile` for dependency sync, global install/uninstall, local DNS serving, inspection, web UI hosting, tests, and linting.
- Added expanded DNS posture checks for special-use public addresses, nameserver redundancy, SOA timers, TTL posture, CAA, SPF, DMARC, MTA-STS, TLS-RPT, BIMI, and wildcard DNS.
- Added `LICENSE.txt` with the MIT license and replaced the embedded README license text with a license pointer.
