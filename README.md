# ReconMap

ReconMap is a terminal-first Recon Intelligence Accelerator for SOC, DFIR, and security assessment workflows.

Its job is to consolidate public attack surface intelligence that analysts would otherwise gather manually from DNS, certificates, HTTP responses, and provider-specific indicators. ReconMap exposes evidence; the analyst remains the decision engine.

ReconMap stops at evidence collection, bounded evidence-based pivoting, relationship mapping, and attack surface visibility. It intentionally does not enter Nmap, ffuf, Burp, vulnerability-scanning, or exploitation territory.

It helps analysts quickly understand:

- what public assets exist
- what services respond over HTTP/S
- what DNS records exist
- whether common security headers are present
- TLS certificate posture

ReconMap performs passive and lightweight active checks only. Use it only on assets you own or are authorized to assess.

## Safety Boundaries

ReconMap is **not**:

- a vulnerability scanner
- an exploit tool
- a brute force tool
- a directory scanner
- a password testing tool
- a replacement for Nmap, Nuclei, or Burp

It performs ordinary public DNS queries, a small fixed set of HTTP/S requests, and TLS handshakes. Subdomain brute forcing is deliberately absent. Passive discovery is disabled by default.

Redirect destinations are recorded for intelligence. ReconMap follows same-host redirects only; it does not automatically expand active checks onto external redirect targets.

### Evidence-Based Pivoting

Pivoting is disabled by default. Enable it explicitly:

```bash
reconmap scan example.com --pivot
reconmap scan example.com --pivot --pivot-depth 2 --max-assets 30
reconmap scan 192.0.2.10 --pivot
```

ReconMap can pivot from PTR records, CNAME/MX/NS infrastructure names, TLS SANs, HTTP redirects, HTML/JavaScript references, CSP references, and cloud evidence. Every relationship is recorded even when policy prevents recursive collection.

Pivot safety controls:

```bash
reconmap scan example.com --pivot \
  --pivot-depth 1 \
  --max-assets 50 \
  --max-references 100 \
  --same-domain-only
```

- Same-domain recursive collection is the default.
- External providers and identity services remain evidence-only unless `--include-external` is supplied.
- IP targets use PTR plus HTTP/S validation on ports `80`, `443`, `8080`, and `8443` only.
- ReconMap does not perform generalized port scanning, brute force, object listing, permission testing, vulnerability scanning, or exploitation.

## Architecture

ReconMap separates three responsibilities:

- **Collectors** gather public DNS, certificate, and lightweight HTTP/TLS observations.
- **Intelligence analysis** derives provider indicators, inventory categories, and interesting artifacts from collected evidence.
- **Renderers** expose both raw observations and derived indicators without declaring vulnerabilities or making assessment decisions.

Provider and asset classifications are evidence-based hints. They are intentionally presented for analyst review rather than treated as conclusions.

## Features

- DNS intelligence: A, AAAA, NS, MX, TXT, SOA, CAA, selected SRV records, SPF, DMARC, and DKIM hints
- Known-host discovery from a manual file
- Optional crt.sh certificate-derived discovery and SecurityTrails passive discovery
- Current TLS certificate subject, issuer, SANs, and expiry
- Historical certificate-derived names from crt.sh
- HTTP status, title, redirect chain, server, content length, cookies, and header/meta-only technology hints
- HSTS, CSP, X-Frame-Options, X-Content-Type-Options, and Referrer-Policy presence
- Cloud indicators for Cloudflare, AWS, Azure, GCP, Fastly, and Akamai
- Cloud reference indicators for CloudFront, API Gateway, S3, Azure Blob, and Google Storage
- Identity indicators for Okta, Auth0, Microsoft Entra, Keycloak, and OneLogin
- Email infrastructure indicators for Microsoft 365, Google Workspace, Mimecast, Proofpoint, and Cisco ESA
- Evidence-based asset inventory categories: Web, API, VPN, Mail, Auth, Admin, and Other
- Dedicated report artifacts for interesting hosts, redirects, certificates, cloud references, and email infrastructure
- CSV, JSON, and Markdown outputs
- Configurable timeouts and request delay
- Graceful per-asset network error handling

## Install

```bash
git clone https://github.com/T4riiiiq/ReconMap.git
cd ReconMap
python -m venv .venv
# Windows: .venv\Scripts\activate
# Linux/macOS: source .venv/bin/activate
python -m pip install -e .
```

## Usage

Normal scan, printing a concise Nmap-style summary to the terminal:

```bash
reconmap scan example.com
```

The terminal report includes DNS totals plus per-host asset, HTTP service, and TLS certificate tables. Each table shows up to 20 rows by default:

```bash
reconmap scan example.com --max-rows 50
reconmap scan example.com --max-rows 0  # show all rows
```

Print live progress followed by the concise summary:

```bash
reconmap scan example.com --verbose
```

Print summary JSON only:

```bash
reconmap scan example.com --json
```

Suppress normal output and print errors only:

```bash
reconmap scan example.com --quiet
```

By default, ReconMap is terminal-only and creates no files or directories.

Write report artifacts to an explicit directory:

```bash
reconmap scan example.com -o output/
```

Save to a timestamped directory such as `reconmap-example.com-20260607-153000`:

```bash
reconmap scan example.com --save
```

Explicitly force terminal-only behavior, even when `-o` is supplied:

```bash
reconmap scan example.com -o output/ --no-save
```

The same output modes apply to every command:

```bash
reconmap scan example.com --subdomains subs.txt -o output/
reconmap scan example.com --passive -o output/
reconmap http hosts.txt --json
reconmap dns example.com --verbose -o output/
```

Every active command supports a timeout and request delay:

```bash
reconmap scan example.com -o output/ --timeout 8 --delay 0.5
```

Manual host files contain one hostname per line. Blank lines and lines beginning with `#` are ignored. During `scan`, out-of-scope entries are ignored and recorded as investigation notes.

### Passive Discovery

Passive discovery is opt-in. `--passive` queries crt.sh without an API key and also uses SecurityTrails when its key is configured:

```bash
export RECONMAP_SECURITYTRAILS_API_KEY="..."
reconmap scan example.com --passive -o output/
```

If a provider is unavailable, the scan continues and records a note. Passive names retain their discovery source in the report.

## Output

Without `-o`, commands print results to stdout and do not write files. With `-o`, each command writes:

- `dns.csv`
- `http.csv`
- `tls.csv`
- `pivots.csv`
- `relationships.txt`
- `summary.json`
- `report.md`

See [`sample-output/`](sample-output/) for an example.

`summary.json` includes derived intelligence indicators and inventory classifications. These are observations based on public strings and naming patterns, not security findings or vulnerability conclusions.

External HTML, JavaScript, and CSP references are recorded separately to reduce discovery-chain noise. Show them in discovery chains when needed:

```bash
reconmap scan example.com --pivot --show-external-references
```

## Testing

```bash
python -m unittest discover -s tests
```

Tests use sample data and mocks; they do not require network access.

## Disclaimer

ReconMap provides informational mapping only, not vulnerability validation. Results can be incomplete, stale, or affected by redirects, CDNs, DNS policy, and network conditions. Review findings manually before making security decisions.

## License

MIT
