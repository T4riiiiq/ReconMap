# ReconMap

ReconMap is a lightweight attack surface mapping utility for SOC, DFIR, and security assessment workflows.

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

It performs ordinary public DNS queries, at most one HTTP and HTTPS request per known host, and a TLS handshake. Subdomain brute forcing is deliberately absent. Passive discovery is disabled by default.

## Features

- DNS overview: A, AAAA, NS, MX, TXT, SPF, DMARC, and DKIM hints
- Known-host discovery from a manual file
- Optional SecurityTrails passive discovery when an API key is configured
- HTTP status, title, server, and header/meta-only technology hints
- HSTS, CSP, X-Frame-Options, X-Content-Type-Options, and Referrer-Policy presence
- TLS certificate subject, issuer, SANs, expiry date, and days until expiry
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

Write the six report files and print the concise summary:

```bash
reconmap scan example.com -o output/
```

Explicitly prevent file output, even when `-o` is supplied:

```bash
reconmap scan example.com -o output/ --no-files
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

Passive discovery is opt-in. Configure the provider key and add `--passive`:

```bash
export RECONMAP_SECURITYTRAILS_API_KEY="..."
reconmap scan example.com --passive -o output/
```

If no key is configured or the provider is unavailable, the scan continues and records a note.

## Output

Without `-o`, commands print results to stdout and do not write files. With `-o`, each command writes:

- `hosts.csv`
- `dns.csv`
- `http.csv`
- `tls.csv`
- `summary.json`
- `report.md`

See [`sample-output/`](sample-output/) for an example.

## Testing

```bash
python -m unittest discover -s tests
```

Tests use sample data and mocks; they do not require network access.

## Disclaimer

ReconMap provides informational mapping only, not vulnerability validation. Results can be incomplete, stale, or affected by redirects, CDNs, DNS policy, and network conditions. Review findings manually before making security decisions.

## License

MIT
