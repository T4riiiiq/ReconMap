# ReconMap Report: example.com

## DNS Summary

- Resolved IPs: **1**
- Nameservers: **0**
- MX records: **1**
- SPF: **present**
- DMARC: **present**

## Discovered Assets

| Host | IPs | Source |
| --- | --- | --- |
| example.com | 192.0.2.10 | root |
| www.example.com | 192.0.2.20 | manual |

## HTTP Services

| URL | Status | Title | Server | Missing Headers |
| --- | --- | --- | --- | --- |
| https://example.com/ | 200 | Example Domain | ExampleServer | CSP,Referrer-Policy |

## TLS Certificates

| Host | Issuer | Expires | Days Left | SAN Count |
| --- | --- | --- | --- | --- |
| example.com | Example CA | 2030-01-01 | 100 | 2 |

## Security Header Overview

| Header | Missing From Services |
| --- | --- |
| HSTS | 0 |
| CSP | 1 |
| X-Frame-Options | 0 |
| X-Content-Type-Options | 0 |
| Referrer-Policy | 1 |

## Informational Disclaimer

**Informational mapping only, not vulnerability validation.**
