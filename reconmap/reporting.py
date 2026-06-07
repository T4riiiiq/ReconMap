from __future__ import annotations

import csv
import json
from dataclasses import dataclass
from dataclasses import field
from pathlib import Path
from typing import Any, Callable

from reconmap.dnsmap import email_security_hints, resolved_ips
from reconmap.httpmap import SECURITY_HEADERS
from reconmap.pivot import relationship_text


@dataclass
class ScanResult:
    summary: dict[str, Any]
    hosts: list[str]
    dns_rows: list[dict[str, Any]]
    http_rows: list[dict[str, Any]]
    tls_rows: list[dict[str, Any]]
    sources: dict[str, str]
    relationships: list[dict[str, Any]] = field(default_factory=list)


def _write_csv(path: Path, rows: list[dict[str, Any]], fields: list[str]) -> None:
    with path.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=fields, extrasaction="ignore")
        writer.writeheader()
        writer.writerows(rows)


def build_summary(
    domain: str,
    hosts: list[str],
    dns_rows: list[dict[str, Any]],
    http_rows: list[dict[str, Any]],
    tls_rows: list[dict[str, Any]],
    notes: list[str],
    http_checks_count: int | None = None,
) -> dict[str, Any]:
    missing = {
        label: sum(not bool(row[label]) for row in http_rows)
        for label in SECURITY_HEADERS
    }
    return {
        "root_domain": domain,
        "resolved_ips": resolved_ips(dns_rows, domain),
        "nameserver_count": sum(row["type"] == "NS" and bool(row["value"]) for row in dns_rows),
        "mx_record_count": sum(row["type"] == "MX" and bool(row["value"]) for row in dns_rows),
        "email_security_hints": email_security_hints(dns_rows),
        "asset_count": len(hosts),
        "http_checks_count": http_checks_count if http_checks_count is not None else len(http_rows),
        "http_service_count": len(http_rows),
        "tls_certificate_count": len(tls_rows),
        "earliest_tls_expiry": min(
            (str(row["expiry_date"]) for row in tls_rows if row["expiry_date"]),
            default="",
        ),
        "missing_security_headers": missing,
        "investigation_notes": notes,
        "disclaimer": "Informational mapping only; results are not vulnerability validation.",
    }


def _missing_headers(row: dict[str, Any]) -> str:
    labels = {
        "hsts": "HSTS",
        "csp": "CSP",
        "x_frame_options": "XFO",
        "x_content_type_options": "XCTO",
        "referrer_policy": "Referrer-Policy",
    }
    return ",".join(label for key, label in labels.items() if not row[key]) or "none"


def _issuer_name(value: str) -> str:
    for part in value.split(","):
        key, _, name = part.strip().partition("=")
        if key.lower() in {"commonname", "organizationname"} and name:
            return name
    return value or "not disclosed"


def _markdown_table(headers: list[str], rows: list[list[Any]]) -> str:
    if not rows:
        return "_None observed._"
    clean = lambda value: str(value).replace("|", r"\|").replace("\n", " ")
    lines = [
        "| " + " | ".join(headers) + " |",
        "| " + " | ".join("---" for _ in headers) + " |",
    ]
    lines.extend("| " + " | ".join(clean(value) for value in row) + " |" for row in rows)
    return "\n".join(lines)


def render_report(result: ScanResult) -> str:
    summary = result.summary
    hints = summary["email_security_hints"]
    asset_rows = [
        [host, ", ".join(resolved_ips(result.dns_rows, host)) or "-", result.sources.get(host, "known")]
        for host in result.hosts
    ]
    dns_record_rows = [
        [row["name"], row["type"], row["value"] or "-", row["error"] or "-"]
        for row in result.dns_rows
    ]
    http_rows = [
        [
            row["url"],
            row["status"],
            row["title"] or "-",
            row["server"] or "-",
            row.get("content_length", "") or "-",
            row.get("redirect_chain", "") or "-",
            row.get("cookies", "") or "-",
            row.get("technologies", "") or "-",
            row.get("referenced_hosts", "") or "-",
            _missing_headers(row),
        ]
        for row in result.http_rows
    ]
    tls_rows = [
        [
            f"{row['host']}:{row.get('port', 443)}",
            _issuer_name(str(row["issuer"])),
            str(row["expiry_date"])[:10],
            row["days_until_expiry"],
            len([san for san in str(row["sans"]).split("; ") if san]),
            row["sans"] or "-",
        ]
        for row in result.tls_rows
    ]
    header_rows = [
        [name, count]
        for name, count in summary["missing_security_headers"].items()
    ]
    intelligence = summary.get("intelligence", {})
    inventory_rows = [
        [row["host"], row["category"], result.sources.get(row["host"], "known")]
        for row in intelligence.get("asset_inventory", [])
    ]
    redirect_rows = [
        [row["url"], row["chain"]]
        for row in intelligence.get("interesting_redirects", [])
    ]
    certificate_rows = [
        [row["host"], _issuer_name(row["issuer"]), str(row["expires"])[:10], row["sans"]]
        for row in intelligence.get("interesting_certificates", [])
    ]
    provider_rows = [
        ["Cloud", ", ".join(intelligence.get("cloud_providers", [])) or "-"],
        ["Identity", ", ".join(intelligence.get("identity_providers", [])) or "-"],
        ["Email", ", ".join(intelligence.get("email_providers", [])) or "-"],
    ]
    evidence_rows = [
        [row["area"], row["provider"], row.get("service", row["provider"]), row["evidence"]]
        for key in ("cloud_evidence", "identity_evidence", "email_evidence")
        for row in intelligence.get(key, [])
    ]
    ip_rows = [
        [row["address"], row["asn"] or "-", row["provider"] or "-", row["prefix"] or "-", row["error"] or "-"]
        for row in summary.get("ip_intelligence", [])
    ]
    external_rows = [
        [row["source"], row["target"]]
        for row in summary.get("external_references", [])
    ]
    interesting_hosts = [
        [row["host"], row["category"]]
        for row in intelligence.get("interesting_hosts", [])
    ]
    relationship_rows = [
        [row["source"], row["relation"], row["target"], row["depth"], row["status"]]
        for row in result.relationships
    ]
    return f"""# ReconMap Report: {summary['root_domain']}

## DNS Summary

- Resolved IPs: **{len(summary['resolved_ips'])}**
- Nameservers: **{summary['nameserver_count']}**
- MX records: **{summary['mx_record_count']}**
- SPF: **{'present' if hints['spf'] else 'not observed'}**
- DMARC: **{'present' if hints['dmarc'] else 'not observed'}**

## Discovered Assets

{_markdown_table(["Host", "IPs", "Source"], asset_rows)}

## DNS Records

{_markdown_table(["Name", "Type", "Value", "Error"], dns_record_rows)}

## HTTP Services

{_markdown_table(["URL", "Status", "Title", "Server", "Content Length", "Redirect Chain", "Cookies", "Technologies", "Referenced Hostnames", "Missing Headers"], http_rows)}

## TLS Certificates

{_markdown_table(["Host", "Issuer", "Expires", "Days Left", "SAN Count", "SANs"], tls_rows)}

## Security Header Overview

{_markdown_table(["Header", "Missing From Services"], header_rows)}

## Attack Surface Inventory

{_markdown_table(["Host", "Category", "Source"], inventory_rows)}

## Provider Intelligence

{_markdown_table(["Area", "Observed Indicators"], provider_rows)}

## Provider Evidence

{_markdown_table(["Area", "Provider", "Service", "Evidence"], evidence_rows)}

## IP Intelligence

{_markdown_table(["Address", "ASN", "Provider", "Prefix", "Error"], ip_rows)}

## Historical Certificate SANs

{_markdown_table(["Certificate-Derived Name"], [[name] for name in summary.get("historical_sans", [])])}

## Interesting Hosts

{_markdown_table(["Host", "Category"], interesting_hosts)}

## Interesting Redirects

{_markdown_table(["URL", "Redirect Chain"], redirect_rows)}

## Interesting Certificates

{_markdown_table(["Host", "Issuer", "Expires", "SANs"], certificate_rows)}

## Interesting Cloud References

{_markdown_table(["Provider"], [[name] for name in intelligence.get("interesting_cloud_references", [])])}

## Interesting Email Infrastructure

{_markdown_table(["Provider"], [[name] for name in intelligence.get("interesting_email_infrastructure", [])])}

## External References

{_markdown_table(["Source", "Referenced Host"], external_rows)}

## Discovery Chains

{_markdown_table(["Source", "Evidence", "Target", "Depth", "Status"], relationship_rows)}

## Relationship Map

```text
{relationship_text(summary['root_domain'], result.relationships).rstrip()}
```

## Informational Disclaimer

**Informational mapping only, not vulnerability validation.** ReconMap performs passive and lightweight active checks. It does not exploit vulnerabilities, brute force names or credentials, scan directories, test passwords, or perform destructive actions.
"""


def write_outputs(
    output_dir: str | Path,
    domain: str,
    hosts: list[str],
    dns_rows: list[dict[str, Any]],
    http_rows: list[dict[str, Any]],
    tls_rows: list[dict[str, Any]],
    notes: list[str],
    summary: dict[str, Any] | None = None,
    progress: Callable[..., None] | None = None,
    sources: dict[str, str] | None = None,
    relationships: list[dict[str, Any]] | None = None,
) -> dict[str, Any]:
    output = Path(output_dir)
    output.mkdir(parents=True, exist_ok=True)
    _write_csv(output / "dns.csv", dns_rows, ["name", "type", "value", "error"])
    if progress:
        progress(f"Wrote {output / 'dns.csv'}", success=True)
    _write_csv(
        output / "http.csv",
        http_rows,
        [
            "host", "url", "final_url", "redirect_chain", "status", "title", "server",
            "content_length", "cookies", "technologies", *SECURITY_HEADERS, "error",
            "csp_value", "referenced_hosts",
        ],
    )
    if progress:
        progress(f"Wrote {output / 'http.csv'}", success=True)
    _write_csv(
        output / "tls.csv",
        tls_rows,
        ["host", "port", "subject", "issuer", "sans", "expiry_date", "days_until_expiry", "error"],
    )
    if progress:
        progress(f"Wrote {output / 'tls.csv'}", success=True)
    _write_csv(
        output / "pivots.csv",
        relationships or [],
        ["source", "relation", "target", "depth", "status"],
    )
    if progress:
        progress(f"Wrote {output / 'pivots.csv'}", success=True)
    (output / "relationships.txt").write_text(
        relationship_text(domain, relationships or []),
        encoding="utf-8",
    )
    if progress:
        progress(f"Wrote {output / 'relationships.txt'}", success=True)
    summary = summary or build_summary(domain, hosts, dns_rows, http_rows, tls_rows, notes)
    (output / "summary.json").write_text(json.dumps(summary, indent=2) + "\n", encoding="utf-8")
    if progress:
        progress(f"Wrote {output / 'summary.json'}", success=True)
    result = ScanResult(summary, hosts, dns_rows, http_rows, tls_rows, sources or {}, relationships or [])
    (output / "report.md").write_text(render_report(result), encoding="utf-8")
    if progress:
        progress(f"Wrote {output / 'report.md'}", success=True)
    return summary


def _terminal_table(headers: list[str], rows: list[list[Any]], max_rows: int) -> str:
    displayed = rows if max_rows == 0 else rows[:max_rows]
    if not displayed:
        return "(none observed)"
    widths = [
        min(max(len(str(header)), *(len(str(row[index])) for row in displayed)), limit)
        for index, (header, limit) in enumerate(zip(headers, [32, 42, 24, 22, 42]))
    ]

    def line(row: list[Any]) -> str:
        cells = []
        for value, width in zip(row, widths):
            text = str(value)
            if len(text) > width:
                text = text[: max(1, width - 3)] + "..."
            cells.append(text.ljust(width))
        return "  ".join(cells).rstrip()

    output = [line(headers), line(["-" * width for width in widths])]
    output.extend(line(row) for row in displayed)
    omitted = len(rows) - len(displayed)
    if omitted:
        output.append(f"... {omitted} more rows omitted. Use --max-rows 0 to show all.")
    return "\n".join(output)


def render_console_summary(
    result: ScanResult | dict[str, Any],
    output_dir: str | Path | None = None,
    max_rows: int = 20,
) -> str:
    if isinstance(result, dict):
        result = ScanResult(result, [], [], [], [], {})
    summary = result.summary
    hints = summary["email_security_hints"]
    title = summary["root_domain"] or "provided hosts"
    asset_rows = [
        [host, ", ".join(resolved_ips(result.dns_rows, host)) or "-", result.sources.get(host, "known")]
        for host in result.hosts
    ]
    http_rows = [
        [row["url"], row["status"], row["title"] or "-", row["server"] or "-", _missing_headers(row)]
        for row in result.http_rows
    ]
    tls_rows = [
        [
            f"{row['host']}:{row.get('port', 443)}",
            _issuer_name(str(row["issuer"])),
            str(row["expiry_date"])[:10],
            row["days_until_expiry"],
            len([san for san in str(row["sans"]).split("; ") if san]),
        ]
        for row in result.tls_rows
    ]
    intelligence = summary.get("intelligence", {})
    intelligence_rows = [
        ["Cloud", ", ".join(intelligence.get("cloud_providers", [])) or "-"],
        ["Identity", ", ".join(intelligence.get("identity_providers", [])) or "-"],
        ["Email", ", ".join(intelligence.get("email_providers", [])) or "-"],
        ["Cloud References", ", ".join(intelligence.get("interesting_cloud_references", [])) or "-"],
    ]
    relationship_rows = [
        [row["source"], row["relation"], row["target"], row["status"]]
        for row in result.relationships
    ]
    dns_rows = [
        [row["type"], row["name"], row["value"] or "-", row["error"] or "-"]
        for row in result.dns_rows
    ]
    san_rows = [
        [f"{row['host']}:{row.get('port', 443)}", row["sans"] or "-", _issuer_name(str(row["issuer"])), str(row["expiry_date"])[:10]]
        for row in result.tls_rows
    ]
    redirect_rows = [
        [row["url"], row.get("redirect_chain", "") or "-"]
        for row in result.http_rows if row.get("redirect_chain")
    ]
    provider_evidence_rows = [
        [row["area"], row["provider"], row.get("service", row["provider"]), row["evidence"]]
        for key in ("cloud_evidence", "identity_evidence", "email_evidence")
        for row in intelligence.get(key, [])
    ]
    ip_rows = [
        [row["address"], row["asn"] or "-", row["provider"] or "-", row["prefix"] or "-"]
        for row in summary.get("ip_intelligence", [])
    ]
    external_rows = [
        [row["source"], row["target"]]
        for row in summary.get("external_references", [])
    ]
    text = f"""ReconMap scan report for {title}

DNS Summary

* Resolved IPs: {len(summary['resolved_ips'])}
* Nameservers: {summary['nameserver_count']}
* MX records: {summary['mx_record_count']}
* SPF: {'present' if hints['spf'] else 'not observed'}
* DMARC: {'present' if hints['dmarc'] else 'not observed'}

DNS Records
{_terminal_table(["TYPE", "NAME", "VALUE", "ERROR"], dns_rows, max_rows)}

Discovered Assets
{_terminal_table(["HOST", "IPS", "SOURCE"], asset_rows, max_rows)}

HTTP Services
{_terminal_table(["URL", "STATUS", "TITLE", "SERVER", "MISSING HEADERS"], http_rows, max_rows)}

TLS Certificates
{_terminal_table(["HOST", "ISSUER", "EXPIRES", "DAYS LEFT", "SAN COUNT"], tls_rows, max_rows)}

TLS Evidence
{_terminal_table(["HOST", "SAN NAMES", "ISSUER", "EXPIRY"], san_rows, max_rows)}

Redirect Evidence
{_terminal_table(["URL", "FULL REDIRECT CHAIN"], redirect_rows, max_rows)}

Intelligence Overview
{_terminal_table(["AREA", "OBSERVED INDICATORS"], intelligence_rows, max_rows)}

Provider Evidence
{_terminal_table(["AREA", "PROVIDER", "SERVICE", "EVIDENCE"], provider_evidence_rows, max_rows)}

IP Intelligence
{_terminal_table(["ADDRESS", "ASN", "PROVIDER", "PREFIX"], ip_rows, max_rows)}

External References
{_terminal_table(["SOURCE", "REFERENCED HOST"], external_rows, max_rows)}

Discovery Chains
{_terminal_table(["SOURCE", "EVIDENCE", "TARGET", "STATUS"], relationship_rows, max_rows)}"""
    if output_dir:
        output = Path(output_dir)
        files = "\n".join(f"* {output / name}" for name in (
            "dns.csv", "http.csv", "tls.csv", "pivots.csv",
            "relationships.txt", "summary.json", "report.md"
        ))
        text += f"\n\nOutput written to:\n\n{files}"
    return text
