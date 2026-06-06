from __future__ import annotations

import csv
import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable

from reconmap.dnsmap import email_security_hints, resolved_ips
from reconmap.httpmap import SECURITY_HEADERS


@dataclass
class ScanResult:
    summary: dict[str, Any]
    hosts: list[str]
    dns_rows: list[dict[str, Any]]
    http_rows: list[dict[str, Any]]
    tls_rows: list[dict[str, Any]]
    sources: dict[str, str]


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
    http_rows = [
        [row["url"], row["status"], row["title"] or "-", row["server"] or "-", _missing_headers(row)]
        for row in result.http_rows
    ]
    tls_rows = [
        [
            row["host"],
            _issuer_name(str(row["issuer"])),
            str(row["expiry_date"])[:10],
            row["days_until_expiry"],
            len([san for san in str(row["sans"]).split("; ") if san]),
        ]
        for row in result.tls_rows
    ]
    header_rows = [
        [name, count]
        for name, count in summary["missing_security_headers"].items()
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

## HTTP Services

{_markdown_table(["URL", "Status", "Title", "Server", "Missing Headers"], http_rows)}

## TLS Certificates

{_markdown_table(["Host", "Issuer", "Expires", "Days Left", "SAN Count"], tls_rows)}

## Security Header Overview

{_markdown_table(["Header", "Missing From Services"], header_rows)}

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
) -> dict[str, Any]:
    output = Path(output_dir)
    output.mkdir(parents=True, exist_ok=True)
    host_rows = [{"host": host, "resolved_ips": "; ".join(resolved_ips(dns_rows, host))} for host in hosts]
    _write_csv(output / "hosts.csv", host_rows, ["host", "resolved_ips"])
    if progress:
        progress(f"Wrote {output / 'hosts.csv'}", success=True)
    _write_csv(output / "dns.csv", dns_rows, ["name", "type", "value", "error"])
    if progress:
        progress(f"Wrote {output / 'dns.csv'}", success=True)
    _write_csv(
        output / "http.csv",
        http_rows,
        ["host", "url", "final_url", "status", "title", "server", "technologies", *SECURITY_HEADERS, "error"],
    )
    if progress:
        progress(f"Wrote {output / 'http.csv'}", success=True)
    _write_csv(
        output / "tls.csv",
        tls_rows,
        ["host", "subject", "issuer", "sans", "expiry_date", "days_until_expiry", "error"],
    )
    if progress:
        progress(f"Wrote {output / 'tls.csv'}", success=True)
    summary = summary or build_summary(domain, hosts, dns_rows, http_rows, tls_rows, notes)
    (output / "summary.json").write_text(json.dumps(summary, indent=2) + "\n", encoding="utf-8")
    if progress:
        progress(f"Wrote {output / 'summary.json'}", success=True)
    result = ScanResult(summary, hosts, dns_rows, http_rows, tls_rows, sources or {})
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
            row["host"],
            _issuer_name(str(row["issuer"])),
            str(row["expiry_date"])[:10],
            row["days_until_expiry"],
            len([san for san in str(row["sans"]).split("; ") if san]),
        ]
        for row in result.tls_rows
    ]
    text = f"""ReconMap scan report for {title}

DNS Summary

* Resolved IPs: {len(summary['resolved_ips'])}
* Nameservers: {summary['nameserver_count']}
* MX records: {summary['mx_record_count']}
* SPF: {'present' if hints['spf'] else 'not observed'}
* DMARC: {'present' if hints['dmarc'] else 'not observed'}

Discovered Assets
{_terminal_table(["HOST", "IPS", "SOURCE"], asset_rows, max_rows)}

HTTP Services
{_terminal_table(["URL", "STATUS", "TITLE", "SERVER", "MISSING HEADERS"], http_rows, max_rows)}

TLS Certificates
{_terminal_table(["HOST", "ISSUER", "EXPIRES", "DAYS LEFT", "SAN COUNT"], tls_rows, max_rows)}"""
    if output_dir:
        output = Path(output_dir)
        files = "\n".join(f"* {output / name}" for name in (
            "hosts.csv", "dns.csv", "http.csv", "tls.csv", "summary.json", "report.md"
        ))
        text += f"\n\nOutput written to:\n\n{files}"
    return text
