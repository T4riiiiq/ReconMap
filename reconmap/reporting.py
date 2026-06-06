from __future__ import annotations

import csv
import json
from pathlib import Path
from typing import Any, Callable

from reconmap.dnsmap import email_security_hints, resolved_ips
from reconmap.httpmap import SECURITY_HEADERS


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


def render_report(
    summary: dict[str, Any],
    hosts: list[str],
    http_rows: list[dict[str, Any]],
    tls_rows: list[dict[str, Any]],
) -> str:
    missing_lines = "\n".join(
        f"- `{name}` missing from {count} responding service(s)"
        for name, count in summary["missing_security_headers"].items()
    )
    service_lines = "\n".join(
        f"- `{row['url']}`: HTTP {row['status']}, title `{row['title'] or 'n/a'}`, server `{row['server'] or 'not disclosed'}`"
        for row in http_rows
    ) or "- No responding HTTP/S services observed."
    tls_lines = "\n".join(
        f"- `{row['host']}`: expires {row['expiry_date']} ({row['days_until_expiry']} days)"
        for row in tls_rows
    ) or "- No validated TLS certificates observed."
    notes = "\n".join(f"- {note}" for note in summary["investigation_notes"]) or "- None."
    assets = "\n".join(f"- `{host}`" for host in hosts)
    return f"""# ReconMap Report: {summary['root_domain']}

## Executive Summary

ReconMap identified **{summary['asset_count']}** in-scope public asset(s), **{summary['http_service_count']}** responding HTTP/S service(s), and **{summary['tls_certificate_count']}** validated TLS certificate(s).

## Discovered Assets

{assets}

## Exposed HTTP Services

{service_lines}

## Missing Security Headers Summary

{missing_lines}

## TLS Expiry Notes

{tls_lines}

## Investigation Notes

{notes}

## Disclaimer

**Informational mapping only, not vulnerability validation.** ReconMap performs passive and lightweight active checks. It does not exploit vulnerabilities, brute force names or credentials, scan directories, or perform destructive actions.
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
    (output / "report.md").write_text(render_report(summary, hosts, http_rows, tls_rows), encoding="utf-8")
    if progress:
        progress(f"Wrote {output / 'report.md'}", success=True)
    return summary


def render_console_summary(summary: dict[str, Any], output_dir: str | Path | None = None) -> str:
    hints = summary["email_security_hints"]
    missing = summary["missing_security_headers"]
    expiry = summary["earliest_tls_expiry"][:10] if summary["earliest_tls_expiry"] else "none observed"
    title = summary["root_domain"] or "provided hosts"
    text = f"""ReconMap scan report for {title}

DNS

* Resolved IPs: {len(summary['resolved_ips'])}
* Nameservers: {summary['nameserver_count']}
* MX records: {summary['mx_record_count']}
* SPF: {'present' if hints['spf'] else 'not observed'}
* DMARC: {'present' if hints['dmarc'] else 'not observed'}

HTTP

* HTTP services checked: {summary['http_checks_count']}
* Responsive services: {summary['http_service_count']}
* Missing HSTS: {missing['hsts']}
* Missing CSP: {missing['csp']}

TLS

* Certificates observed: {summary['tls_certificate_count']}
* Earliest expiry: {expiry}"""
    if output_dir:
        output = Path(output_dir)
        files = "\n".join(f"* {output / name}" for name in (
            "hosts.csv", "dns.csv", "http.csv", "tls.csv", "summary.json", "report.md"
        ))
        text += f"\n\nOutput written to:\n\n{files}"
    return text
