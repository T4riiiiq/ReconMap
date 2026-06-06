from __future__ import annotations

import csv
import json
from pathlib import Path
from typing import Any

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
) -> dict[str, Any]:
    missing = {
        label: sum(not bool(row[label]) for row in http_rows)
        for label in SECURITY_HEADERS
    }
    return {
        "root_domain": domain,
        "resolved_ips": resolved_ips(dns_rows, domain),
        "email_security_hints": email_security_hints(dns_rows),
        "asset_count": len(hosts),
        "http_service_count": len(http_rows),
        "tls_certificate_count": len(tls_rows),
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
) -> dict[str, Any]:
    output = Path(output_dir)
    output.mkdir(parents=True, exist_ok=True)
    host_rows = [{"host": host, "resolved_ips": "; ".join(resolved_ips(dns_rows, host))} for host in hosts]
    _write_csv(output / "hosts.csv", host_rows, ["host", "resolved_ips"])
    _write_csv(output / "dns.csv", dns_rows, ["name", "type", "value", "error"])
    _write_csv(
        output / "http.csv",
        http_rows,
        ["host", "url", "final_url", "status", "title", "server", "technologies", *SECURITY_HEADERS, "error"],
    )
    _write_csv(
        output / "tls.csv",
        tls_rows,
        ["host", "subject", "issuer", "sans", "expiry_date", "days_until_expiry", "error"],
    )
    summary = build_summary(domain, hosts, dns_rows, http_rows, tls_rows, notes)
    (output / "summary.json").write_text(json.dumps(summary, indent=2) + "\n", encoding="utf-8")
    (output / "report.md").write_text(render_report(summary, hosts, http_rows, tls_rows), encoding="utf-8")
    return summary
