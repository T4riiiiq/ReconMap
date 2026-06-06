from __future__ import annotations

from typing import Callable

from reconmap.discovery import discover
from reconmap.dnsmap import collect_dns
from reconmap.httpmap import fingerprint_hosts
from reconmap.reporting import ScanResult, build_summary, write_outputs
from reconmap.tlsmap import inspect_hosts
from reconmap.util import read_hosts


def scan(
    domain: str,
    output: str | None,
    subdomains_file: str | None,
    passive: bool,
    timeout: float,
    delay: float,
    progress: Callable[..., None] | None = None,
) -> ScanResult:
    manual = read_hosts(subdomains_file) if subdomains_file else []
    hosts, notes = discover(domain, manual, passive, timeout)
    dns_rows = []
    for host in hosts:
        if progress:
            progress(f"Resolving DNS records for {host}")
        dns_rows.extend(collect_dns(host, timeout) if host == domain else collect_host_addresses(host, timeout))
    http_rows = fingerprint_hosts(hosts, timeout, delay, progress)
    tls_hosts = sorted({row["host"] for row in http_rows if str(row["url"]).startswith("https://")})
    tls_rows = inspect_hosts(tls_hosts, timeout, delay, progress)
    summary = build_summary(domain, hosts, dns_rows, http_rows, tls_rows, notes, len(hosts) * 2)
    manual_hosts = set(manual)
    sources = {
        host: "root" if host == domain else "manual" if host in manual_hosts else "passive"
        for host in hosts
    }
    if output:
        write_outputs(output, domain, hosts, dns_rows, http_rows, tls_rows, notes, summary, progress, sources)
    return ScanResult(summary, hosts, dns_rows, http_rows, tls_rows, sources)


def collect_host_addresses(host: str, timeout: float) -> list[dict]:
    from reconmap.dnsmap import query_record

    rows = []
    for record_type in ("A", "AAAA"):
        values, error = query_record(host, record_type, timeout)
        rows.extend({"name": host, "type": record_type, "value": value, "error": ""} for value in values)
        if error:
            rows.append({"name": host, "type": record_type, "value": "", "error": error})
    return rows


def dns_only(
    domain: str,
    output: str | None,
    timeout: float,
    progress: Callable[..., None] | None = None,
) -> ScanResult:
    if progress:
        progress(f"Resolving DNS records for {domain}")
    dns_rows = collect_dns(domain, timeout)
    summary = build_summary(domain, [domain], dns_rows, [], [], [], 0)
    if output:
        write_outputs(output, domain, [domain], dns_rows, [], [], [], summary, progress, {domain: "root"})
    return ScanResult(summary, [domain], dns_rows, [], [], {domain: "root"})


def http_only(
    host_file: str,
    output: str | None,
    timeout: float,
    delay: float,
    progress: Callable[..., None] | None = None,
) -> ScanResult:
    hosts = read_hosts(host_file)
    http_rows = fingerprint_hosts(hosts, timeout, delay, progress)
    tls_hosts = sorted({row["host"] for row in http_rows if str(row["url"]).startswith("https://")})
    tls_rows = inspect_hosts(tls_hosts, timeout, delay, progress)
    summary = build_summary("", hosts, [], http_rows, tls_rows, [], len(hosts) * 2)
    if output:
        write_outputs(output, "", hosts, [], http_rows, tls_rows, [], summary, progress, {host: "input" for host in hosts})
    return ScanResult(summary, hosts, [], http_rows, tls_rows, {host: "input" for host in hosts})
