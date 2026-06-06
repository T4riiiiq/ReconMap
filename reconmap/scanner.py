from __future__ import annotations

from pathlib import Path

from reconmap.discovery import discover
from reconmap.dnsmap import collect_dns
from reconmap.httpmap import fingerprint_hosts
from reconmap.reporting import write_outputs
from reconmap.tlsmap import inspect_hosts
from reconmap.util import read_hosts


def scan(
    domain: str,
    output: str,
    subdomains_file: str | None,
    passive: bool,
    timeout: float,
    delay: float,
) -> dict:
    manual = read_hosts(subdomains_file) if subdomains_file else []
    hosts, notes = discover(domain, manual, passive, timeout)
    dns_rows = []
    for host in hosts:
        dns_rows.extend(collect_dns(host, timeout) if host == domain else collect_host_addresses(host, timeout))
    http_rows = fingerprint_hosts(hosts, timeout, delay)
    tls_hosts = sorted({row["host"] for row in http_rows if str(row["url"]).startswith("https://")})
    tls_rows = inspect_hosts(tls_hosts, timeout, delay)
    return write_outputs(output, domain, hosts, dns_rows, http_rows, tls_rows, notes)


def collect_host_addresses(host: str, timeout: float) -> list[dict]:
    from reconmap.dnsmap import query_record

    rows = []
    for record_type in ("A", "AAAA"):
        values, error = query_record(host, record_type, timeout)
        rows.extend({"name": host, "type": record_type, "value": value, "error": ""} for value in values)
        if error:
            rows.append({"name": host, "type": record_type, "value": "", "error": error})
    return rows


def dns_only(domain: str, output: str, timeout: float) -> dict:
    return write_outputs(output, domain, [domain], collect_dns(domain, timeout), [], [], [])


def http_only(host_file: str, output: str, timeout: float, delay: float) -> dict:
    hosts = read_hosts(host_file)
    http_rows = fingerprint_hosts(hosts, timeout, delay)
    tls_hosts = sorted({row["host"] for row in http_rows if str(row["url"]).startswith("https://")})
    tls_rows = inspect_hosts(tls_hosts, timeout, delay)
    return write_outputs(output, "", hosts, [], http_rows, tls_rows, [])
