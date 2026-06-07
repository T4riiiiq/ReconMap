from __future__ import annotations

from typing import Callable

from reconmap.discovery import discover
from reconmap.dnsmap import collect_dns, collect_ptr
from reconmap.httpmap import fingerprint_hosts, fingerprint_target
from reconmap.intelligence import analyze
from reconmap.pivot import PivotPolicy, evidence_candidates
from reconmap.reporting import ScanResult, build_summary, write_outputs
from reconmap.tlsmap import inspect_hosts, inspect_tls
from reconmap.util import is_ip, read_hosts


def scan(
    domain: str,
    output: str | None,
    subdomains_file: str | None,
    passive: bool,
    timeout: float,
    delay: float,
    progress: Callable[..., None] | None = None,
    pivot: bool = False,
    pivot_depth: int = 1,
    max_assets: int = 50,
    same_domain_only: bool = True,
    include_external: bool = False,
    max_references: int = 100,
) -> ScanResult:
    manual = read_hosts(subdomains_file) if subdomains_file else []
    if is_ip(domain):
        hosts, notes, sources = [domain], [], {domain: "root"}
    else:
        hosts, notes, sources = discover(domain, manual, passive, timeout)
    if pivot and len(hosts) > max_assets:
        retained = [domain] + [host for host in hosts if host != domain][:max_assets - 1]
        omitted = [host for host in hosts if host not in retained]
        hosts = retained
        sources = {host: sources[host] for host in hosts}
        notes.append(f"Initial discovery omitted {len(omitted)} asset(s) due to --max-assets.")
    dns_rows: list[dict] = []
    http_rows: list[dict] = []
    tls_rows: list[dict] = []
    relationships: list[dict] = []
    scanned: set[str] = set()

    def collect_asset(host: str) -> None:
        if progress:
            progress(f"Resolving DNS records for {host}")
        if is_ip(host):
            dns_rows.extend(collect_ptr(host, timeout))
            asset_http = fingerprint_target(host, timeout, delay, progress, ip_target=True)
            http_rows.extend(asset_http)
            for port in (443, 8443):
                if progress:
                    progress(f"Fetching TLS certificate for {host}:{port}")
                row = inspect_tls(host, timeout, port)
                if not row["error"] or row["subject"]:
                    tls_rows.append(row)
        else:
            dns_rows.extend(collect_dns(host, timeout))
            asset_http = fingerprint_target(host, timeout, delay, progress)
            http_rows.extend(asset_http)
            if any(str(row["url"]).startswith(f"https://{host}/") for row in asset_http):
                tls_rows.extend(inspect_hosts([host], timeout, delay, progress))
        scanned.add(host)

    for host in list(hosts):
        collect_asset(host)

    if pivot:
        policy = PivotPolicy(domain, pivot_depth, max_assets, same_domain_only, include_external, max_references)
        queue = [(host, 0) for host in hosts]
        reference_count = 0
        while queue:
            asset, depth = queue.pop(0)
            if asset not in scanned:
                collect_asset(asset)
            asset_dns = [row for row in dns_rows if row["name"] == asset]
            asset_http = [row for row in http_rows if row["host"] == asset]
            asset_tls = [row for row in tls_rows if row["host"] == asset]
            for relation, candidate in evidence_candidates(asset, asset_dns, asset_http, asset_tls):
                if reference_count >= policy.max_references:
                    break
                reference_count += 1
                next_depth = depth + 1
                status = "queued"
                if next_depth > policy.depth:
                    status = "depth-limit"
                elif candidate in scanned or any(candidate == queued for queued, _ in queue):
                    status = "already-known"
                elif len(scanned) + len(queue) >= policy.max_assets:
                    status = "asset-limit"
                elif not policy.allows(candidate, relation):
                    status = "external-evidence-only"
                relationships.append({
                    "source": asset, "relation": relation, "target": candidate,
                    "depth": next_depth, "status": status,
                })
                if status == "queued":
                    queue.append((candidate, next_depth))
                    hosts.append(candidate)
                    sources[candidate] = relation

    summary = build_summary(domain, hosts, dns_rows, http_rows, tls_rows, notes, len(hosts) * 2)
    summary["intelligence"] = analyze(hosts, dns_rows, http_rows, tls_rows)
    summary["historical_sans"] = sorted(host for host, source in sources.items() if source == "crt.sh")
    summary["pivot_enabled"] = pivot
    summary["relationships"] = relationships
    if output:
        write_outputs(output, domain, hosts, dns_rows, http_rows, tls_rows, notes, summary, progress, sources, relationships)
    return ScanResult(summary, hosts, dns_rows, http_rows, tls_rows, sources, relationships)


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
    summary["intelligence"] = analyze([domain], dns_rows, [], [])
    summary["historical_sans"] = []
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
    summary["intelligence"] = analyze(hosts, [], http_rows, tls_rows)
    summary["historical_sans"] = []
    if output:
        write_outputs(output, "", hosts, [], http_rows, tls_rows, [], summary, progress, {host: "input" for host in hosts})
    return ScanResult(summary, hosts, [], http_rows, tls_rows, {host: "input" for host in hosts})
