from __future__ import annotations

import json
import os
import urllib.error
import urllib.request

from reconmap.util import normalize_host


def securitytrails_subdomains(domain: str, timeout: float) -> tuple[list[str], str]:
    api_key = os.getenv("RECONMAP_SECURITYTRAILS_API_KEY")
    if not api_key:
        return [], "RECONMAP_SECURITYTRAILS_API_KEY is not configured"
    request = urllib.request.Request(
        f"https://api.securitytrails.com/v1/domain/{domain}/subdomains",
        headers={"APIKEY": api_key, "User-Agent": "ReconMap/0.1"},
    )
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            payload = json.load(response)
        return [
            normalize_host(f"{label}.{domain}")
            for label in payload.get("subdomains", [])
            if label
        ], ""
    except (urllib.error.URLError, TimeoutError, json.JSONDecodeError, ValueError) as exc:
        return [], str(exc)


def discover(domain: str, manual_hosts: list[str], passive: bool, timeout: float) -> tuple[list[str], list[str]]:
    hosts = {domain}
    notes: list[str] = []
    for host in manual_hosts:
        if host == domain or host.endswith(f".{domain}"):
            hosts.add(host)
        else:
            notes.append(f"Ignored out-of-scope manual host: {host}")
    if passive:
        passive_hosts, error = securitytrails_subdomains(domain, timeout)
        hosts.update(passive_hosts)
        if error:
            notes.append(f"SecurityTrails passive discovery unavailable: {error}")
    return sorted(hosts), notes
