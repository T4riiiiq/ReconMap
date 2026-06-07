from __future__ import annotations

from typing import Any
import ipaddress

import dns.exception
import dns.resolver
import dns.reversename


def _clean(value: str) -> str:
    return value.rstrip(".").replace('" "', "").strip('"')


def query_record(name: str, record_type: str, timeout: float) -> tuple[list[str], str]:
    resolver = dns.resolver.Resolver()
    resolver.timeout = timeout
    resolver.lifetime = timeout
    try:
        answer = resolver.resolve(name, record_type, search=False)
        return [_clean(item.to_text()) for item in answer], ""
    except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
        return [], ""
    except (dns.exception.Timeout, dns.resolver.NoNameservers) as exc:
        return [], str(exc)
    except dns.exception.DNSException as exc:
        return [], str(exc)


def collect_dns(domain: str, timeout: float = 5.0) -> list[dict[str, Any]]:
    requests = [
        (domain, "A"),
        (domain, "AAAA"),
        (domain, "CNAME"),
        (domain, "NS"),
        (domain, "MX"),
        (domain, "TXT"),
        (domain, "SOA"),
        (domain, "CAA"),
        (f"_sip._tcp.{domain}", "SRV"),
        (f"_sip._tls.{domain}", "SRV"),
        (f"_submission._tcp.{domain}", "SRV"),
        (f"_dmarc.{domain}", "TXT"),
        (f"_domainkey.{domain}", "TXT"),
    ]
    rows: list[dict[str, Any]] = []
    for name, record_type in requests:
        values, error = query_record(name, record_type, timeout)
        if values:
            rows.extend(
                {"name": name, "type": record_type, "value": value, "error": ""}
                for value in values
            )
        elif error:
            rows.append({"name": name, "type": record_type, "value": "", "error": error})
    return rows


def collect_ptr(address: str, timeout: float = 5.0) -> list[dict[str, Any]]:
    try:
        name = dns.reversename.from_address(address).to_text()
    except ValueError as exc:
        return [{"name": address, "type": "PTR", "value": "", "error": str(exc)}]
    values, error = query_record(name, "PTR", timeout)
    if values:
        return [{"name": address, "type": "PTR", "value": value, "error": ""} for value in values]
    return [{"name": address, "type": "PTR", "value": "", "error": error}] if error else []


def collect_asn(address: str, timeout: float = 5.0) -> dict[str, str]:
    try:
        parsed = ipaddress.ip_address(address)
    except ValueError as exc:
        return {"address": address, "asn": "", "provider": "", "prefix": "", "error": str(exc)}
    if parsed.version == 4:
        reversed_address = ".".join(reversed(str(parsed).split(".")))
        query = f"{reversed_address}.origin.asn.cymru.com"
    else:
        reversed_address = ".".join(reversed(parsed.exploded.replace(":", "")))
        query = f"{reversed_address}.origin6.asn.cymru.com"
    values, error = query_record(query, "TXT", timeout)
    if not values:
        return {"address": address, "asn": "", "provider": "", "prefix": "", "error": error}
    parts = [part.strip() for part in values[0].split("|")]
    asn = parts[0] if parts else ""
    prefix = parts[1] if len(parts) > 1 else ""
    provider_values, provider_error = query_record(f"AS{asn}.asn.cymru.com", "TXT", timeout) if asn else ([], "")
    provider_parts = [part.strip() for part in provider_values[0].split("|")] if provider_values else []
    provider = provider_parts[-1] if provider_parts else ""
    return {"address": address, "asn": asn, "provider": provider, "prefix": prefix, "error": error or provider_error}


def resolved_ips(rows: list[dict[str, Any]], host: str) -> list[str]:
    return sorted(
        {
            str(row["value"])
            for row in rows
            if row["name"] == host and row["type"] in {"A", "AAAA"} and row["value"]
        }
    )


def email_security_hints(rows: list[dict[str, Any]]) -> dict[str, bool]:
    txt_rows = [row for row in rows if row["type"] == "TXT" and row["value"]]
    txt = [str(row["value"]).lower() for row in txt_rows]
    return {
        "spf": any(value.startswith("v=spf1") for value in txt),
        "dmarc": any(value.startswith("v=dmarc1") for value in txt),
        "dkim_hint": any(
            "dkim" in value or "domainkey" in str(row["name"]).lower()
            for row, value in zip(txt_rows, txt)
        ),
    }
