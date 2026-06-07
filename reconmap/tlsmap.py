from __future__ import annotations

import socket
import ssl
import ipaddress
from datetime import datetime, timezone
from typing import Any, Callable


def _name(parts: tuple[tuple[tuple[str, str], ...], ...]) -> str:
    return ", ".join(f"{key}={value}" for group in parts for key, value in group)


def inspect_tls(host: str, timeout: float = 5.0, port: int = 443) -> dict[str, Any]:
    row: dict[str, Any] = {
        "host": host,
        "port": port,
        "subject": "",
        "issuer": "",
        "sans": "",
        "expiry_date": "",
        "days_until_expiry": "",
        "error": "",
    }
    try:
        context = ssl.create_default_context()
        try:
            ipaddress.ip_address(host)
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
        except ValueError:
            pass
        with socket.create_connection((host, port), timeout=timeout) as raw_socket:
            with context.wrap_socket(raw_socket, server_hostname=host) as tls_socket:
                cert = tls_socket.getpeercert()
        expiry = datetime.strptime(cert["notAfter"], "%b %d %H:%M:%S %Y %Z").replace(tzinfo=timezone.utc)
        row.update(
            {
                "subject": _name(cert.get("subject", ())),
                "issuer": _name(cert.get("issuer", ())),
                "sans": "; ".join(value for kind, value in cert.get("subjectAltName", ()) if kind == "DNS"),
                "expiry_date": expiry.isoformat(),
                "days_until_expiry": (expiry - datetime.now(timezone.utc)).days,
            }
        )
    except (OSError, ssl.SSLError, ValueError, KeyError) as exc:
        row["error"] = str(exc)
    return row


def inspect_hosts(
    hosts: list[str],
    timeout: float,
    delay: float,
    progress: Callable[[str], None] | None = None,
) -> list[dict[str, Any]]:
    from reconmap.util import RateLimiter

    limiter = RateLimiter(delay)
    rows = []
    for host in hosts:
        limiter.wait()
        if progress:
            progress(f"Fetching TLS certificate for {host}:443")
        row = inspect_tls(host, timeout)
        if not row["error"] or row["subject"]:
            rows.append(row)
    return rows
