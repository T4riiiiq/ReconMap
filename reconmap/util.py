from __future__ import annotations

import ipaddress
import re
import time
from pathlib import Path
from urllib.parse import urlsplit

from publicsuffix2 import get_sld

DOMAIN_RE = re.compile(
    r"^(?=.{1,253}\.?$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.?$",
    re.IGNORECASE,
)


def normalize_host(value: str) -> str:
    value = value.strip().lower()
    if "://" in value:
        value = urlsplit(value).hostname or ""
    value = value.rstrip(".")
    if not value or not DOMAIN_RE.match(value):
        raise ValueError(f"invalid domain or hostname: {value!r}")
    try:
        ipaddress.ip_address(value)
    except ValueError:
        return value
    raise ValueError("IP addresses are not accepted where a domain or hostname is required")


def normalize_target(value: str) -> str:
    value = value.strip().lower()
    if "://" in value:
        value = urlsplit(value).hostname or ""
    value = value.rstrip(".")
    try:
        return str(ipaddress.ip_address(value))
    except ValueError:
        return normalize_host(value)


def is_ip(value: str) -> bool:
    try:
        ipaddress.ip_address(value)
        return True
    except ValueError:
        return False


def registrable_domain(host: str) -> str:
    if is_ip(host):
        return host
    return get_sld(host.rstrip(".").lower(), strict=True) or host


def read_hosts(path: str | Path) -> list[str]:
    hosts: list[str] = []
    seen: set[str] = set()
    for line_number, line in enumerate(Path(path).read_text(encoding="utf-8").splitlines(), 1):
        value = line.strip()
        if not value or value.startswith("#"):
            continue
        try:
            host = normalize_target(value)
        except ValueError as exc:
            raise ValueError(f"{path}:{line_number}: {exc}") from exc
        if host not in seen:
            seen.add(host)
            hosts.append(host)
    return hosts


class RateLimiter:
    def __init__(self, delay: float) -> None:
        self.delay = max(0.0, delay)
        self._last_call = 0.0

    def wait(self) -> None:
        if self.delay <= 0:
            return
        remaining = self.delay - (time.monotonic() - self._last_call)
        if remaining > 0:
            time.sleep(remaining)
        self._last_call = time.monotonic()
