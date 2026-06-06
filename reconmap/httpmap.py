from __future__ import annotations

import re
import urllib.error
import urllib.parse
import urllib.request
from html import unescape
from typing import Any, Callable

from reconmap.util import RateLimiter


TITLE_RE = re.compile(r"<title[^>]*>(.*?)</title>", re.IGNORECASE | re.DOTALL)
GENERATOR_RE = re.compile(
    r'<meta[^>]+name=["\']generator["\'][^>]+content=["\']([^"\']+)',
    re.IGNORECASE,
)
SECURITY_HEADERS = {
    "hsts": "strict-transport-security",
    "csp": "content-security-policy",
    "x_frame_options": "x-frame-options",
    "x_content_type_options": "x-content-type-options",
    "referrer_policy": "referrer-policy",
}


def detect_technologies(headers: Any, body: str) -> list[str]:
    technologies: set[str] = set()
    server = headers.get("Server", "")
    powered_by = headers.get("X-Powered-By", "")
    if server:
        technologies.add(server)
    if powered_by:
        technologies.add(powered_by)
    generator = GENERATOR_RE.search(body)
    if generator:
        technologies.add(unescape(generator.group(1)).strip())
    lower = body.lower()
    if "wp-content/" in lower or "wp-includes/" in lower:
        technologies.add("WordPress")
    return sorted(technologies)


def probe_url(url: str, timeout: float) -> dict[str, Any]:
    request = urllib.request.Request(
        url,
        headers={"User-Agent": "ReconMap/0.1 (+informational attack surface mapping)"},
    )
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            raw = response.read(131072)
            charset = response.headers.get_content_charset() or "utf-8"
            body = raw.decode(charset, errors="replace")
            title_match = TITLE_RE.search(body)
            headers = {key.lower(): value for key, value in response.headers.items()}
            return {
                "host": urllib.parse.urlparse(response.url).hostname or "",
                "url": url,
                "final_url": response.url,
                "status": response.status,
                "title": unescape(title_match.group(1)).strip() if title_match else "",
                "server": response.headers.get("Server", ""),
                "technologies": "; ".join(detect_technologies(response.headers, body)),
                **{name: header in headers for name, header in SECURITY_HEADERS.items()},
                "error": "",
            }
    except urllib.error.HTTPError as exc:
        headers = {key.lower(): value for key, value in exc.headers.items()}
        return {
            "host": exc.url.split("/")[2].split(":")[0],
            "url": url,
            "final_url": exc.url,
            "status": exc.code,
            "title": "",
            "server": exc.headers.get("Server", ""),
            "technologies": "",
            **{name: header in headers for name, header in SECURITY_HEADERS.items()},
            "error": "",
        }
    except (urllib.error.URLError, TimeoutError, ValueError) as exc:
        return {
            "host": url.split("/")[2].split(":")[0],
            "url": url,
            "final_url": "",
            "status": "",
            "title": "",
            "server": "",
            "technologies": "",
            **{name: False for name in SECURITY_HEADERS},
            "error": str(exc),
        }


def fingerprint_hosts(
    hosts: list[str],
    timeout: float,
    delay: float,
    progress: Callable[[str], None] | None = None,
) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    limiter = RateLimiter(delay)
    for host in hosts:
        for scheme in ("http", "https"):
            limiter.wait()
            url = f"{scheme}://{host}/"
            if progress:
                progress(f"Checking {scheme.upper()}: {url}")
            row = probe_url(url, timeout)
            if not row["error"] or row["status"]:
                rows.append(row)
    return rows
