from __future__ import annotations

import re
import urllib.error
import urllib.parse
import urllib.request
from html import unescape
from typing import Any, Callable

from reconmap.util import RateLimiter


TITLE_RE = re.compile(r"<title[^>]*>(.*?)</title>", re.IGNORECASE | re.DOTALL)
URL_RE = re.compile(r"""(?:https?:)?//(?:\*\.)?([a-z0-9.-]+\.[a-z]{2,})(?::\d+)?(?:[/?"'][^\s"'<>]*)?""", re.IGNORECASE)
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


class RedirectRecorder(urllib.request.HTTPRedirectHandler):
    def __init__(self, root_host: str) -> None:
        self.chain: list[str] = []
        self.root_host = root_host

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        self.chain.append(newurl)
        if urllib.parse.urlparse(newurl).hostname != self.root_host:
            return None
        return super().redirect_request(req, fp, code, msg, headers, newurl)


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


def extract_referenced_hosts(body: str, csp: str = "") -> list[str]:
    return sorted({match.lower().rstrip(".") for match in URL_RE.findall(f"{body} {csp}")})


def probe_url(url: str, timeout: float) -> dict[str, Any]:
    request = urllib.request.Request(
        url,
        headers={"User-Agent": "ReconMap/0.1 (+informational attack surface mapping)"},
    )
    requested_host = urllib.parse.urlparse(url).hostname or ""
    redirect_recorder = RedirectRecorder(requested_host)
    opener = urllib.request.build_opener(redirect_recorder)
    try:
        with opener.open(request, timeout=timeout) as response:
            raw = response.read(131072)
            charset = response.headers.get_content_charset() or "utf-8"
            body = raw.decode(charset, errors="replace")
            title_match = TITLE_RE.search(body)
            headers = {key.lower(): value for key, value in response.headers.items()}
            return {
                "host": requested_host,
                "url": url,
                "final_url": response.url,
                "redirect_chain": "; ".join(redirect_recorder.chain),
                "status": response.status,
                "title": unescape(title_match.group(1)).strip() if title_match else "",
                "server": response.headers.get("Server", ""),
                "technologies": "; ".join(detect_technologies(response.headers, body)),
                "content_length": response.headers.get("Content-Length", str(len(raw))),
                "cookies": "; ".join(response.headers.get_all("Set-Cookie", [])),
                "csp_value": response.headers.get("Content-Security-Policy", ""),
                "referenced_hosts": "; ".join(
                    extract_referenced_hosts(body, response.headers.get("Content-Security-Policy", ""))
                ),
                **{name: header in headers for name, header in SECURITY_HEADERS.items()},
                "error": "",
            }
    except urllib.error.HTTPError as exc:
        headers = {key.lower(): value for key, value in exc.headers.items()}
        return {
            "host": requested_host,
            "url": url,
            "final_url": exc.url,
            "redirect_chain": "; ".join(redirect_recorder.chain),
            "status": exc.code,
            "title": "",
            "server": exc.headers.get("Server", ""),
            "technologies": "",
            "content_length": exc.headers.get("Content-Length", ""),
            "cookies": "; ".join(exc.headers.get_all("Set-Cookie", [])),
            "csp_value": exc.headers.get("Content-Security-Policy", ""),
            "referenced_hosts": "",
            **{name: header in headers for name, header in SECURITY_HEADERS.items()},
            "error": "",
        }
    except (urllib.error.URLError, TimeoutError, ValueError) as exc:
        return {
            "host": requested_host,
            "url": url,
            "final_url": "",
            "redirect_chain": "; ".join(redirect_recorder.chain),
            "status": "",
            "title": "",
            "server": "",
            "technologies": "",
            "content_length": "",
            "cookies": "",
            "csp_value": "",
            "referenced_hosts": "",
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


def fingerprint_target(
    target: str,
    timeout: float,
    delay: float,
    progress: Callable[[str], None] | None = None,
    ip_target: bool = False,
) -> list[dict[str, Any]]:
    urls = (
        [f"http://{target}/", f"https://{target}/"]
        if not ip_target
        else [
            f"http://{target}:80/",
            f"https://{target}:443/",
            f"http://{target}:8080/",
            f"https://{target}:8443/",
        ]
    )
    limiter = RateLimiter(delay)
    rows = []
    for url in urls:
        limiter.wait()
        if progress:
            progress(f"Checking HTTP: {url}")
        row = probe_url(url, timeout)
        if not row["error"] or row["status"]:
            rows.append(row)
    return rows
