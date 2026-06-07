from __future__ import annotations

import re
from dataclasses import dataclass
from dataclasses import field
from typing import Any
from urllib.parse import urlparse

from reconmap.util import is_ip, normalize_target, registrable_domain


HOST_IN_RECORD = re.compile(r"([a-z0-9][a-z0-9.-]*\.[a-z]{2,})\.?", re.IGNORECASE)


@dataclass
class PivotPolicy:
    root: str
    depth: int = 1
    max_assets: int = 50
    same_domain_only: bool = True
    include_external: bool = False
    max_references: int = 100
    anchor_domains: set[str] = field(default_factory=set)

    def allows(self, candidate: str, relation: str = "") -> bool:
        if self.include_external or not self.same_domain_only:
            return True
        if is_ip(candidate):
            return relation in {"A", "AAAA"}
        candidate_domain = registrable_domain(candidate)
        if not is_ip(self.root):
            return candidate_domain == registrable_domain(self.root)
        if not self.anchor_domains and relation in {"PTR", "TLS SAN"}:
            self.anchor_domains.add(candidate_domain)
            return True
        return candidate_domain in self.anchor_domains


def _record_hosts(value: str) -> list[str]:
    return [match.lower().rstrip(".") for match in HOST_IN_RECORD.findall(value)]


def evidence_candidates(
    asset: str,
    dns_rows: list[dict[str, Any]],
    http_rows: list[dict[str, Any]],
    tls_rows: list[dict[str, Any]],
) -> list[tuple[str, str]]:
    found: list[tuple[str, str]] = []
    for row in dns_rows:
        value = str(row.get("value", ""))
        record_type = str(row.get("type", ""))
        if record_type in {"A", "AAAA"} and value:
            found.append((record_type, value))
        elif record_type in {"PTR", "CNAME", "MX", "NS"}:
            found.extend((record_type, host) for host in _record_hosts(value))
    for row in tls_rows:
        for san in str(row.get("sans", "")).split("; "):
            if san and not san.startswith("*"):
                found.append(("TLS SAN", san))
    for row in http_rows:
        for redirect in str(row.get("redirect_chain", "")).split("; "):
            host = urlparse(redirect).hostname
            if host:
                found.append(("HTTP Redirect", host))
        for host in str(row.get("referenced_hosts", "")).split("; "):
            if host:
                found.append(("HTTP Reference", host))
    unique = []
    seen = set()
    for relation, candidate in found:
        try:
            candidate = normalize_target(candidate)
        except ValueError:
            continue
        key = (relation, candidate)
        if candidate != asset and key not in seen:
            seen.add(key)
            unique.append(key)
    return unique


def relationship_text(root: str, relationships: list[dict[str, Any]]) -> str:
    lines = [root]
    seen: set[tuple[str, str, str]] = set()

    def walk(source: str, prefix: str) -> None:
        rows = [row for row in relationships if row["source"] == source]
        for index, row in enumerate(rows):
            key = (row["source"], row["relation"], row["target"])
            if key in seen:
                continue
            seen.add(key)
            last = index == len(rows) - 1
            branch = "`--" if last else "|--"
            lines.append(f"{prefix}{branch} {row['relation']}: {row['target']} [{row['status']}]")
            if row["status"] in {"queued", "already-known"}:
                walk(row["target"], prefix + ("    " if last else "|   "))

    walk(root, "")
    return "\n".join(lines) + "\n"
