from __future__ import annotations

from typing import Any


CLOUD_PATTERNS = {
    "Cloudflare": ("cloudflare",),
    "AWS": ("amazonaws.com", "aws.amazon.com", "cloudfront", "execute-api.", "s3."),
    "Azure": ("azurewebsites.net", "blob.core.windows.net", "azureedge.net", "microsoftonline.com"),
    "GCP": ("googleapis.com", "storage.googleapis.com", "appspot.com"),
    "Fastly": ("fastly", "fastly.net"),
    "Akamai": ("akamai", "akamaiedge.net", "edgekey.net"),
}
CLOUD_REFERENCE_PATTERNS = {
    "CloudFront": ("cloudfront",),
    "API Gateway": ("execute-api.",),
    "S3": ("s3.amazonaws.com", ".s3.",),
    "Elastic Beanstalk": ("elasticbeanstalk.com",),
    "Azure Blob": ("blob.core.windows.net",),
    "Azure Web Apps": ("azurewebsites.net",),
    "Azure API Management": ("azure-api.net",),
    "Google Storage": ("storage.googleapis.com",),
    "Google App Engine": ("appspot.com",),
    "Google Cloud Functions": ("cloudfunctions.net",),
}
CLOUD_SERVICE_PROVIDERS = {
    "CloudFront": "AWS",
    "API Gateway": "AWS",
    "S3": "AWS",
    "Elastic Beanstalk": "AWS",
    "Azure Blob": "Azure",
    "Azure Web Apps": "Azure",
    "Azure API Management": "Azure",
    "Google Storage": "GCP",
    "Google App Engine": "GCP",
    "Google Cloud Functions": "GCP",
}
IDENTITY_PATTERNS = {
    "Okta": ("okta.com", "oktapreview.com"),
    "Auth0": ("auth0.com",),
    "Microsoft Entra": ("login.microsoftonline.com", "microsoftonline.com"),
    "Keycloak": ("keycloak",),
    "OneLogin": ("onelogin.com",),
}
EMAIL_PATTERNS = {
    "Microsoft 365": ("outlook.com", "protection.outlook.com", "spf.protection.outlook.com"),
    "Google Workspace": ("google.com", "googlemail.com", "_spf.google.com"),
    "Mimecast": ("mimecast",),
    "Proofpoint": ("proofpoint", "pphosted.com"),
    "Cisco ESA": ("cisco", "ironport"),
}


def _matches(text: str, patterns: dict[str, tuple[str, ...]]) -> list[str]:
    lower = text.lower()
    return sorted(name for name, values in patterns.items() if any(value in lower for value in values))


def _evidence(
    observations: list[str],
    patterns: dict[str, tuple[str, ...]],
    area: str,
    service: str = "",
) -> list[dict[str, str]]:
    rows = []
    seen = set()
    for observation in observations:
        lower = observation.lower()
        for provider, values in patterns.items():
            if any(value in lower for value in values):
                key = (provider, observation)
                if key not in seen:
                    seen.add(key)
                    rows.append({
                        "area": area,
                        "provider": provider,
                        "service": service or provider,
                        "evidence": observation,
                    })
    return rows


def _cloud_service_evidence(observations: list[str]) -> list[dict[str, str]]:
    rows = _evidence(observations, CLOUD_REFERENCE_PATTERNS, "Cloud")
    for row in rows:
        row["service"] = row["provider"]
        row["provider"] = CLOUD_SERVICE_PROVIDERS[row["service"]]
    return rows


def classify_asset(host: str, http_rows: list[dict[str, Any]]) -> str:
    lower = host.lower()
    labels = (
        ("API", ("api.", "graphql.", "rest.")),
        ("VPN", ("vpn.", "remote.", "gateway.")),
        ("Mail", ("mail.", "smtp.", "webmail.", "autodiscover.")),
        ("Auth", ("auth.", "login.", "sso.", "idp.")),
        ("Admin", ("admin.", "portal.", "manage.", "console.")),
    )
    for category, patterns in labels:
        if any(pattern in lower for pattern in patterns):
            return category
    if any(row["host"] == host for row in http_rows):
        return "Web"
    return "Other"


def analyze(
    hosts: list[str],
    dns_rows: list[dict[str, Any]],
    http_rows: list[dict[str, Any]],
    tls_rows: list[dict[str, Any]],
) -> dict[str, Any]:
    dns_observations = [str(row.get("value", "")) for row in dns_rows if row.get("value")]
    http_observations = [
        " ".join(str(row.get(key, "")) for key in ("url", "final_url", "redirect_chain", "server", "technologies", "cookies"))
        for row in http_rows
    ]
    dns_text = " ".join(dns_observations)
    http_text = " ".join(http_observations)
    all_text = f"{dns_text} {http_text}"
    cloud = _matches(all_text, CLOUD_PATTERNS)
    cloud_references = _matches(all_text, CLOUD_REFERENCE_PATTERNS)
    identity = _matches(all_text, IDENTITY_PATTERNS)
    email = _matches(dns_text, EMAIL_PATTERNS)
    inventory = [{"host": host, "category": classify_asset(host, http_rows)} for host in hosts]
    redirects = [
        {"url": row["url"], "chain": row.get("redirect_chain", "")}
        for row in http_rows if row.get("redirect_chain")
    ]
    certificates = [
        {"host": row["host"], "issuer": row["issuer"], "expires": row["expiry_date"], "sans": row["sans"]}
        for row in tls_rows
        if int(row.get("days_until_expiry") or 9999) < 90 or len(str(row.get("sans", "")).split("; ")) > 5
    ]
    interesting_hosts = [
        item for item in inventory if item["category"] in {"API", "VPN", "Mail", "Auth", "Admin"}
    ]
    return {
        "cloud_providers": cloud,
        "identity_providers": identity,
        "email_providers": email,
        "asset_inventory": inventory,
        "interesting_hosts": interesting_hosts,
        "interesting_redirects": redirects,
        "interesting_certificates": certificates,
        "interesting_cloud_references": cloud_references,
        "interesting_email_infrastructure": email,
        "cloud_evidence": (
            _evidence(dns_observations + http_observations, CLOUD_PATTERNS, "Cloud", "Provider")
            + _cloud_service_evidence(dns_observations + http_observations)
        ),
        "identity_evidence": _evidence(http_observations, IDENTITY_PATTERNS, "Identity"),
        "email_evidence": _evidence(dns_observations, EMAIL_PATTERNS, "Email"),
    }
