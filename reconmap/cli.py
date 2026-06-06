from __future__ import annotations

import argparse
import json
import sys

from reconmap import __version__
from reconmap.scanner import dns_only, http_only, scan
from reconmap.util import normalize_host


def common_options(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("-o", "--output", required=True, help="Output directory")
    parser.add_argument("--timeout", type=float, default=5.0, help="Per-request timeout in seconds (default: 5)")
    parser.add_argument("--delay", type=float, default=0.25, help="Delay between active requests in seconds (default: 0.25)")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="reconmap",
        description="Safe, lightweight public attack surface mapping.",
        epilog="Use only on assets you are authorized to assess.",
    )
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    commands = parser.add_subparsers(dest="command", required=True)

    scan_parser = commands.add_parser("scan", help="Run DNS, HTTP, and TLS mapping")
    scan_parser.add_argument("domain", help="Root domain to map")
    scan_parser.add_argument("--subdomains", help="File containing known in-scope subdomains")
    scan_parser.add_argument("--passive", action="store_true", help="Use configured passive API providers")
    common_options(scan_parser)

    http_parser = commands.add_parser("http", help="Fingerprint HTTP/S for a host list")
    http_parser.add_argument("hosts", help="File containing hostnames")
    common_options(http_parser)

    dns_parser = commands.add_parser("dns", help="Collect public DNS records")
    dns_parser.add_argument("domain", help="Domain to map")
    dns_parser.add_argument("-o", "--output", required=True, help="Output directory")
    dns_parser.add_argument("--timeout", type=float, default=5.0, help="DNS timeout in seconds (default: 5)")
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        if getattr(args, "timeout", 0) <= 0 or getattr(args, "delay", 0) < 0:
            raise ValueError("timeout must be positive and delay cannot be negative")
        if args.command == "scan":
            summary = scan(
                normalize_host(args.domain),
                args.output,
                args.subdomains,
                args.passive,
                args.timeout,
                args.delay,
            )
        elif args.command == "http":
            summary = http_only(args.hosts, args.output, args.timeout, args.delay)
        else:
            summary = dns_only(normalize_host(args.domain), args.output, args.timeout)
        print(json.dumps(summary, indent=2))
        return 0
    except (OSError, ValueError) as exc:
        print(f"reconmap: error: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
