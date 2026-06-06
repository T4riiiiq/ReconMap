from __future__ import annotations

import argparse
import json
import sys

from reconmap import __version__
from reconmap.reporting import render_console_summary
from reconmap.scanner import dns_only, http_only, scan
from reconmap.util import normalize_host


def common_options(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("-o", "--output", help="Write output files to this directory")
    parser.add_argument("--no-files", action="store_true", help="Do not write output files")
    modes = parser.add_mutually_exclusive_group()
    modes.add_argument("-v", "--verbose", action="store_true", help="Print live progress and final summary")
    modes.add_argument("-q", "--quiet", action="store_true", help="Print errors only")
    modes.add_argument("--json", action="store_true", help="Print summary JSON to stdout")
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
    common_options(dns_parser)
    return parser


def _progress(message: str, success: bool = False) -> None:
    print(f"[{'+' if success else '*'}] {message}")


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        if getattr(args, "timeout", 0) <= 0 or getattr(args, "delay", 0) < 0:
            raise ValueError("timeout must be positive and delay cannot be negative")
        output = None if args.no_files else args.output
        progress = _progress if args.verbose else None
        if args.command == "scan":
            summary = scan(
                normalize_host(args.domain),
                output,
                args.subdomains,
                args.passive,
                args.timeout,
                args.delay,
                progress,
            )
        elif args.command == "http":
            summary = http_only(args.hosts, output, args.timeout, args.delay, progress)
        else:
            summary = dns_only(normalize_host(args.domain), output, args.timeout, progress)
        if not args.quiet:
            print(json.dumps(summary, indent=2) if args.json else render_console_summary(summary, output))
        return 0
    except (OSError, ValueError) as exc:
        print(f"reconmap: error: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
