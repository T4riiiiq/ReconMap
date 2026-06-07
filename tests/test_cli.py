import io
import json
import tempfile
import unittest
from copy import deepcopy
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path
from unittest.mock import patch

from reconmap.cli import main
from reconmap.reporting import ScanResult, render_console_summary


SUMMARY = {
    "root_domain": "example.com",
    "resolved_ips": ["192.0.2.10"],
    "nameserver_count": 2,
    "mx_record_count": 1,
    "email_security_hints": {"spf": True, "dmarc": True, "dkim_hint": False},
    "asset_count": 1,
    "http_checks_count": 2,
    "http_service_count": 1,
    "tls_certificate_count": 1,
    "earliest_tls_expiry": "2030-01-01T00:00:00+00:00",
    "missing_security_headers": {
        "hsts": 1,
        "csp": 1,
        "x_frame_options": 0,
        "x_content_type_options": 0,
        "referrer_policy": 1,
    },
    "investigation_notes": [],
    "disclaimer": "Informational mapping only; results are not vulnerability validation.",
}
HOSTS = ["example.com", "www.example.com", "api.example.com"]
DNS_ROWS = [
    {"name": host, "type": "A", "value": f"192.0.2.{index}", "error": ""}
    for index, host in enumerate(HOSTS, 10)
]
HTTP_ROWS = [
    {
        "host": host, "url": f"https://{host}/", "final_url": f"https://{host}/",
        "status": 200, "title": f"Example {index}", "server": "ExampleServer", "technologies": "",
        "hsts": False, "csp": False, "x_frame_options": True, "x_content_type_options": True,
        "referrer_policy": False, "error": "",
    }
    for index, host in enumerate(HOSTS, 1)
]
TLS_ROWS = [
    {
        "host": host, "subject": f"commonName={host}", "issuer": "organizationName=Example Trust",
        "sans": host, "expiry_date": "2030-01-01T00:00:00+00:00", "days_until_expiry": 100,
        "error": "",
    }
    for host in HOSTS
]
RESULT = ScanResult(SUMMARY, HOSTS, DNS_ROWS, HTTP_ROWS, TLS_ROWS, {
    "example.com": "root", "www.example.com": "manual", "api.example.com": "passive",
})


def run_cli(arguments):
    stdout = io.StringIO()
    stderr = io.StringIO()
    with redirect_stdout(stdout), redirect_stderr(stderr):
        code = main(arguments)
    return code, stdout.getvalue(), stderr.getvalue()


class CliOutputTests(unittest.TestCase):
    @patch("reconmap.cli.scan", return_value=RESULT)
    def test_default_scan_passes_no_output_directory(self, scan):
        run_cli(["scan", "example.com"])
        self.assertIsNone(scan.call_args.args[1])

    @patch("reconmap.cli.scan", return_value=RESULT)
    def test_save_uses_timestamped_directory(self, scan):
        run_cli(["scan", "example.com", "--save"])
        self.assertRegex(scan.call_args.args[1], r"^reconmap-example\.com-\d{8}-\d{6}$")

    @patch("reconmap.cli.scan", return_value=RESULT)
    def test_no_save_overrides_output_directory(self, scan):
        run_cli(["scan", "example.com", "-o", "ignored", "--no-save"])
        self.assertIsNone(scan.call_args.args[1])

    @patch("reconmap.cli.scan", return_value=RESULT)
    def test_default_output_is_human_readable_not_raw_json(self, _scan):
        code, stdout, _ = run_cli(["scan", "example.com", "--no-files"])
        self.assertEqual(code, 0)
        self.assertIn("ReconMap scan report for example.com", stdout)
        self.assertIn("Discovered Hostnames", stdout)
        self.assertIn("HTTP Services", stdout)
        self.assertIn("TLS Certificates", stdout)
        self.assertIn("www.example.com", stdout)
        with self.assertRaises(json.JSONDecodeError):
            json.loads(stdout)

    @patch("reconmap.cli.scan", return_value=RESULT)
    def test_json_output_is_valid_json(self, _scan):
        code, stdout, _ = run_cli(["scan", "example.com", "--json"])
        self.assertEqual(code, 0)
        self.assertEqual(json.loads(stdout)["root_domain"], "example.com")
        self.assertNotIn("Discovered Assets", stdout)

    @patch("reconmap.cli.scan", return_value=RESULT)
    def test_quiet_suppresses_normal_output(self, _scan):
        code, stdout, stderr = run_cli(["scan", "example.com", "--quiet"])
        self.assertEqual((code, stdout, stderr), (0, "", ""))

    @patch("reconmap.cli.scan")
    def test_verbose_includes_progress_markers(self, scan):
        def fake_scan(domain, output, subdomains, passive, timeout, delay, progress, *pivot_options):
            progress(f"Resolving DNS records for {domain}")
            progress("Wrote output/http.csv", success=True)
            return RESULT

        scan.side_effect = fake_scan
        code, stdout, _ = run_cli(["scan", "example.com", "--verbose"])
        self.assertEqual(code, 0)
        self.assertIn("[*] Resolving DNS records for example.com", stdout)
        self.assertIn("[+] Wrote output/http.csv", stdout)
        self.assertIn("ReconMap scan report for example.com", stdout)

    @patch("reconmap.cli.scan", return_value=RESULT)
    def test_max_rows_limits_each_table(self, _scan):
        code, stdout, _ = run_cli(["scan", "example.com", "--max-rows", "1"])
        self.assertEqual(code, 0)
        self.assertIn("... 2 more rows omitted. Use --max-rows 0 to show all.", stdout)
        self.assertNotIn("www.example.com", stdout)

    @patch("reconmap.cli.scan", return_value=RESULT)
    def test_max_rows_zero_shows_all_rows(self, _scan):
        code, stdout, _ = run_cli(["scan", "example.com", "--max-rows", "0"])
        self.assertEqual(code, 0)
        self.assertIn("www.example.com", stdout)
        self.assertIn("api.example.com", stdout)
        self.assertNotIn("more rows omitted", stdout)

    @patch("reconmap.scanner.collect_dns", return_value=[])
    def test_output_option_writes_files(self, _collect_dns):
        with tempfile.TemporaryDirectory() as directory:
            code, stdout, _ = run_cli(["dns", "example.com", "-o", directory])
            self.assertEqual(code, 0)
            self.assertIn("Output written to:", stdout)
            self.assertTrue((Path(directory) / "summary.json").exists())
            self.assertTrue((Path(directory) / "report.md").exists())

    @patch("reconmap.scanner.collect_dns", return_value=[])
    def test_no_files_writes_no_files(self, _collect_dns):
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / "ignored"
            code, stdout, _ = run_cli(["dns", "example.com", "-o", str(output), "--no-files"])
            self.assertEqual(code, 0)
            self.assertIn("ReconMap scan report for example.com", stdout)
        self.assertFalse(output.exists())

    def test_ip_is_not_listed_as_hostname_and_resolved_ips_map_to_hosts(self):
        summary = deepcopy(SUMMARY)
        summary["root_domain"] = "192.0.2.10"
        result = ScanResult(
            summary,
            ["192.0.2.10", "example.com", "www.example.com"],
            [
                {"name": "192.0.2.10", "type": "PTR", "value": "example.com", "error": ""},
                {"name": "www.example.com", "type": "A", "value": "192.0.2.10", "error": ""},
            ],
            [],
            [],
            {"192.0.2.10": "root", "example.com": "PTR", "www.example.com": "TLS SAN"},
        )

        output = render_console_summary(result)
        hostname_section = output.split("Discovered Hostnames\n", 1)[1].split("\n\nResolved IPs", 1)[0]
        resolved_section = output.split("Resolved IPs\n", 1)[1].split("\n\nHTTP Services", 1)[0]
        self.assertIn("IP Target\n* 192.0.2.10", output)
        self.assertNotIn("192.0.2.10", hostname_section)
        self.assertIn("192.0.2.10", resolved_section)
        self.assertIn("example.com, www.example.com", resolved_section)

    def test_pivot_statuses_are_human_readable(self):
        result = ScanResult(
            SUMMARY,
            HOSTS,
            DNS_ROWS,
            [],
            [],
            {},
            [{
                "source": "example.com",
                "relation": "PTR",
                "target": "server.example.com",
                "depth": 1,
                "status": "depth-limit",
            }],
        )
        self.assertIn("not-scanned-depth-limit", render_console_summary(result))

    @patch("reconmap.cli.scan")
    def test_external_references_are_summarized_by_default_and_expand_on_request(self, scan):
        summary = deepcopy(SUMMARY)
        summary["external_references"] = [
            {"source": "example.com", "target": "fonts.example.net"},
            {"source": "example.com", "target": "schema.example.net"},
        ]
        scan.return_value = ScanResult(summary, HOSTS, DNS_ROWS, [], [], {})

        _, default_output, _ = run_cli(["scan", "example.com"])
        _, expanded_output, _ = run_cli(["scan", "example.com", "--show-external-references"])
        self.assertIn("2 observed. Use --show-external-references to display.", default_output)
        self.assertNotIn("fonts.example.net", default_output)
        self.assertIn("fonts.example.net", expanded_output)
        self.assertIn("schema.example.net", expanded_output)

    @patch("reconmap.cli.scan")
    def test_no_truncate_prints_full_values(self, scan):
        long_value = "v=spf1 include:" + ("very-long-provider-name." * 4) + "example.net -all"
        scan.return_value = ScanResult(
            SUMMARY,
            HOSTS,
            [{"name": "example.com", "type": "TXT", "value": long_value, "error": ""}],
            [],
            [],
            {},
        )

        _, default_output, _ = run_cli(["scan", "example.com"])
        _, full_output, _ = run_cli(["scan", "example.com", "--no-truncate"])
        self.assertNotIn(long_value, default_output)
        self.assertIn(long_value, full_output)


if __name__ == "__main__":
    unittest.main()
