import io
import json
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path
from unittest.mock import patch

from reconmap.cli import main


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


def run_cli(arguments):
    stdout = io.StringIO()
    stderr = io.StringIO()
    with redirect_stdout(stdout), redirect_stderr(stderr):
        code = main(arguments)
    return code, stdout.getvalue(), stderr.getvalue()


class CliOutputTests(unittest.TestCase):
    @patch("reconmap.cli.scan", return_value=SUMMARY)
    def test_default_output_is_human_readable_not_raw_json(self, _scan):
        code, stdout, _ = run_cli(["scan", "example.com", "--no-files"])
        self.assertEqual(code, 0)
        self.assertIn("ReconMap scan report for example.com", stdout)
        with self.assertRaises(json.JSONDecodeError):
            json.loads(stdout)

    @patch("reconmap.cli.scan", return_value=SUMMARY)
    def test_json_output_is_valid_json(self, _scan):
        code, stdout, _ = run_cli(["scan", "example.com", "--json"])
        self.assertEqual(code, 0)
        self.assertEqual(json.loads(stdout)["root_domain"], "example.com")

    @patch("reconmap.cli.scan", return_value=SUMMARY)
    def test_quiet_suppresses_normal_output(self, _scan):
        code, stdout, stderr = run_cli(["scan", "example.com", "--quiet"])
        self.assertEqual((code, stdout, stderr), (0, "", ""))

    @patch("reconmap.cli.scan")
    def test_verbose_includes_progress_markers(self, scan):
        def fake_scan(domain, output, subdomains, passive, timeout, delay, progress):
            progress(f"Resolving DNS records for {domain}")
            progress("Wrote output/http.csv", success=True)
            return SUMMARY

        scan.side_effect = fake_scan
        code, stdout, _ = run_cli(["scan", "example.com", "--verbose"])
        self.assertEqual(code, 0)
        self.assertIn("[*] Resolving DNS records for example.com", stdout)
        self.assertIn("[+] Wrote output/http.csv", stdout)
        self.assertIn("ReconMap scan report for example.com", stdout)

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


if __name__ == "__main__":
    unittest.main()
