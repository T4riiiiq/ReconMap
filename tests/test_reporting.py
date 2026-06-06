import json
import tempfile
import unittest
from pathlib import Path

from reconmap.reporting import write_outputs


class ReportingTests(unittest.TestCase):
    def test_writes_all_expected_outputs(self):
        dns_rows = [{"name": "example.com", "type": "A", "value": "192.0.2.10", "error": ""}]
        http_rows = [{
            "host": "example.com", "url": "https://example.com/", "final_url": "https://example.com/",
            "status": 200, "title": "Example", "server": "", "technologies": "", "hsts": True,
            "csp": False, "x_frame_options": True, "x_content_type_options": True,
            "referrer_policy": False, "error": "",
        }]
        tls_rows = [{
            "host": "example.com", "subject": "commonName=example.com", "issuer": "commonName=Example CA",
            "sans": "example.com", "expiry_date": "2030-01-01T00:00:00+00:00",
            "days_until_expiry": 100, "error": "",
        }]
        with tempfile.TemporaryDirectory() as directory:
            write_outputs(directory, "example.com", ["example.com"], dns_rows, http_rows, tls_rows, [])
            expected = {"hosts.csv", "dns.csv", "http.csv", "tls.csv", "summary.json", "report.md"}
            self.assertEqual({path.name for path in Path(directory).iterdir()}, expected)
            summary = json.loads((Path(directory) / "summary.json").read_text(encoding="utf-8"))
            self.assertEqual(summary["asset_count"], 1)
            report = (Path(directory) / "report.md").read_text(encoding="utf-8")
            self.assertIn("Informational mapping only", report)
            self.assertIn("## DNS Summary", report)
            self.assertIn("## Discovered Assets", report)
            self.assertIn("## HTTP Services", report)
            self.assertIn("## TLS Certificates", report)
            self.assertIn("## Security Header Overview", report)

    def test_empty_domainkey_query_is_not_a_dkim_hint(self):
        from reconmap.dnsmap import email_security_hints

        rows = [{"name": "_domainkey.example.com", "type": "TXT", "value": "", "error": "timeout"}]
        self.assertFalse(email_security_hints(rows)["dkim_hint"])


if __name__ == "__main__":
    unittest.main()
