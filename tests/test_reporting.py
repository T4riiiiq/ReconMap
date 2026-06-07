import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from reconmap.reporting import write_outputs
from reconmap.dnsmap import collect_dns
from reconmap.dnsmap import collect_asn


class ReportingTests(unittest.TestCase):
    @patch("reconmap.dnsmap.query_record", return_value=([], ""))
    def test_dns_collection_requests_intelligence_record_types(self, query):
        collect_dns("example.com", 1)
        requested = {call.args[1] for call in query.call_args_list}
        self.assertTrue({"SOA", "CAA", "SRV"}.issubset(requested))

    @patch("reconmap.dnsmap.query_record")
    def test_ip_asn_collection_uses_public_dns_evidence(self, query):
        query.side_effect = [
            (["13335 | 1.1.1.0/24 | AU | apnic | 2011-08-11"], ""),
            (["13335 | AU | apnic | 2010-07-14 | CLOUDFLARENET, US"], ""),
        ]
        result = collect_asn("1.1.1.1", 1)
        self.assertEqual(result["asn"], "13335")
        self.assertEqual(result["provider"], "CLOUDFLARENET, US")
        self.assertEqual(query.call_args_list[0].args[0], "1.1.1.1.origin.asn.cymru.com")

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
            expected = {
                "dns.csv", "http.csv", "tls.csv", "pivots.csv",
                "relationships.txt", "summary.json", "report.md",
            }
            self.assertEqual({path.name for path in Path(directory).iterdir()}, expected)
            summary = json.loads((Path(directory) / "summary.json").read_text(encoding="utf-8"))
            self.assertEqual(summary["asset_count"], 1)
            report = (Path(directory) / "report.md").read_text(encoding="utf-8")
            self.assertIn("Informational mapping only", report)
            self.assertIn("## DNS Summary", report)
            self.assertIn("## Discovered Assets", report)
            self.assertIn("## DNS Records", report)
            self.assertIn("## HTTP Services", report)
            self.assertIn("## TLS Certificates", report)
            self.assertIn("## Security Header Overview", report)
            self.assertIn("## Attack Surface Inventory", report)
            self.assertIn("## Interesting Redirects", report)
            self.assertIn("## Interesting Cloud References", report)
            self.assertIn("## Interesting Email Infrastructure", report)
            self.assertIn("## Discovery Chains", report)
            self.assertIn("## Relationship Map", report)
            self.assertIn("## Provider Evidence", report)
            self.assertIn("## IP Intelligence", report)
            self.assertIn("## External References", report)

    def test_empty_domainkey_query_is_not_a_dkim_hint(self):
        from reconmap.dnsmap import email_security_hints

        rows = [{"name": "_domainkey.example.com", "type": "TXT", "value": "", "error": "timeout"}]
        self.assertFalse(email_security_hints(rows)["dkim_hint"])


if __name__ == "__main__":
    unittest.main()
