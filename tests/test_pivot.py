import unittest
from unittest.mock import patch

from reconmap.httpmap import extract_referenced_hosts, fingerprint_target
from reconmap.pivot import PivotPolicy, evidence_candidates
from reconmap.scanner import scan
from reconmap.util import is_ip, normalize_target


class PivotTests(unittest.TestCase):
    def test_ip_input_detection(self):
        self.assertTrue(is_ip(normalize_target("192.0.2.10")))

    def test_ptr_pivot(self):
        rows = [{"name": "192.0.2.10", "type": "PTR", "value": "www.example.com", "error": ""}]
        self.assertIn(("PTR", "www.example.com"), evidence_candidates("192.0.2.10", rows, [], []))

    def test_tls_san_pivot(self):
        tls = [{"host": "example.com", "sans": "example.com; www.example.com"}]
        self.assertIn(("TLS SAN", "www.example.com"), evidence_candidates("example.com", [], [], tls))

    def test_cname_chain_pivot(self):
        dns = [{"name": "app.example.com", "type": "CNAME", "value": "edge.example.com", "error": ""}]
        self.assertIn(("CNAME", "edge.example.com"), evidence_candidates("app.example.com", dns, [], []))

    def test_redirect_pivot(self):
        http = [{"redirect_chain": "https://login.example.com/", "referenced_hosts": ""}]
        self.assertIn(("HTTP Redirect", "login.example.com"), evidence_candidates("example.com", [], http, []))

    def test_html_and_js_reference_extraction(self):
        body = '<script src="https://cdn.example.com/app.js"></script><a href="//api.example.com/v1">'
        csp = "default-src https://*.static.example.com"
        self.assertEqual(extract_referenced_hosts(body, csp), [
            "api.example.com", "cdn.example.com", "static.example.com",
        ])

    def test_same_domain_only_behavior(self):
        policy = PivotPolicy("example.com")
        self.assertTrue(policy.allows("api.example.com", "HTTP Reference"))
        self.assertFalse(policy.allows("external.test", "HTTP Redirect"))
        self.assertFalse(policy.allows("198.51.100.10", "HTTP Redirect"))
        self.assertTrue(policy.allows("198.51.100.10", "A"))

    def test_include_external_behavior(self):
        policy = PivotPolicy("example.com", include_external=True)
        self.assertTrue(policy.allows("external.test", "HTTP Redirect"))

    @patch("reconmap.httpmap.probe_url")
    def test_ip_collection_uses_only_fixed_safe_ports(self, probe):
        probe.return_value = {"error": "closed", "status": ""}
        fingerprint_target("192.0.2.10", 1, 0, ip_target=True)
        urls = [call.args[0] for call in probe.call_args_list]
        self.assertEqual(urls, [
            "http://192.0.2.10:80/",
            "https://192.0.2.10:443/",
            "http://192.0.2.10:8080/",
            "https://192.0.2.10:8443/",
        ])

    @patch("reconmap.scanner.inspect_hosts", return_value=[])
    @patch("reconmap.scanner.fingerprint_target", return_value=[])
    @patch("reconmap.scanner.collect_dns")
    @patch("reconmap.scanner.discover")
    def test_pivot_depth_and_max_assets_limits(self, discover, collect_dns, _http, _tls):
        discover.return_value = (["example.com"], [], {"example.com": "root"})

        def dns(host, _timeout):
            targets = {
                "example.com": ["a.example.com", "b.example.com"],
                "a.example.com": ["deep.example.com"],
            }
            return [
                {"name": host, "type": "CNAME", "value": target, "error": ""}
                for target in targets.get(host, [])
            ]

        collect_dns.side_effect = dns
        result = scan(
            "example.com", None, None, False, 1, 0,
            pivot=True, pivot_depth=1, max_assets=2,
        )
        statuses = {row["target"]: row["status"] for row in result.relationships}
        self.assertEqual(statuses["b.example.com"], "asset-limit")
        self.assertEqual(statuses["deep.example.com"], "depth-limit")
        self.assertNotIn("deep.example.com", result.hosts)

    def test_no_brute_force_or_port_scan_api_exists(self):
        import reconmap.scanner as scanner

        self.assertFalse(hasattr(scanner, "brute_force"))
        self.assertFalse(hasattr(scanner, "port_scan"))


if __name__ == "__main__":
    unittest.main()
