import unittest

from reconmap.intelligence import analyze, classify_asset


class IntelligenceTests(unittest.TestCase):
    def test_detects_cloud_identity_email_and_references(self):
        dns_rows = [
            {"name": "example.com", "type": "MX", "value": "mail.protection.outlook.com", "error": ""},
            {"name": "example.com", "type": "TXT", "value": "include:_spf.google.com", "error": ""},
        ]
        http_rows = [{
            "host": "login.example.com",
            "url": "https://login.example.com/",
            "final_url": "https://tenant.okta.com/",
            "redirect_chain": "https://tenant.okta.com/",
            "server": "CloudFront",
            "technologies": "",
            "cookies": "",
        }]
        result = analyze(["login.example.com"], dns_rows, http_rows, [])
        self.assertIn("AWS", result["cloud_providers"])
        self.assertIn("CloudFront", result["interesting_cloud_references"])
        self.assertIn("Okta", result["identity_providers"])
        self.assertIn("Microsoft 365", result["email_providers"])
        self.assertEqual(result["asset_inventory"][0]["category"], "Auth")

    def test_classifies_high_value_hostnames(self):
        self.assertEqual(classify_asset("api.example.com", []), "API")
        self.assertEqual(classify_asset("vpn.example.com", []), "VPN")
        self.assertEqual(classify_asset("admin.example.com", []), "Admin")


if __name__ == "__main__":
    unittest.main()
