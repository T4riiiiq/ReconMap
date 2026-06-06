import unittest
from unittest.mock import patch

from reconmap.discovery import discover


class DiscoveryTests(unittest.TestCase):
    def test_manual_discovery_is_in_scope_only(self):
        hosts, notes = discover(
            "example.com",
            ["www.example.com", "unrelated.test"],
            passive=False,
            timeout=1,
        )
        self.assertEqual(hosts, ["example.com", "www.example.com"])
        self.assertIn("Ignored out-of-scope manual host: unrelated.test", notes)

    @patch("reconmap.discovery.securitytrails_subdomains")
    def test_passive_discovery_is_opt_in(self, provider):
        provider.return_value = (["api.example.com"], "")
        hosts, _ = discover("example.com", [], passive=True, timeout=1)
        self.assertIn("api.example.com", hosts)
        provider.assert_called_once()


if __name__ == "__main__":
    unittest.main()
