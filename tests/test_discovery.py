import unittest
import io
from unittest.mock import patch

from reconmap.discovery import crtsh_subdomains, discover


class DiscoveryTests(unittest.TestCase):
    @patch("reconmap.discovery.urllib.request.urlopen")
    def test_crtsh_extracts_in_scope_certificate_names(self, urlopen):
        urlopen.return_value.__enter__.return_value = io.BytesIO(
            b'[{"name_value":"*.api.example.com\\nwww.example.com\\nunrelated.test"}]'
        )
        hosts, error = crtsh_subdomains("example.com", 1)
        self.assertEqual(error, "")
        self.assertEqual(hosts, ["api.example.com", "www.example.com"])

    def test_manual_discovery_is_in_scope_only(self):
        hosts, notes, sources = discover(
            "example.com",
            ["www.example.com", "unrelated.test"],
            passive=False,
            timeout=1,
        )
        self.assertEqual(hosts, ["example.com", "www.example.com"])
        self.assertIn("Ignored out-of-scope manual host: unrelated.test", notes)
        self.assertEqual(sources["www.example.com"], "manual")

    @patch("reconmap.discovery.crtsh_subdomains", return_value=([], ""))
    @patch("reconmap.discovery.securitytrails_subdomains")
    def test_passive_discovery_is_opt_in(self, provider, _crtsh):
        provider.return_value = (["api.example.com"], "")
        hosts, _, sources = discover("example.com", [], passive=True, timeout=1)
        self.assertIn("api.example.com", hosts)
        self.assertEqual(sources["api.example.com"], "SecurityTrails")
        provider.assert_called_once()


if __name__ == "__main__":
    unittest.main()
