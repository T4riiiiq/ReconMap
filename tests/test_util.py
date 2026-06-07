import unittest
from pathlib import Path

from reconmap.util import normalize_host, normalize_target, read_hosts, registrable_domain


class UtilTests(unittest.TestCase):
    def test_normalize_host(self):
        self.assertEqual(normalize_host("HTTPS://WWW.Example.COM/path"), "www.example.com")

    def test_rejects_ip(self):
        with self.assertRaises(ValueError):
            normalize_host("192.0.2.10")

    def test_normalize_target_accepts_ip(self):
        self.assertEqual(normalize_target("192.0.2.10"), "192.0.2.10")

    def test_registrable_domain_handles_common_multilabel_suffix(self):
        self.assertEqual(registrable_domain("api.example.co.uk"), "example.co.uk")
        self.assertEqual(registrable_domain("tenant.github.io"), "tenant.github.io")

    def test_read_hosts_deduplicates_and_ignores_comments(self):
        path = Path(__file__).parent / "data" / "hosts.txt"
        self.assertEqual(read_hosts(path), ["www.example.com", "api.example.com"])


if __name__ == "__main__":
    unittest.main()
