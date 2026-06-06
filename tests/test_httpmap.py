import unittest
from email.message import Message

from reconmap.httpmap import detect_technologies


class HttpMapTests(unittest.TestCase):
    def test_detects_header_and_meta_technologies(self):
        headers = Message()
        headers["Server"] = "ExampleServer"
        headers["X-Powered-By"] = "ExampleRuntime"
        body = '<meta name="generator" content="ExampleCMS"><link href="/wp-content/a.css">'
        self.assertEqual(
            detect_technologies(headers, body),
            ["ExampleCMS", "ExampleRuntime", "ExampleServer", "WordPress"],
        )


if __name__ == "__main__":
    unittest.main()
