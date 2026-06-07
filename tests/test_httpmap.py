import unittest
from email.message import Message

from reconmap.httpmap import RedirectRecorder, detect_technologies


class HttpMapTests(unittest.TestCase):
    def test_external_redirect_is_recorded_but_not_followed(self):
        recorder = RedirectRecorder("example.com")
        request = recorder.redirect_request(
            None, None, 302, "Found", {}, "https://login.example-idp.test/"
        )
        self.assertIsNone(request)
        self.assertEqual(recorder.chain, ["https://login.example-idp.test/"])

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
