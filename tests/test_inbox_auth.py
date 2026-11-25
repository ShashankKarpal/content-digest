"""The inbox is written only after the token check (fleet security audit
HFCD1, H4, 2026-11-25).

Before this, do_POST recorded every ingest link in inbox.json before auth,
so any page open on a tailnet device could add entries (500 of them pushed
every real entry out of the capped file). Now a POST without the token is
refused with 401 and inbox.json is untouched; an authenticated POST is still
recorded before the fetch, so the inbox sweep can retry it.
Run: python3 -m unittest tests.test_inbox_auth
"""

import json
import sys
import tempfile
import threading
import unittest
import urllib.error
import urllib.request
from http.server import ThreadingHTTPServer
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

try:
    import server  # noqa: E402
except Exception as e:  # pragma: no cover
    server = None
    IMPORT_ERROR = e

TOKEN = "test-token-" + "y" * 32


@unittest.skipIf(server is None, "server.py could not be imported here")
class InboxAuthTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        d = Path(self.tmp.name)
        self._saved = {}
        for name in dir(server):
            value = getattr(server, name)
            if name.endswith("_FILE") and isinstance(value, Path):
                self._saved[name] = value
                setattr(server, name, d / value.name)
        self._saved["AUTH_TOKEN"] = server.AUTH_TOKEN
        server.AUTH_TOKEN = TOKEN
        server.DATA_FILE.write_text(json.dumps({"items": []}))
        server.FAILURES_FILE.write_text(json.dumps({"items": []}))
        self.fetched = []
        self._patch = mock.patch.object(server, "process_url",
                                        lambda url, *a, **k: self.fetched.append(url))
        self._patch.start()
        self.httpd = ThreadingHTTPServer(("127.0.0.1", 0), server.Handler)
        self.port = self.httpd.server_address[1]
        threading.Thread(target=self.httpd.serve_forever, daemon=True).start()

    def tearDown(self):
        self.httpd.shutdown()
        self.httpd.server_close()
        self._patch.stop()
        for name, value in self._saved.items():
            setattr(server, name, value)
        self.tmp.cleanup()

    def post(self, path, body, token=None, origin=None, cookie=False):
        data = json.dumps(body).encode()
        req = urllib.request.Request(f"http://127.0.0.1:{self.port}{path}", data=data, method="POST")
        req.add_header("Content-Type", "application/json")
        if token:
            req.add_header("Authorization", "Bearer " + token)
        if cookie:
            req.add_header("Cookie", f"{server.COOKIE_NAME}={server._session_cookie_value()}")
        if origin:
            req.add_header("Origin", origin)
        try:
            with urllib.request.urlopen(req, timeout=10) as r:
                return r.status
        except urllib.error.HTTPError as e:
            return e.code

    def inbox_urls(self):
        if not server.INBOX_FILE.exists():
            return []
        return [i["url"] for i in json.loads(server.INBOX_FILE.read_text())["items"]]

    def test_no_token_is_refused_and_not_recorded(self):
        for path in ("/add", "/add_sync"):
            self.assertEqual(self.post(path, {"url": "https://example.com/no-token" + path}), 401)
        self.assertEqual(self.inbox_urls(), [])

    def test_wrong_token_is_refused_and_not_recorded(self):
        self.assertEqual(self.post("/add", {"url": "https://example.com/wrong"}, token="wrong-token"), 401)
        self.assertEqual(self.inbox_urls(), [])

    def test_cross_origin_page_without_token_writes_nothing(self):
        status = self.post("/add", {"url": "https://example.com/from-a-page"}, origin="https://evil.example")
        self.assertEqual(status, 401)
        self.assertEqual(self.inbox_urls(), [])

    def test_authenticated_ingest_is_recorded_as_authed(self):
        self.assertEqual(self.post("/add", {"url": "https://example.com/good"}, token=TOKEN), 200)
        items = json.loads(server.INBOX_FILE.read_text())["items"]
        self.assertEqual([i["url"] for i in items], ["https://example.com/good"])
        self.assertTrue(items[0]["authed"])

    def test_cookie_from_another_origin_is_refused_and_not_recorded(self):
        status = self.post("/add", {"url": "https://example.com/cookie-ride"}, cookie=True,
                           origin="http://127.0.0.1:9999")
        self.assertEqual(status, 403)
        self.assertEqual(self.inbox_urls(), [])

    def test_same_origin_cookie_ingest_is_recorded(self):
        status = self.post("/add", {"url": "https://example.com/from-view"}, cookie=True,
                           origin=f"http://127.0.0.1:{self.port}")
        self.assertEqual(status, 200)
        self.assertEqual(self.inbox_urls(), ["https://example.com/from-view"])

    def test_non_ingest_routes_never_touch_the_inbox(self):
        self.assertEqual(self.post("/delete", {"url": "https://example.com/x"}, token=TOKEN), 200)
        self.assertEqual(self.inbox_urls(), [])


if __name__ == "__main__":
    unittest.main()
