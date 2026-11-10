"""The browser view's safety rails: local Host only, token-protected actions, no path tricks."""

import json
import re
import shutil
import tempfile
import threading
import unittest
import urllib.error
import urllib.request
from http.server import ThreadingHTTPServer
from pathlib import Path
from unittest import mock

from mapper import common, viewer

from tests import fake_pc


class ViewerServer(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = Path(tempfile.mkdtemp())
        snaps = cls.tmp / "snapshots"
        snaps.mkdir()
        fake_pc.build(snaps / "snapshot-2026-01-01_000000.db")
        cls.patches = [
            mock.patch.object(common, "SNAPSHOT_DIR", snaps),
            mock.patch.object(common, "KEPT_PATH", cls.tmp / "cleanup-kept.json"),
            mock.patch.object(viewer, "KEPT_PATH", cls.tmp / "cleanup-kept.json"),
            mock.patch.object(viewer, "REPORT_DIR", cls.tmp / "reports"),
        ]
        for p in cls.patches:
            p.start()
        cls.httpd = ThreadingHTTPServer(("127.0.0.1", 0), viewer.Handler)
        port = cls.httpd.server_address[1]
        viewer.Handler.allowed_hosts = {f"127.0.0.1:{port}"}
        cls.base = f"http://127.0.0.1:{port}"
        threading.Thread(target=cls.httpd.serve_forever, daemon=True).start()
        page = urllib.request.urlopen(cls.base + "/").read().decode()
        cls.token = re.search(r'const TOKEN = "([^"]+)"', page).group(1)

    @classmethod
    def tearDownClass(cls):
        cls.httpd.shutdown()
        cls.httpd.server_close()
        for p in cls.patches:
            p.stop()
        shutil.rmtree(cls.tmp, ignore_errors=True)

    def request(self, path, body=None, token=None, host=None):
        headers = {"Content-Type": "application/json"}
        if token:
            headers["X-Token"] = token
        if host:
            headers["Host"] = host
        data = json.dumps(body).encode() if body is not None else None
        req = urllib.request.Request(self.base + path, data=data, headers=headers,
                                     method="POST" if body is not None else "GET")
        try:
            with urllib.request.urlopen(req) as r:
                return r.status, r.read()
        except urllib.error.HTTPError as e:
            return e.code, e.read()

    def test_other_hosts_are_refused(self):
        self.assertEqual(self.request("/api/snapshots", host="evil.example")[0], 403)

    def test_actions_need_the_token(self):
        self.assertEqual(self.request("/api/keep", {"key": "x", "keep": True})[0], 403)
        self.assertEqual(self.request("/api/open", {"what": "apps"})[0], 403)
        self.assertEqual(self.request("/api/reveal", {"path": "C:\\"})[0], 403)

    def test_only_listed_pages_can_be_opened(self):
        self.assertEqual(self.request("/api/open", {"what": "cmd.exe"}, self.token)[0], 404)

    def test_report_paths_cannot_escape(self):
        self.assertEqual(self.request("/reports/..%5C..%5Cwindows%5Cwin.ini")[0], 404)

    def test_cleanup_and_keep(self):
        status, body = self.request("/api/cleanup")
        self.assertEqual(status, 200)
        rows = json.loads(body)["rows"]
        self.assertTrue(rows)
        key = rows[0]["key"]
        self.assertEqual(self.request("/api/keep", {"key": key, "keep": True, "title": "t"}, self.token)[0], 200)
        kept = {r["key"]: r["kept"] for r in json.loads(self.request("/api/cleanup")[1])["rows"]}
        self.assertTrue(kept[key])
        self.assertEqual(self.request("/api/keep", {"key": key, "keep": False}, self.token)[0], 200)
        kept = {r["key"]: r["kept"] for r in json.loads(self.request("/api/cleanup")[1])["rows"]}
        self.assertFalse(kept[key])

    def test_categories(self):
        status, body = self.request("/api/categories")
        self.assertEqual(status, 200)
        cats = {r["cat"] for r in json.loads(body)["rows"]}
        self.assertTrue({"windows", "junk", "personal"} <= cats)


if __name__ == "__main__":
    unittest.main()
