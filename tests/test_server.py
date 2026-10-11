from __future__ import annotations

import base64
import hashlib
import http.cookiejar
import io
import json
import os
from pathlib import Path
import tempfile
import threading
import unittest
from unittest import mock
from urllib.error import HTTPError
from urllib.parse import quote, urlencode
from urllib.request import HTTPCookieProcessor, Request, build_opener
import zipfile

import server as app


class QuietShareHandler(app.ShareHandler):
    def log_message(self, _fmt: str, *_args: object) -> None:
        pass


class RunningShare:
    def __init__(self, root: Path, *, one_time: bool = False):
        self.root = root
        self.temp = tempfile.TemporaryDirectory(prefix="file-share-test-state-")
        self.config = app.Config(root, "127.0.0.1", 0, True, None, one_time)
        self.state = app.State(self.config, Path(self.temp.name))
        self.state.open_root()
        self.httpd = app.http.server.ThreadingHTTPServer(("127.0.0.1", 0), QuietShareHandler)
        self.httpd.daemon_threads = True
        self.httpd.share_state = self.state
        self.state.server = self.httpd
        self.config.port = int(self.httpd.server_address[1])
        self.origin = f"http://127.0.0.1:{self.config.port}"
        self.base = self.origin + "/"
        self.thread = threading.Thread(target=self.httpd.serve_forever, daemon=True)
        self.thread.start()
        self.jar = http.cookiejar.CookieJar()
        self.client = build_opener(HTTPCookieProcessor(self.jar))
        response = self.client.open(
            Request(
                self.base + "login",
                data=urlencode({"password": self.state.password}).encode(),
                method="POST",
                headers={"Content-Type": "application/x-www-form-urlencoded", "Origin": self.origin},
            ),
            timeout=5,
        )
        if response.status != 200:
            raise AssertionError(f"login failed: HTTP {response.status}")
        response.close()

    def close(self) -> None:
        self.httpd.shutdown()
        self.httpd.server_close()
        self.thread.join(timeout=3)
        self.state.close_root()
        self.temp.cleanup()

    def open(self, path: str, *, method: str = "GET", data: bytes | None = None, headers: dict[str, str] | None = None):
        request = Request(self.base + path.lstrip("/"), data=data, method=method, headers=headers or {})
        return self.client.open(request, timeout=10)

    def put(self, name: str, data: bytes, *, origin: str | None = None):
        headers = {"Content-Type": "application/octet-stream", "Origin": origin or self.origin}
        return self.open("/upload/" + quote(name, safe=""), method="PUT", data=data, headers=headers)


class FileShareTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory(prefix="file-share-test-root-")
        self.root = Path(self.temp.name) / "shared"
        self.root.mkdir()
        (self.root / "sample.txt").write_bytes(b"0123456789")
        (self.root / "empty.txt").write_bytes(b"")
        try:
            (self.root / "outside-link").symlink_to("/etc/passwd")
        except OSError:
            pass
        self.share = RunningShare(self.root)

    def tearDown(self) -> None:
        self.share.close()
        self.temp.cleanup()

    def test_authenticated_listing_range_and_path_guards(self) -> None:
        payload = json.loads(self.share.open("/api/files").read())
        names = {item["name"] for item in payload["files"]}
        self.assertIn("sample.txt", names)
        self.assertIn("empty.txt", names)
        self.assertNotIn("outside-link", names)

        partial = self.share.open(
            "/download/sample.txt",
            headers={"Range": "bytes=2-4", "Sec-Fetch-Site": "same-origin"},
        )
        self.assertEqual(partial.status, 206)
        self.assertEqual(partial.read(), b"234")

        with self.assertRaises(HTTPError) as traversal:
            self.share.open("/download/..%2Fetc%2Fpasswd")
        self.assertEqual(traversal.exception.code, 404)

        with self.assertRaises(HTTPError) as cross_site:
            self.share.open("/download/sample.txt", headers={"Sec-Fetch-Site": "same-site"})
        self.assertEqual(cross_site.exception.code, 403)

    def test_login_rejects_cross_origin_request(self) -> None:
        request = Request(
            self.share.base + "login",
            data=urlencode({"password": self.share.state.password}).encode(),
            method="POST",
            headers={
                "Content-Type": "application/x-www-form-urlencoded",
                "Origin": "https://attacker.example",
            },
        )
        with self.assertRaises(HTTPError) as cross_origin:
            build_opener().open(request, timeout=5)
        self.assertEqual(cross_origin.exception.code, 403)

    def test_upload_requires_authentication(self) -> None:
        request = Request(
            self.share.base + "upload/unauthorized.txt",
            data=b"must not publish",
            method="PUT",
            headers={"Content-Type": "application/octet-stream", "Origin": self.share.origin},
        )
        with self.assertRaises(HTTPError) as unauthorized:
            build_opener().open(request, timeout=5)
        self.assertEqual(unauthorized.exception.code, 401)
        self.assertFalse((self.root / "unauthorized.txt").exists())

    def test_dashboard_contains_upload_controls(self) -> None:
        response = self.share.open("/")
        page = response.read().decode("utf-8")
        self.assertIn('id="uploadFile"', page)
        self.assertIn('id="uploadInput"', page)
        self.assertIn('"max_upload_size":1073741824', page)
        self.assertIn('class="skip-link" href="#main-content"', page)
        self.assertIn('id="main-content" tabindex="-1"', page)
        self.assertIn('role="list"', page)
        self.assertIn('aria-pressed="true"', page)
        self.assertIn('role="progressbar"', page)
        self.assertIn('/assets/qrcode-generator.js', page)
        digest = base64.b64encode(hashlib.sha512(app.QR_SCRIPT_PATH.read_bytes()).digest()).decode("ascii")
        self.assertIn(f'integrity="sha512-{digest}"', page)
        self.assertNotIn('cdn.jsdelivr.net', page)
        self.assertNotIn('archiveOverlay', page)

    def test_loopback_host_classifier_is_conservative(self) -> None:
        for host in ("localhost", "localhost.", "127.0.0.1", "::1"):
            with self.subTest(host=host):
                self.assertTrue(app.is_loopback_host(host))
        for host in ("0.0.0.0", "192.168.1.10", "example.org"):
            with self.subTest(host=host):
                self.assertFalse(app.is_loopback_host(host))
        self.assertEqual(app.origin_host_for_bind("0.0.0.0"), "127.0.0.1")
        self.assertEqual(app.origin_host_for_bind("::"), "::1")
        self.assertEqual(app.format_http_origin("::1", 80), "http://[::1]")

    def test_filename_validation_rejects_path_and_control_characters(self) -> None:
        self.assertIsNone(app.safe_filename("../secret.txt"))
        self.assertIsNone(app.safe_filename("nested\\secret.txt"))
        self.assertIsNone(app.safe_filename("line\nbreak.txt"))

    def test_upload_requires_same_origin_and_never_overwrites(self) -> None:
        with self.assertRaises(HTTPError) as cross_origin:
            self.share.put("blocked.txt", b"blocked", origin="https://attacker.example")
        self.assertEqual(cross_origin.exception.code, 403)
        self.assertFalse((self.root / "blocked.txt").exists())

        rebound_origin = f"http://attacker.example:{self.share.config.port}"
        with self.assertRaises(HTTPError) as host_header:
            self.share.open(
                "/upload/rebound.txt",
                method="PUT",
                data=b"must not publish",
                headers={
                    "Content-Type": "application/octet-stream",
                    "Origin": rebound_origin,
                    "Host": f"attacker.example:{self.share.config.port}",
                },
            )
        self.assertEqual(host_header.exception.code, 403)
        self.assertFalse((self.root / "rebound.txt").exists())

        response = self.share.put("new file.txt", b"uploaded data")
        self.assertEqual(response.status, 201)
        self.assertEqual(json.loads(response.read()), {"name": "new file.txt", "size": 13})
        self.assertEqual((self.root / "new file.txt").read_bytes(), b"uploaded data")
        self.assertEqual((self.root / "new file.txt").stat().st_mode & 0o777, 0o600)
        listed = {item["name"] for item in json.loads(self.share.open("/api/files").read())["files"]}
        self.assertIn("new file.txt", listed)

        with self.assertRaises(HTTPError) as conflict:
            self.share.put("sample.txt", b"overwrite attempt")
        self.assertEqual(conflict.exception.code, 409)
        self.assertEqual((self.root / "sample.txt").read_bytes(), b"0123456789")

    def test_upload_size_limit_is_enforced_before_body_is_read(self) -> None:
        with mock.patch.object(app, "MAX_UPLOAD_SIZE", 3):
            with self.assertRaises(HTTPError) as too_large:
                self.share.put("large.txt", b"four")
        self.assertEqual(too_large.exception.code, 413)
        self.assertFalse((self.root / "large.txt").exists())

    def test_disk_work_slot_serializes_upload_and_bundle(self) -> None:
        self.assertTrue(self.share.state.disk_work_semaphore.acquire(blocking=False))
        try:
            with self.assertRaises(HTTPError) as upload_busy:
                self.share.put("busy.txt", b"busy")
            self.assertEqual(upload_busy.exception.code, 503)
            with self.assertRaises(HTTPError) as bundle_busy:
                self.share.open("/download-all", headers={"Sec-Fetch-Site": "same-origin"})
            self.assertEqual(bundle_busy.exception.code, 503)
        finally:
            self.share.state.disk_work_semaphore.release()

    def test_bundle_download_is_valid_and_limit_is_enforced(self) -> None:
        response = self.share.open("/download-all", headers={"Sec-Fetch-Site": "same-origin"})
        self.assertEqual(response.status, 200)
        archive_bytes = response.read()
        with zipfile.ZipFile(io.BytesIO(archive_bytes)) as archive:
            self.assertEqual(archive.read("sample.txt"), b"0123456789")
            self.assertEqual(archive.read("empty.txt"), b"")

        with mock.patch.object(app, "MAX_BUNDLE_SIZE", 3):
            with self.assertRaises(HTTPError) as too_large:
                self.share.open("/download-all")
        self.assertEqual(too_large.exception.code, 413)

        with mock.patch.object(app.shutil, "disk_usage", return_value=mock.Mock(free=0)):
            with self.assertRaises(HTTPError) as insufficient_space:
                self.share.open("/download-all")
        self.assertEqual(insufficient_space.exception.code, 507)

    def test_stop_share_requires_same_origin(self) -> None:
        with self.assertRaises(HTTPError) as cross_origin:
            self.share.open(
                "/stop-share",
                method="POST",
                data=b"",
                headers={"Origin": "https://attacker.example"},
            )
        self.assertEqual(cross_origin.exception.code, 403)
        self.assertFalse(self.share.state.stop_event.is_set())

        response = self.share.open(
            "/stop-share",
            method="POST",
            data=b"",
            headers={"Origin": self.share.origin},
        )
        self.assertEqual(response.status, 204)
        self.assertTrue(self.share.state.stop_event.is_set())

    @unittest.skipUnless(app.directory_fd_supported(), "directory-relative operations are not supported here")
    def test_root_path_replacement_does_not_change_shared_directory(self) -> None:
        outside = self.root.parent / "outside"
        outside.mkdir()
        (outside / "secret.txt").write_text("outside", encoding="utf-8")
        original_root = self.root.parent / "shared-original"
        self.root.rename(original_root)
        self.root.symlink_to(outside, target_is_directory=True)

        names = {item["name"] for item in json.loads(self.share.open("/api/files").read())["files"]}
        self.assertIn("sample.txt", names)
        self.assertNotIn("secret.txt", names)
        with self.assertRaises(HTTPError) as outside_download:
            self.share.open("/download/secret.txt")
        self.assertEqual(outside_download.exception.code, 404)
        self.assertEqual(self.share.open("/download/sample.txt").read(), b"0123456789")

    def test_status_stats_are_a_snapshot(self) -> None:
        self.share.state.stats["sample.txt"] = {"downloads": 1, "bytes": 10}
        snapshot = self.share.state.status()["stats"]
        self.share.state.stats["new.txt"] = {"downloads": 1, "bytes": 1}
        self.share.state.stats["sample.txt"]["downloads"] = 9
        self.assertNotIn("new.txt", snapshot)
        self.assertEqual(snapshot["sample.txt"]["downloads"], 1)

    def test_empty_one_time_download_stops_share(self) -> None:
        self.share.close()
        self.share = RunningShare(self.root, one_time=True)
        response = self.share.open("/download/empty.txt", headers={"Range": "bytes=0-0"})
        self.assertEqual(response.status, 200)
        self.assertEqual(response.read(), b"")
        self.assertTrue(self.share.state.stop_event.wait(1))
        status = self.share.state.status()
        self.assertEqual(status["downloads_total"], 1)
        self.assertEqual(status["bytes_total"], 0)

    def test_qr_asset_is_served_locally(self) -> None:
        response = self.share.open("/assets/qrcode-generator.js")
        self.assertEqual(response.status, 200)
        self.assertIn(b"QR Code Generator", response.read()[:1000])


if __name__ == "__main__":
    unittest.main()
