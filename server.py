#!/usr/bin/env python3
"""Lightweight authenticated temporary file-sharing server.

Examples:
    python3 server.py /root/swiftslate-secrets
    python3 server.py /root/backups --expires 1h
    python3 server.py /root/one-file --one-time
    python3 server.py /root/files --expires 30m --one-time --port 8080
    python3 server.py /root/files --no-tunnel

The application uses only Python's standard library. A Cloudflare Quick
Tunnel is started automatically unless --no-tunnel is supplied.
"""

from __future__ import annotations

import argparse
import hashlib
import hmac
import html
import http.server
import json
import mimetypes
import os
from pathlib import Path
import re
import secrets
import shutil
import signal
import socket
import subprocess
import sys
import tempfile
import threading
import time
import zipfile
from typing import NoReturn
from urllib.error import HTTPError, URLError
from urllib.parse import parse_qs, quote, unquote, urlparse
from urllib.request import Request, urlopen

APP_VERSION = "3.0.1"
TEMPLATE_PATH = Path(__file__).resolve().parent / "templates" / "index.html"
SESSION_COOKIE = "fs_session"
SESSION_TTL = 12 * 60 * 60
LOGIN_WINDOW = 60
LOGIN_MAX_ATTEMPTS = 5
MAX_NAME_LENGTH = 255
DEFAULT_EXPIRY = 30 * 60
MAX_SHARE_LIFETIME = 7 * 24 * 60 * 60
PROGRESS_LIMIT = 50 * 1024 * 1024
CLOUDFLARE_API = "https://api.github.com/repos/cloudflare/cloudflared/releases/latest"
CLOUDFLARE_USER_AGENT = f"file-share/{APP_VERSION}"


def fail(message: str, code: int = 1) -> NoReturn:
    print(f"[ERROR] {message}", file=sys.stderr)
    raise SystemExit(code)


def human_size(size: int) -> str:
    units = ["B", "KB", "MB", "GB", "TB"]
    value = float(size)
    for unit in units:
        if value < 1024 or unit == units[-1]:
            return f"{value:.0f} {unit}" if unit == "B" else f"{value:.1f} {unit}"
        value /= 1024
    return f"{size} B"


def file_type(name: str) -> str:
    mime, _ = mimetypes.guess_type(name)
    if mime:
        return mime
    suffix = Path(name).suffix.lower().lstrip(".")
    return suffix.upper() if suffix else "FILE"


def category_for(name: str, mime: str) -> str:
    ext = Path(name).suffix.lower()
    if ext in {".zip", ".7z", ".rar", ".tar", ".gz", ".bz2", ".xz", ".tgz", ".tbz2"}:
        return "archives"
    if mime.startswith("image/") or ext in {".svg", ".ico"}:
        return "images"
    if mime.startswith("text/") or mime in {"application/json", "application/xml", "application/pdf"} or ext in {".md", ".csv", ".log", ".yaml", ".yml", ".toml"}:
        return "documents"
    return "other"


def parse_duration(value: str) -> int:
    text = value.strip().lower()
    match = re.fullmatch(r"(\d+(?:\.\d+)?)(s|m|h|d)", text)
    if not match:
        raise ValueError("duration must look like 30s, 15m, 1h or 1d")
    amount = float(match.group(1))
    unit = match.group(2)
    multiplier = {"s": 1, "m": 60, "h": 3600, "d": 86400}[unit]
    seconds = int(amount * multiplier)
    if seconds < 5:
        raise ValueError("duration must be at least 5 seconds")
    if seconds > MAX_SHARE_LIFETIME:
        raise ValueError("duration cannot exceed 7 days")
    return seconds


def safe_filename(name: str) -> str | None:
    if not name or name in {".", ".."} or len(name) > MAX_NAME_LENGTH:
        return None
    if "/" in name or "\\" in name or "\x00" in name:
        return None
    return name


def safe_child(root: Path, name: str) -> Path | None:
    if safe_filename(name) is None:
        return None
    candidate = root / name
    try:
        if candidate.is_symlink() or not candidate.is_file():
            return None
        real_root = root.resolve()
        real_candidate = candidate.resolve()
        if os.path.commonpath([str(real_root), str(real_candidate)]) != str(real_root):
            return None
        return real_candidate
    except (OSError, ValueError):
        return None


def iter_regular_files(root: Path) -> list[dict[str, object]]:
    result: list[dict[str, object]] = []
    try:
        entries = sorted(root.iterdir(), key=lambda p: p.name.casefold())
    except OSError:
        return result
    for entry in entries:
        if entry.is_symlink() or not entry.is_file():
            continue
        try:
            stat = entry.stat()
        except OSError:
            continue
        mime = mimetypes.guess_type(entry.name)[0] or "application/octet-stream"
        result.append(
            {
                "name": entry.name,
                "size": stat.st_size,
                "size_human": human_size(stat.st_size),
                "mtime": time.strftime("%Y-%m-%d %H:%M", time.localtime(stat.st_mtime)),
                "type": file_type(entry.name),
                "category": category_for(entry.name, mime),
            }
        )
    return result


def render_template(template: str, content: str, *, title: str, nonce: str, app_data: dict[str, object]) -> bytes:
    safe_data = json.dumps(app_data, ensure_ascii=True, separators=(",", ":"))
    safe_data = safe_data.replace("<", "\\u003c").replace(">", "\\u003e").replace("&", "\\u0026")
    replacements = {
        "{{TITLE}}": html.escape(title),
        "{{CONTENT}}": content,
        "{{VERSION}}": html.escape(APP_VERSION),
        "{{NONCE}}": html.escape(nonce, quote=True),
        "{{APP_DATA}}": safe_data,
    }
    rendered = template
    for key, value in replacements.items():
        rendered = rendered.replace(key, value)
    return rendered.encode("utf-8")


def load_template() -> str:
    try:
        template = TEMPLATE_PATH.read_text(encoding="utf-8")
    except OSError as exc:
        fail(f"Unable to load template {TEMPLATE_PATH}: {exc}")
    required = ("{{CONTENT}}", "{{NONCE}}", "{{APP_DATA}}")
    if any(item not in template for item in required):
        fail("Template is missing one or more required placeholders.")
    return template


def http_download(url: str, *, headers: dict[str, str] | None = None, timeout: int = 30) -> bytes:
    request = Request(url, headers=headers or {})
    with urlopen(request, timeout=timeout) as response:
        return response.read()


def download_stream(url: str, destination: Path, *, headers: dict[str, str] | None = None, timeout: int = 60) -> str:
    request = Request(url, headers=headers or {})
    digest = hashlib.sha256()
    with urlopen(request, timeout=timeout) as response, destination.open("wb") as output:
        while True:
            chunk = response.read(1024 * 1024)
            if not chunk:
                break
            output.write(chunk)
            digest.update(chunk)
    return digest.hexdigest()


def architecture_asset() -> str:
    machine = os.uname().machine.lower()
    mapping = {
        "x86_64": "amd64",
        "amd64": "amd64",
        "aarch64": "arm64",
        "arm64": "arm64",
        "armv7l": "arm",
        "armv7": "arm",
        "i386": "386",
        "i686": "386",
    }
    asset = mapping.get(machine)
    if not asset:
        raise RuntimeError(f"unsupported Linux architecture: {machine}")
    return asset


def ensure_cloudflared(temp_root: Path) -> str:
    existing = shutil.which("cloudflared")
    if existing:
        try:
            subprocess.run([existing, "--version"], check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=10)
            return existing
        except (OSError, subprocess.SubprocessError):
            pass

    if not sys.platform.startswith("linux"):
        fail("cloudflared is missing. Automatic installation is implemented for Linux VPS/container environments.")

    try:
        asset_arch = architecture_asset()
        asset_name = f"cloudflared-linux-{asset_arch}"
        request = Request(
            CLOUDFLARE_API,
            headers={"Accept": "application/vnd.github+json", "User-Agent": CLOUDFLARE_USER_AGENT},
        )
        with urlopen(request, timeout=20) as response:
            release = json.load(response)
    except Exception as exc:
        fail(f"Unable to retrieve the official cloudflared release metadata: {exc}")

    asset = next((item for item in release.get("assets", []) if item.get("name") == asset_name), None)
    if not asset:
        fail(f"The official release does not contain {asset_name}.")

    download_url = asset.get("browser_download_url")
    digest = asset.get("digest") or ""
    if not isinstance(download_url, str) or not download_url.startswith("https://"):
        fail("The official cloudflared asset has no usable HTTPS download URL.")
    if not isinstance(digest, str) or not digest.startswith("sha256:"):
        fail("The official cloudflared asset did not provide a SHA-256 digest; refusing an unverified binary.")
    expected = digest.split(":", 1)[1].lower()

    binary = temp_root / asset_name
    print(f"[INFO] cloudflared not found; downloading verified official binary ({asset_arch})...")
    try:
        actual = download_stream(download_url, binary, headers={"User-Agent": CLOUDFLARE_USER_AGENT}, timeout=90)
    except Exception as exc:
        fail(f"Unable to download cloudflared: {exc}")

    if not hmac.compare_digest(actual, expected):
        try:
            binary.unlink()
        except OSError:
            pass
        fail("cloudflared SHA-256 verification failed; the binary was rejected.")

    binary.chmod(0o700)
    try:
        subprocess.run([str(binary), "--version"], check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=10)
    except Exception as exc:
        fail(f"Downloaded cloudflared failed executable validation: {exc}")
    print("[OK] Official cloudflared binary downloaded and SHA-256 verified.")
    return str(binary)


class Config:
    def __init__(self, root: Path, host: str, port: int, no_tunnel: bool, expires: int | None, one_time: bool):
        self.root = root
        self.host = host
        self.port = port
        self.no_tunnel = no_tunnel
        self.expires = expires
        self.one_time = one_time


class State:
    def __init__(self, config: Config, temp_root: Path):
        self.config = config
        self.temp_root = temp_root
        self.password = secrets.token_urlsafe(12)
        self.created_at = time.time()
        self.expires_at = self.created_at + config.expires if config.expires else None
        self.sessions: dict[str, float] = {}
        self.login_attempts: dict[str, list[float]] = {}
        self.stats: dict[str, dict[str, int]] = {}
        self.downloads_total = 0
        self.bytes_total = 0
        self.active_downloads = 0
        self.lock = threading.RLock()
        self.server: http.server.ThreadingHTTPServer | None = None
        self.http_thread: threading.Thread | None = None
        self.tunnel: subprocess.Popen[str] | None = None
        self.tunnel_home: Path | None = None
        self.tunnel_log: Path | None = None
        self.public_url: str | None = None
        self.stop_event = threading.Event()
        self.stop_reason = "stopped"

    def is_expired(self) -> bool:
        with self.lock:
            return self.expires_at is not None and time.time() >= self.expires_at

    def remaining_seconds(self) -> int | None:
        with self.lock:
            if self.expires_at is None:
                return None
            return max(0, int(self.expires_at - time.time()))

    def ensure_active(self) -> bool:
        if self.is_expired():
            self.stop_reason = "expired"
            self.stop_event.set()
            return False
        return not self.stop_event.is_set()

    def client_id(self, handler: http.server.BaseHTTPRequestHandler) -> str:
        # The origin only binds to loopback by default. Quick Tunnel supplies
        # CF-Connecting-IP to the local origin for public clients.
        return (
            handler.headers.get("CF-Connecting-IP")
            or handler.headers.get("X-Forwarded-For", "").split(",")[0].strip()
            or handler.client_address[0]
        )

    def allow_login_attempt(self, client: str) -> tuple[bool, int]:
        now = time.time()
        with self.lock:
            for key in list(self.login_attempts):
                self.login_attempts[key] = [t for t in self.login_attempts[key] if now - t < LOGIN_WINDOW]
                if not self.login_attempts[key]:
                    self.login_attempts.pop(key, None)
            values = [t for t in self.login_attempts.get(client, []) if now - t < LOGIN_WINDOW]
            if len(values) >= LOGIN_MAX_ATTEMPTS:
                retry = max(1, int(LOGIN_WINDOW - (now - values[0])))
                self.login_attempts[client] = values
                return False, retry
            values.append(now)
            self.login_attempts[client] = values
            return True, 0

    def login_success(self, client: str) -> None:
        with self.lock:
            self.login_attempts.pop(client, None)

    def create_session(self) -> str:
        token = secrets.token_urlsafe(32)
        ttl = SESSION_TTL
        remaining = self.remaining_seconds()
        if remaining is not None:
            ttl = min(ttl, max(1, remaining))
        with self.lock:
            self.sessions[token] = time.time() + ttl
        return token

    def is_authenticated(self, handler: http.server.BaseHTTPRequestHandler) -> bool:
        self.ensure_active()
        cookie_header = handler.headers.get("Cookie", "")
        token = None
        for part in cookie_header.split(";"):
            name, sep, value = part.strip().partition("=")
            if sep and name == SESSION_COOKIE:
                token = value
                break
        if not token:
            return False
        with self.lock:
            expiry = self.sessions.get(token)
            if expiry is None or expiry <= time.time():
                self.sessions.pop(token, None)
                return False
            remaining = self.remaining_seconds()
            if remaining is not None:
                expiry = min(expiry, time.time() + remaining)
            self.sessions[token] = expiry
            return True

    def revoke_session(self, handler: http.server.BaseHTTPRequestHandler) -> None:
        cookie_header = handler.headers.get("Cookie", "")
        for part in cookie_header.split(";"):
            name, sep, value = part.strip().partition("=")
            if sep and name == SESSION_COOKIE:
                with self.lock:
                    self.sessions.pop(value, None)
                return

    def cookie_suffix(self) -> str:
        secure = "; Secure" if self.public_url else ""
        return f"; Path=/; HttpOnly{secure}; SameSite=Strict"

    def record_start(self, name: str) -> None:
        with self.lock:
            self.active_downloads += 1
            self.stats.setdefault(name, {"downloads": 0, "bytes": 0})

    def record_finish(self, name: str, size: int, complete: bool) -> None:
        with self.lock:
            self.active_downloads = max(0, self.active_downloads - 1)
            if complete:
                item = self.stats.setdefault(name, {"downloads": 0, "bytes": 0})
                item["downloads"] += 1
                item["bytes"] += size
                self.downloads_total += 1
                self.bytes_total += size
                if self.config.one_time:
                    self.stop_reason = "one-time download completed"
                    self.stop_event.set()

    def status(self) -> dict[str, object]:
        files = iter_regular_files(self.config.root)
        with self.lock:
            return {
                "version": APP_VERSION,
                "expires_at": self.expires_at,
                "remaining": self.remaining_seconds(),
                "one_time": self.config.one_time,
                "downloads_total": self.downloads_total,
                "bytes_total": self.bytes_total,
                "bytes_total_human": human_size(self.bytes_total),
                "active_downloads": self.active_downloads,
                "file_count": len(files),
                "stats": self.stats,
            }


class ShareHandler(http.server.BaseHTTPRequestHandler):
    server_version = "FileShare/3.0.1"

    @property
    def state(self) -> State:
        return self.server.share_state  # type: ignore[attr-defined]

    def log_message(self, fmt: str, *args: object) -> None:
        print(f"[HTTP] {self.client_address[0]} - {fmt % args}")

    def nonce(self) -> str:
        return secrets.token_urlsafe(18)

    def send_security_headers(self, *, nonce: str | None = None) -> None:
        script_policy = f"'nonce-{nonce}' https://cdn.jsdelivr.net" if nonce else "'none'"
        csp = (
            "default-src 'self'; "
            f"script-src {script_policy}; "
            "style-src 'self' 'unsafe-inline'; "
            "img-src 'self' data:; "
            "connect-src 'self'; "
            "font-src 'self'; "
            "form-action 'self'; "
            "frame-ancestors 'none'; base-uri 'none'; object-src 'none'"
        )
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Referrer-Policy", "no-referrer")
        self.send_header("X-Frame-Options", "DENY")
        self.send_header("Content-Security-Policy", csp)
        self.send_header("Permissions-Policy", "camera=(), microphone=(), geolocation=()")

    def send_html(self, payload: bytes, *, status: int = 200, nonce: str = "") -> None:
        self.send_response(status)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(payload)))
        self.send_header("Cache-Control", "no-store, max-age=0")
        self.send_security_headers(nonce=nonce)
        self.end_headers()
        self.wfile.write(payload)

    def render_page(self, content: str, *, status: int = 200, title: str = "File Share", extra_headers: dict[str, str] | None = None) -> None:
        nonce = self.nonce()
        data: dict[str, object] = {
            "public_url": self.state.public_url,
            "local_url": f"http://127.0.0.1:{self.state.config.port}/",
            "one_time": self.state.config.one_time,
            "expires_at": self.state.expires_at,
            "progress_limit": PROGRESS_LIMIT,
        }
        payload = render_template(load_template(), content, title=title, nonce=nonce, app_data=data)
        self.send_response(status)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(payload)))
        self.send_header("Cache-Control", "no-store, max-age=0")
        self.send_security_headers(nonce=nonce)
        for key, value in (extra_headers or {}).items():
            self.send_header(key, value)
        self.end_headers()
        self.wfile.write(payload)

    def send_json(self, data: dict[str, object], *, status: int = 200) -> None:
        payload = json.dumps(data, ensure_ascii=True, separators=(",", ":")).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(payload)))
        self.send_header("Cache-Control", "no-store, max-age=0")
        self.send_security_headers()
        self.end_headers()
        self.wfile.write(payload)

    def reject_expired(self) -> bool:
        if self.state.ensure_active():
            return False
        remaining = self.state.remaining_seconds()
        if remaining == 0 or self.state.stop_reason == "expired":
            self.send_html(b"<h1>Share expired</h1>", status=410)
        else:
            self.send_html(b"<h1>Share stopped</h1>", status=410)
        return True

    def do_GET(self) -> None:
        if self.reject_expired():
            return
        parsed = urlparse(self.path)
        path = parsed.path

        if path == "/favicon.ico":
            self.send_response(204)
            self.end_headers()
            return

        if path in {"/", "/index.html"}:
            if not self.state.is_authenticated(self):
                self.render_page(login_html(), title="Sign in · File Share")
            else:
                self.render_page(dashboard_html(self.state), title="Files · File Share")
            return

        if path == "/api/status":
            if not self.state.is_authenticated(self):
                self.send_json({"error": "authentication required"}, status=401)
                return
            self.send_json(self.state.status())
            return

        if path == "/api/files":
            if not self.state.is_authenticated(self):
                self.send_json({"error": "authentication required"}, status=401)
                return
            self.send_json({"files": iter_regular_files(self.state.config.root)})
            return

        if path.startswith("/download/"):
            if not self.state.is_authenticated(self):
                self.send_html(b"<h1>Authentication required</h1>", status=401)
                return
            name = unquote(path[len("/download/"):])
            self.handle_file_download(name)
            return

        if path == "/download-all":
            if not self.state.is_authenticated(self):
                self.send_html(b"<h1>Authentication required</h1>", status=401)
                return
            self.handle_bundle_download()
            return

        self.send_error(404, "Not found")

    def do_HEAD(self) -> None:
        if self.reject_expired():
            return
        parsed = urlparse(self.path)
        if not parsed.path.startswith("/download/") or not self.state.is_authenticated(self):
            self.send_error(404, "Not found")
            return
        name = unquote(parsed.path[len("/download/"):])
        target = safe_child(self.state.config.root, name)
        if target is None:
            self.send_error(404, "File not found")
            return
        try:
            size = target.stat().st_size
        except OSError:
            self.send_error(404, "File not found")
            return
        self.send_response(200)
        self.send_header("Content-Type", mimetypes.guess_type(name)[0] or "application/octet-stream")
        self.send_header("Content-Length", str(size))
        self.send_header("Content-Disposition", self.content_disposition(name))
        self.send_header("Cache-Control", "no-store, max-age=0")
        self.send_header("Accept-Ranges", "none" if self.state.config.one_time else "bytes")
        self.send_security_headers()
        self.end_headers()

    def do_POST(self) -> None:
        if self.reject_expired():
            return
        parsed = urlparse(self.path)
        if parsed.path == "/login":
            self.handle_login()
            return
        if parsed.path == "/logout":
            if not self.state.is_authenticated(self):
                self.send_response(303)
                self.send_header("Location", "/")
                self.end_headers()
                return
            self.state.revoke_session(self)
            self.send_response(303)
            self.send_header("Location", "/")
            self.send_header("Set-Cookie", f"{SESSION_COOKIE}=deleted; Max-Age=0{self.state.cookie_suffix()}")
            self.end_headers()
            return
        self.send_error(404, "Not found")

    def handle_login(self) -> None:
        client = self.state.client_id(self)
        allowed, retry_after = self.state.allow_login_attempt(client)
        if not allowed:
            self.render_page(
                '<section class="auth-card"><div class="eyebrow">RATE LIMITED</div><h1>Too many attempts</h1><p class="muted">Try again in about one minute.</p></section>',
                status=429,
                title="Rate limited · File Share",
                extra_headers={"Retry-After": str(retry_after)},
            )
            return

        try:
            length = int(self.headers.get("Content-Length", "0"))
        except ValueError:
            length = 0
        if length < 0 or length > 4096:
            self.send_error(400, "Request too large")
            return
        data = self.rfile.read(length).decode("utf-8", "replace")
        password = parse_qs(data, keep_blank_values=True).get("password", [""])[0]
        if not hmac.compare_digest(password.encode("utf-8"), self.state.password.encode("utf-8")):
            self.render_page('<section class="auth-card"><div class="eyebrow">DENIED</div><h1>Access denied</h1><p class="muted">The password is incorrect.</p><a class="back" href="/">Try again</a></section>', status=401, title="Access denied · File Share")
            return

        self.state.login_success(client)
        token = self.state.create_session()
        self.send_response(303)
        self.send_header("Location", "/")
        self.send_header("Set-Cookie", f"{SESSION_COOKIE}={token}; Max-Age={SESSION_TTL}{self.state.cookie_suffix()}")
        self.end_headers()

    @staticmethod
    def content_disposition(name: str) -> str:
        clean = name.replace("\r", "").replace("\n", "")
        ascii_name = clean.encode("ascii", "replace").decode("ascii").replace('"', "") or "download"
        return f'attachment; filename="{ascii_name}"; filename*=UTF-8\'\'{quote(clean, safe="")}'

    def open_target(self, target: Path):
        flags = os.O_RDONLY
        if hasattr(os, "O_NOFOLLOW"):
            flags |= os.O_NOFOLLOW
        fd = os.open(target, flags)
        return os.fdopen(fd, "rb", buffering=1024 * 1024)

    def parse_range(self, header: str, size: int) -> tuple[int, int] | None:
        if not header.startswith("bytes=") or "," in header:
            return None
        spec = header[6:].strip()
        if "-" not in spec:
            return None
        start_text, end_text = spec.split("-", 1)
        try:
            if start_text == "":
                length = int(end_text)
                if length <= 0:
                    return None
                start = max(0, size - length)
                end = size - 1
            else:
                start = int(start_text)
                end = int(end_text) if end_text else size - 1
        except ValueError:
            return None
        if start < 0 or start >= size or end < start:
            return None
        end = min(end, size - 1)
        return start, end

    def stream_file(self, source, *, start: int, length: int) -> int:
        source.seek(start)
        remaining = length
        sent = 0
        while remaining > 0:
            chunk = source.read(min(1024 * 1024, remaining))
            if not chunk:
                break
            self.wfile.write(chunk)
            sent += len(chunk)
            remaining -= len(chunk)
        return sent

    def handle_file_download(self, name: str) -> None:
        target = safe_child(self.state.config.root, name)
        if target is None:
            self.send_error(404, "File not found")
            return
        try:
            source = self.open_target(target)
            stat = os.fstat(source.fileno())
            size = stat.st_size
        except (OSError, ValueError):
            self.send_error(404, "File not found")
            return

        range_header = self.headers.get("Range")
        requested = self.parse_range(range_header, size) if range_header and not self.state.config.one_time else None
        if range_header and not self.state.config.one_time and requested is None:
            source.close()
            self.send_response(416)
            self.send_header("Content-Range", f"bytes */{size}")
            self.end_headers()
            return

        if requested:
            start, end = requested
            length = end - start + 1
            status = 206
        else:
            start, end, length, status = 0, max(0, size - 1), size, 200

        mime = mimetypes.guess_type(name)[0] or "application/octet-stream"
        self.state.record_start(name)
        complete = False
        sent = 0
        try:
            self.send_response(status)
            self.send_header("Content-Type", mime)
            self.send_header("Content-Length", str(length))
            self.send_header("Content-Disposition", self.content_disposition(name))
            self.send_header("Cache-Control", "no-store, max-age=0")
            self.send_header("Accept-Ranges", "none" if self.state.config.one_time else "bytes")
            if status == 206:
                self.send_header("Content-Range", f"bytes {start}-{end}/{size}")
            self.send_security_headers()
            self.end_headers()
            sent = self.stream_file(source, start=start, length=length)
            complete = sent == length and start == 0 and end == size - 1
        except (BrokenPipeError, ConnectionResetError):
            complete = False
        except OSError:
            complete = False
        finally:
            source.close()
            self.state.record_finish(name, sent, complete)

    def handle_bundle_download(self) -> None:
        files = iter_regular_files(self.state.config.root)
        if not files:
            self.send_error(404, "No files to bundle")
            return

        bundle = self.state.temp_root / f"files-{secrets.token_hex(8)}.zip"
        try:
            with zipfile.ZipFile(bundle, "w", compression=zipfile.ZIP_STORED, allowZip64=True) as archive:
                for item in files:
                    name = str(item["name"])
                    target = safe_child(self.state.config.root, name)
                    if target is None:
                        continue
                    try:
                        info = zipfile.ZipInfo(name)
                        stat = target.stat()
                        info.date_time = time.localtime(stat.st_mtime)[:6]
                        info.compress_type = zipfile.ZIP_STORED
                        with self.open_target(target) as source:
                            with archive.open(info, "w") as dest:
                                shutil.copyfileobj(source, dest, length=1024 * 1024)
                    except OSError:
                        continue
            size = bundle.stat().st_size
        except (OSError, zipfile.BadZipFile, zipfile.LargeZipFile) as exc:
            try:
                bundle.unlink()
            except OSError:
                pass
            self.send_error(500, f"Unable to create ZIP: {exc}")
            return

        self.state.record_start("__bundle__")
        sent = 0
        complete = False
        try:
            self.send_response(200)
            self.send_header("Content-Type", "application/zip")
            self.send_header("Content-Length", str(size))
            self.send_header("Content-Disposition", self.content_disposition("files.zip"))
            self.send_header("Cache-Control", "no-store, max-age=0")
            self.send_header("Accept-Ranges", "none")
            self.send_security_headers()
            self.end_headers()
            with bundle.open("rb") as source:
                sent = self.stream_file(source, start=0, length=size)
            complete = sent == size
        except (BrokenPipeError, ConnectionResetError, OSError):
            complete = False
        finally:
            self.state.record_finish("__bundle__", sent, complete)
            try:
                bundle.unlink()
            except OSError:
                pass


def login_html() -> str:
    return """
<section class="auth-card">
  <div class="eyebrow">TEMPORARY SHARE</div>
  <h1>Private file access</h1>
  <p class="muted">Enter the temporary password shown in the server logs.</p>
  <form method="post" action="/login" class="auth-form">
    <label for="password">Password</label>
    <input id="password" name="password" type="password" autocomplete="current-password" required autofocus>
    <button type="submit">Unlock files</button>
  </form>
</section>
"""


def dashboard_html(state: State) -> str:
    public_url = state.public_url or ""
    public_display = html.escape(public_url or f"http://127.0.0.1:{state.config.port}/")
    remaining = state.remaining_seconds()
    file_count = len(iter_regular_files(state.config.root))
    mode = "One-time download" if state.config.one_time else "Temporary access"
    expiry_text = "No expiry" if remaining is None else f"Expires in {remaining}s"
    public_url_json = json.dumps(public_url or f"http://127.0.0.1:{state.config.port}/", ensure_ascii=True)
    return f"""
<section class="dashboard" data-share-url={html.escape(public_url_json, quote=True)}>
  <div class="hero">
    <div>
      <div class="eyebrow">{html.escape(mode)}</div>
      <h1>Available files</h1>
      <p class="muted">{file_count} file{'s' if file_count != 1 else ''} · {html.escape(str(state.config.root))}</p>
    </div>
    <form method="post" action="/logout"><button class="ghost" type="submit">Lock</button></form>
  </div>

  <div class="toolbar">
    <div class="search-wrap">
      <label class="sr-only" for="search">Search files</label>
      <input id="search" type="search" placeholder="Search files…" autocomplete="off">
    </div>
    <div class="filter-group" role="group" aria-label="File filters">
      <button class="filter active" data-filter="all" type="button">All</button>
      <button class="filter" data-filter="archives" type="button">ZIP</button>
      <button class="filter" data-filter="images" type="button">Images</button>
      <button class="filter" data-filter="documents" type="button">Docs</button>
      <button class="filter" data-filter="other" type="button">Other</button>
    </div>
  </div>

  <div class="meta-strip">
    <span><strong id="fileCount">{file_count}</strong> files</span>
    <span id="shareState">{html.escape(expiry_text)}</span>
    <span id="statsText">0 downloads · 0 B transferred</span>
  </div>

  <div class="actions">
    <button id="downloadAll" type="button" class="primary">Download all</button>
    <button id="copyLink" type="button" class="ghost">Copy link</button>
    <button id="showQr" type="button" class="ghost">QR code</button>
  </div>

  <div id="qrPanel" class="qr-panel" hidden>
    <div>
      <div class="eyebrow">SCAN TO OPEN</div>
      <h2>Share link</h2>
      <p class="muted">The QR code contains only the public URL. The password is never embedded.</p>
    </div>
    <canvas id="qrCanvas" width="220" height="220" aria-label="QR code for the share URL"></canvas>
  </div>

  <div id="downloadProgress" class="progress-card" hidden>
    <div class="progress-head"><strong id="progressName">Downloading</strong><span id="progressValue">0%</span></div>
    <div class="progress-track"><div id="progressBar" class="progress-bar"></div></div>
    <button id="cancelDownload" class="ghost small" type="button">Cancel</button>
  </div>

  <div id="fileList" class="file-list" aria-live="polite"></div>
  <div id="emptyState" class="empty" hidden>No matching files.</div>

  <div class="share-link">
    <span>{public_display}</span>
  </div>
</section>
"""


def main() -> int:
    parser = argparse.ArgumentParser(description="Authenticated temporary file sharing with optional Cloudflare Quick Tunnel.")
    parser.add_argument("directory", help="Directory whose immediate regular files should be shared")
    parser.add_argument("--host", default="127.0.0.1", help="Bind address (default: 127.0.0.1)")
    parser.add_argument("--port", type=int, default=0, help="Port; 0 means auto-select")
    parser.add_argument("--no-tunnel", action="store_true", help="Run only the local web server")
    expiry_group = parser.add_mutually_exclusive_group()
    expiry_group.add_argument("--expires", default="30m", help="Share lifetime, e.g. 30m, 1h, 2d (default: 30m)")
    expiry_group.add_argument("--no-expiry", action="store_true", help="Disable automatic expiration")
    parser.add_argument("--one-time", action="store_true", help="Stop the whole share after the first completed file/bundle download")
    args = parser.parse_args()

    root = Path(args.directory).expanduser()
    if not root.exists() or not root.is_dir():
        fail(f"Directory does not exist: {root}")
    root = root.resolve()
    if root == Path("/"):
        fail("Refusing to share the filesystem root.")

    if not (0 <= args.port <= 65535):
        fail("Port must be between 0 and 65535.")
    if not (1 <= args.port or args.port == 0):
        fail("Invalid port.")

    expires = None if args.no_expiry else parse_duration(args.expires)
    temp_root = Path(tempfile.mkdtemp(prefix="file-share-"))
    temp_root.chmod(0o700)
    config = Config(root=root, host=args.host, port=args.port, no_tunnel=args.no_tunnel, expires=expires, one_time=args.one_time)
    state = State(config, temp_root)

    def stop_on_signal(signum: int, _frame: object) -> None:
        state.stop_reason = "interrupted"
        state.stop_event.set()
        raise KeyboardInterrupt

    signal.signal(signal.SIGINT, stop_on_signal)
    signal.signal(signal.SIGTERM, stop_on_signal)

    try:
        load_template()
        print(f"[INFO] FileShare v{APP_VERSION}")
        print(f"[INFO] Sharing: {root}")
        print(f"[INFO] Files: {len(iter_regular_files(root))}")
        print(f"[INFO] Expiry: {'disabled' if expires is None else args.expires}")
        print(f"[INFO] One-time: {'yes' if args.one_time else 'no'}")

        binary = ""
        if not args.no_tunnel:
            binary = ensure_cloudflared(temp_root)
            print(f"[OK] cloudflared: {binary}")

        server = http.server.ThreadingHTTPServer((config.host, config.port), ShareHandler)
        server.daemon_threads = True
        server.allow_reuse_address = True
        server.share_state = state  # type: ignore[attr-defined]
        state.server = server
        config.port = int(server.server_address[1])
        thread = threading.Thread(target=server.serve_forever, name="http-server", daemon=True)
        state.http_thread = thread
        thread.start()
        print(f"[OK] Local server: http://127.0.0.1:{config.port}/")

        # Prove the origin is reachable before starting the public tunnel.
        with urlopen(f"http://127.0.0.1:{config.port}/", timeout=5) as response:
            if response.status >= 500:
                fail(f"Local HTTP health check failed with status {response.status}.")
        print("[OK] Local HTTP health check passed.")

        if not config.no_tunnel:
            work = temp_root / "cloudflared"
            work.mkdir(mode=0o700)
            state.tunnel_home = work / "home"
            state.tunnel_home.mkdir(mode=0o700)
            (state.tunnel_home / ".cloudflared").mkdir(mode=0o700)
            state.tunnel_log = work / "cloudflared.log"
            env = os.environ.copy()
            env["HOME"] = str(state.tunnel_home)
            env["XDG_CONFIG_HOME"] = str(state.tunnel_home / ".config")
            env["NO_COLOR"] = "1"
            (state.tunnel_home / ".config").mkdir(mode=0o700)
            cmd = [binary, "tunnel", "--no-autoupdate", "--url", f"http://127.0.0.1:{config.port}"]
            log_file = state.tunnel_log.open("w", encoding="utf-8")
            state.tunnel = subprocess.Popen(cmd, stdout=log_file, stderr=subprocess.STDOUT, text=True, env=env)
            deadline = time.time() + 30
            pattern = re.compile(r"https://[a-z0-9-]+\.trycloudflare\.com", re.I)
            while time.time() < deadline:
                if state.tunnel.poll() is not None:
                    break
                text = state.tunnel_log.read_text(encoding="utf-8", errors="replace") if state.tunnel_log.exists() else ""
                found = pattern.search(text)
                if found:
                    state.public_url = found.group(0).rstrip("/")
                    break
                time.sleep(0.25)
            log_file.close()
            if not state.public_url:
                details = state.tunnel_log.read_text(encoding="utf-8", errors="replace") if state.tunnel_log.exists() else ""
                print("[ERROR] Cloudflare Quick Tunnel URL was not detected.")
                if details.strip():
                    print(details[-4000:])
                fail("The public tunnel could not be established.")
            print(f"[OK] Public URL: {state.public_url}/")

            # Best-effort verification of the public endpoint.
            # A VPS/container may have working cloudflared connectivity while
            # its own DNS resolver cannot resolve trycloudflare.com. That is
            # not sufficient evidence to declare the tunnel broken, so DNS
            # failures are reported as UNVERIFIED and the share remains alive.
            request = Request(state.public_url + "/", headers={"User-Agent": "file-share-verifier/3.0.1"})
            try:
                with urlopen(request, timeout=20) as response:
                    status = int(getattr(response, "status", response.getcode()))
                    if status != 200:
                        print(f"[WARN] Public HTTP verification returned HTTP {status}; external access remains UNVERIFIED.")
                    else:
                        print("[OK] Public HTTP health check passed.")
            except HTTPError as exc:
                print(f"[WARN] Public HTTP verification returned HTTP {exc.code}; external access remains UNVERIFIED.")
            except URLError as exc:
                print(f"[WARN] Public endpoint could not be verified from this container: {exc}")
                print("[INFO] The Cloudflare tunnel is still running; test the URL from another device/network if needed.")

        print("\n" + "=" * 72)
        print(f"  TEMPORARY FILE SHARE v{APP_VERSION}")
        print("=" * 72)
        print(f"  Directory : {root}")
        print(f"  Local     : http://127.0.0.1:{config.port}/")
        print("  Password  : " + state.password)
        print("  Lifetime  : " + ("disabled" if expires is None else args.expires))
        print("  One-time  : " + ("YES" if args.one_time else "NO"))
        if state.public_url:
            print("\n  PUBLIC URL:")
            print(f"  {state.public_url}/")
        else:
            print("\n  PUBLIC URL: disabled (--no-tunnel)")
        print("=" * 72)
        print("  STATUS: READY")
        print("  Password + URL are required to access the share.")
        print("  Press Ctrl+C to stop immediately.")
        print("=" * 72 + "\n")

        while not state.stop_event.wait(0.5):
            if state.is_expired():
                state.stop_reason = "expired"
                state.stop_event.set()
                break
            if state.tunnel is not None and state.tunnel.poll() is not None:
                state.stop_reason = "cloudflared exited"
                print("[ERROR] cloudflared exited unexpectedly; public access is no longer available.")
                break

        return 0
    except KeyboardInterrupt:
        print("[INFO] Stopping share...")
        return 0
    except HTTPError as exc:
        fail(f"HTTP verification failed: {exc}")
    except URLError as exc:
        fail(f"Network verification failed: {exc}")
    finally:
        if state.tunnel is not None:
            try:
                state.tunnel.terminate()
                try:
                    state.tunnel.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    state.tunnel.kill()
                    state.tunnel.wait(timeout=2)
            except OSError:
                pass
            state.tunnel = None
        if state.server is not None:
            try:
                state.server.shutdown()
                state.server.server_close()
            except Exception:
                pass
            state.server = None
        shutil.rmtree(temp_root, ignore_errors=True)
        print(f"[OK] Share stopped ({state.stop_reason}); temporary data removed.")


if __name__ == "__main__":
    raise SystemExit(main())
