#!/usr/bin/env python3
"""Lightweight authenticated temporary file-sharing server.

Examples:
    python3 server.py /root/swiftslate-secrets
    python3 server.py /root/backups --expires 1h
    python3 server.py /root/one-file --one-time
    python3 server.py /root/files --expires 30m --one-time --port 8080
    python3 server.py /root/files --no-tunnel
    python3 server.py                         # share the current working directory

The application uses only Python's standard library. A Cloudflare Quick
Tunnel is started automatically unless --no-tunnel is supplied.
"""

from __future__ import annotations

import argparse
import errno
import hashlib
import hmac
import html
import http.server
import ipaddress
import json
import mimetypes
import os
from pathlib import Path
import re
import secrets
import shutil
import signal
import socket
import stat
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

APP_VERSION = "3.6.3"
TEMPLATE_PATH = Path(__file__).resolve().parent / "templates" / "index.html"
QR_SCRIPT_PATH = Path(__file__).resolve().parent / "static" / "qrcode-generator.js"
SESSION_COOKIE = "fs_session"
SESSION_TTL = 12 * 60 * 60
LOGIN_WINDOW = 60
LOGIN_MAX_ATTEMPTS = 5
MAX_NAME_LENGTH = 255
DEFAULT_EXPIRY = 30 * 60
MAX_SHARE_LIFETIME = 7 * 24 * 60 * 60
PROGRESS_LIMIT = 50 * 1024 * 1024
MAX_UPLOAD_SIZE = 1024 * 1024 * 1024
MAX_BUNDLE_SIZE = 2 * 1024 * 1024 * 1024
DISK_SPACE_RESERVE = 16 * 1024 * 1024
UPLOAD_IDLE_TIMEOUT = 60
UPLOAD_TEMP_PREFIX = ".fileshare-upload-"
# Startup sweep only removes upload temp files older than this. A live upload
# writes (refreshing mtime) at least once per idle-timeout window, so a fresh
# file may belong to an in-flight upload.
ORPHAN_TEMP_MAX_AGE = 3600
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
    if "/" in name or "\\" in name or "\x00" in name or any(ord(char) < 32 or ord(char) == 127 for char in name):
        return None
    try:
        if os.name == "nt":
            if any(char in '<>:"|?*' for char in name) or name.endswith((".", " ")):
                return None
            device_name = name.split(".", 1)[0].rstrip(" .").upper()
            reserved_devices = {"CON", "PRN", "AUX", "NUL", "CONIN$", "CONOUT$", "CLOCK$"}
            if device_name in reserved_devices or re.fullmatch(r"(?:COM|LPT)[1-9¹²³]", device_name):
                return None
            encoded_length = len(name.encode("utf-16-le")) // 2
        else:
            encoded_length = len(os.fsencode(name))
        if encoded_length > MAX_NAME_LENGTH:
            return None
    except (UnicodeEncodeError, ValueError):
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


def directory_fd_supported() -> bool:
    return (
        os.name == "posix"
        and hasattr(os, "O_DIRECTORY")
        and all(operation in os.supports_dir_fd for operation in (os.open, os.link, os.unlink, os.stat))
        and os.link in os.supports_follow_symlinks
        and os.scandir in os.supports_fd
    )


def open_directory(root: Path) -> int | None:
    """Pin the shared directory on POSIX so child operations cannot follow a replaced root path."""
    if not directory_fd_supported():
        return None
    flags = os.O_RDONLY | os.O_DIRECTORY
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    return os.open(root, flags)


def iter_regular_files(root: Path, root_fd: int | None = None) -> list[dict[str, object]]:
    result: list[dict[str, object]] = []
    try:
        if root_fd is not None:
            with os.scandir(root_fd) as iterator:
                entries = sorted(iterator, key=lambda entry: entry.name.casefold())
        else:
            entries = sorted(root.iterdir(), key=lambda entry: entry.name.casefold())
    except OSError:
        return result
    for entry in entries:
        name = entry.name
        if name.casefold().startswith(UPLOAD_TEMP_PREFIX.casefold()):
            continue
        try:
            if root_fd is not None:
                if entry.is_symlink() or not entry.is_file(follow_symlinks=False):
                    continue
                file_stat = entry.stat(follow_symlinks=False)
            else:
                if entry.is_symlink() or not entry.is_file():
                    continue
                file_stat = entry.stat()
        except OSError:
            continue
        mime = mimetypes.guess_type(name)[0] or "application/octet-stream"
        result.append(
            {
                "name": name,
                "size": file_stat.st_size,
                "size_human": human_size(file_stat.st_size),
                "mtime": time.strftime("%Y-%m-%d %H:%M", time.localtime(file_stat.st_mtime)),
                "type": file_type(name),
                "category": category_for(name, mime),
            }
        )
    return result


def cleanup_orphaned_uploads(state: State) -> list[str]:
    """Remove upload temp files left behind when a previous run crashed.

    Only files older than ORPHAN_TEMP_MAX_AGE are touched, so an in-flight
    upload from a concurrent run is left alone.
    """
    removed: list[str] = []
    try:
        if state.root_fd is not None:
            with os.scandir(state.root_fd) as iterator:
                entries = list(iterator)
        else:
            entries = list(os.scandir(state.config.root))
    except OSError:
        return removed
    prefix = UPLOAD_TEMP_PREFIX.casefold()
    now = time.time()
    for entry in entries:
        if not entry.name.casefold().startswith(prefix):
            continue
        try:
            if entry.is_symlink() or not entry.is_file(follow_symlinks=False):
                continue
            if now - entry.stat(follow_symlinks=False).st_mtime <= ORPHAN_TEMP_MAX_AGE:
                continue
        except OSError:
            continue
        try:
            if state.root_fd is not None:
                os.unlink(entry.name, dir_fd=state.root_fd)
            else:
                Path(entry.path).unlink()
            removed.append(entry.name)
        except OSError:
            pass
    return removed


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


def verify_public_url(url: str, attempts: int = 3, delay: float = 2.0) -> str:
    """Return 'ok', or a short description of the last failed attempt.

    Retries because the Cloudflare edge can take a moment after tunnel
    creation to serve the new hostname (transient 530 responses).
    """
    result = "unreachable (no attempt made)"
    for attempt in range(attempts):
        request = Request(url + "/", headers={"User-Agent": f"file-share-verifier/{APP_VERSION}"})
        try:
            with urlopen(request, timeout=20) as response:
                status = int(getattr(response, "status", response.getcode()))
                if status == 200:
                    return "ok"
                result = f"HTTP {status}"
        except HTTPError as exc:
            result = f"HTTP {exc.code}"
        except URLError as exc:
            result = f"unreachable ({exc.reason})"
        except OSError as exc:
            result = f"unreachable ({exc})"
        if attempt < attempts - 1:
            time.sleep(delay)
    return result


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
    def __init__(self, root: Path, host: str, port: int, no_tunnel: bool, expires: int | None, one_time: bool, extra_origins: frozenset[str] = frozenset()):
        self.root = root
        self.host = host
        self.port = port
        self.no_tunnel = no_tunnel
        self.expires = expires
        self.one_time = one_time
        self.extra_origins = frozenset(normalize_allowed_origin(value) for value in extra_origins)


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
        self.root_fd: int | None = None
        self.root_identity: tuple[int, int] | None = None
        self.disk_work_semaphore = threading.BoundedSemaphore(1)
        self.server: http.server.ThreadingHTTPServer | None = None
        self.tunnel: subprocess.Popen[str] | None = None
        self.tunnel_home: Path | None = None
        self.tunnel_log: Path | None = None
        self.public_url: str | None = None
        self.stop_event = threading.Event()
        self.stop_reason = "stopped"

    def open_root(self) -> None:
        if self.root_fd is not None or self.root_identity is not None:
            return
        self.root_fd = open_directory(self.config.root)
        if self.root_fd is None:
            root_stat = os.stat(self.config.root, follow_symlinks=False)
            if not stat.S_ISDIR(root_stat.st_mode):
                raise OSError("shared path is not a directory")
            self.root_identity = (root_stat.st_dev, root_stat.st_ino)

    def root_path_is_same(self) -> bool:
        if self.root_fd is not None:
            return True
        if self.root_identity is None:
            return False
        try:
            current = os.stat(self.config.root, follow_symlinks=False)
        except OSError:
            return False
        return stat.S_ISDIR(current.st_mode) and (current.st_dev, current.st_ino) == self.root_identity

    def files(self) -> list[dict[str, object]]:
        if not self.root_path_is_same():
            return []
        return iter_regular_files(self.config.root, self.root_fd)

    def close_root(self) -> None:
        if self.root_fd is not None:
            try:
                os.close(self.root_fd)
            except OSError:
                pass
            self.root_fd = None

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
        peer = handler.client_address[0]
        # Cloudflare's Quick Tunnel connects to the origin from loopback and
        # supplies CF-Connecting-IP for the real public client. Trust proxy
        # headers only from a loopback peer; a directly connected client must
        # not be able to pick its own rate-limit bucket.
        if is_loopback_host(peer):
            forwarded = (
                handler.headers.get("CF-Connecting-IP")
                or handler.headers.get("X-Forwarded-For", "").split(",")[0].strip()
            )
            if forwarded:
                return forwarded
        return peer

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

    def cookie_suffix(self, handler: http.server.BaseHTTPRequestHandler) -> str:
        # The origin always speaks plain HTTP (Cloudflare terminates TLS for
        # the public URL), so the Secure attribute is attached only when the
        # request arrived at the public URL's host — where the browser's
        # connection is HTTPS. Browsers reject Secure cookies set over plain
        # HTTP on non-loopback hosts, which would break documented direct
        # access (loopback or a wildcard --host IP).
        secure = ""
        if self.public_url:
            public_host = urlparse(self.public_url).hostname or ""
            host_header = (handler.headers.get("Host") or "").strip()
            request_host = urlparse(f"http://{host_header}").hostname or ""
            if public_host and request_host == public_host:
                secure = "; Secure"
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
        files = self.files()
        with self.lock:
            stats_snapshot = {name: values.copy() for name, values in self.stats.items()}
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
                "stats": stats_snapshot,
            }


class BundleTooLargeError(Exception):
    pass


class ShareHandler(http.server.BaseHTTPRequestHandler):
    server_version = f"FileShare/{APP_VERSION}"
    # Close idle connections after this many seconds so a stalled client
    # cannot pin a handler thread (and, through the tunnel, a Cloudflare slot).
    timeout = 60

    @property
    def state(self) -> State:
        return self.server.share_state  # type: ignore[attr-defined]

    def log_message(self, fmt: str, *args: object) -> None:
        print(f"[HTTP] {self.client_address[0]} - {fmt % args}")

    def nonce(self) -> str:
        return secrets.token_urlsafe(18)

    def send_security_headers(self, *, nonce: str | None = None) -> None:
        script_policy = f"'nonce-{nonce}' 'self'" if nonce else "'none'"
        # Explicitly trusted origins (trusted reverse proxy / preview
        # environment) may frame the app; when set, CSP frame-ancestors
        # replaces the X-Frame-Options DENY header.
        extra_origins = self.state.config.extra_origins
        frame_ancestors = "'none'" if not extra_origins else " ".join(["'self'"] + sorted(extra_origins))
        csp = (
            "default-src 'self'; "
            f"script-src {script_policy}; "
            "style-src 'self' 'unsafe-inline'; "
            "img-src 'self' data:; "
            "connect-src 'self'; "
            "font-src 'self'; "
            "form-action 'self'; "
            f"frame-ancestors {frame_ancestors}; base-uri 'none'; object-src 'none'"
        )
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Referrer-Policy", "same-origin")
        if not extra_origins:
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
            "local_url": format_http_origin(origin_host_for_bind(self.state.config.host), self.state.config.port) + "/",
            "one_time": self.state.config.one_time,
            "expires_at": self.state.expires_at,
            "progress_limit": PROGRESS_LIMIT,
            "max_upload_size": MAX_UPLOAD_SIZE,
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

    def send_qr_asset(self) -> None:
        try:
            payload = QR_SCRIPT_PATH.read_bytes()
        except OSError:
            self.send_error(404, "Asset not found")
            return
        self.send_response(200)
        self.send_header("Content-Type", "application/javascript; charset=utf-8")
        self.send_header("Content-Length", str(len(payload)))
        self.send_header("Cache-Control", "no-store, max-age=0")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.end_headers()
        self.wfile.write(payload)

    def request_origin_is_valid(self) -> bool:
        raw_origin = self.headers.get("Origin", "")
        if not raw_origin:
            return False
        try:
            parsed = urlparse(raw_origin)
        except ValueError:
            return False
        if parsed.scheme.lower() not in {"http", "https"} or not parsed.netloc:
            return False
        if parsed.path not in {"", "/"} or parsed.query or parsed.fragment or "?" in raw_origin or "#" in raw_origin:
            return False
        origin = f"{parsed.scheme.lower()}://{parsed.netloc.lower()}"
        allowed: set[str] = set()
        allowed.update(self.state.config.extra_origins)
        if self.state.public_url:
            allowed.add(self.state.public_url.rstrip("/").lower())
        port = self.state.config.port
        try:
            local_host = str(self.connection.getsockname()[0])
        except (OSError, IndexError, TypeError):
            local_host = ""
        if local_host:
            allowed.add(format_http_origin(local_host, port).lower())
            if is_loopback_host(local_host):
                allowed.update(
                    {
                        format_http_origin("localhost", port).lower(),
                        format_http_origin("127.0.0.1", port).lower(),
                        format_http_origin("::1", port).lower(),
                    }
                )
        configured_host = self.state.config.host.strip()
        if configured_host.lower() not in {"0.0.0.0", "::"}:
            allowed.add(format_http_origin(configured_host, port).lower())
        return origin in allowed

    def require_same_origin(self) -> bool:
        raw_origin = self.headers.get("Origin", "")
        if raw_origin:
            # Browser form posts always carry Origin. An invalid one — an
            # attacker page, or the literal string "null" from an opaque
            # origin such as a sandboxed iframe — is rejected outright.
            if self.request_origin_is_valid():
                return True
            self._reject_same_origin()
            return False
        # No Origin: some browsers omit it on top-level form navigations and
        # privacy tooling may strip it. Sec-Fetch-Site is browser-attested and
        # cannot be set by web content. "same-origin" is a direct match;
        # "none" is what a browser reports for our own document's form post
        # when the document's referrer policy strips the referrer used to
        # compute the site. A cross-site browser request always carries a
        # real (invalid) Origin and is already rejected above.
        fetch_site = self.headers.get("Sec-Fetch-Site", "").strip().lower()
        if fetch_site in {"same-origin", "none"}:
            return True
        if fetch_site:
            self._reject_same_origin()
            return False
        # A request with no Origin and no fetch metadata is not a browser
        # submission; a raw client has no browser victim to protect, so a
        # direct local peer serving one of our own hosts is accepted.
        if self._direct_local_peer():
            return True
        self._reject_same_origin()
        return False

    def _reject_same_origin(self) -> None:
        """Log the failure and report exactly which headers were seen."""
        origin = self.headers.get("Origin", "") or "missing"
        fetch_site = self.headers.get("Sec-Fetch-Site", "") or "missing"
        host = self.headers.get("Host", "") or "missing"
        try:
            peer = self.client_address[0]
        except (IndexError, TypeError, OSError):
            peer = "unknown"
        detail = f"origin={origin}; sec-fetch-site={fetch_site}; host={host}; peer={peer}"
        self.log_error("same-origin check failed: %s", detail)
        self.send_json({"error": "same-origin request required", "detail": detail}, status=403)

    def _direct_local_peer(self) -> bool:
        """True for a direct loopback peer whose Host header is one we serve."""
        try:
            peer = self.client_address[0]
        except (IndexError, TypeError, OSError):
            return False
        if not is_loopback_host(peer):
            return False
        host_header = (self.headers.get("Host") or "").strip()
        host = urlparse(f"http://{host_header}").hostname or "" if host_header else ""
        if not host:
            return False
        trusted = set()
        if self.state.public_url:
            public_host = urlparse(self.state.public_url).hostname
            if public_host:
                trusted.add(public_host)
        local_host = origin_host_for_bind(self.state.config.host)
        trusted.add(local_host)
        if is_loopback_host(local_host):
            trusted.update({"localhost", "127.0.0.1", "::1"})
        configured_host = self.state.config.host.strip().lower()
        if configured_host not in {"0.0.0.0", "::"}:
            trusted.add(configured_host)
        return host in trusted

    def require_same_origin_fetch(self) -> bool:
        fetch_site = self.headers.get("Sec-Fetch-Site")
        if not fetch_site or fetch_site.lower() in {"same-origin", "none"}:
            return True
        self.send_html(b"<h1>Same-origin request required</h1>", status=403)
        return False

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

        if path == "/assets/qrcode-generator.js":
            self.send_qr_asset()
            return

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
            self.send_json({"files": self.state.files()})
            return

        if path.startswith("/download/"):
            if not self.state.is_authenticated(self):
                self.send_html(b"<h1>Authentication required</h1>", status=401)
                return
            if not self.require_same_origin_fetch():
                return
            name = unquote(path[len("/download/"):])
            self.handle_file_download(name)
            return

        if path == "/download-all":
            if not self.state.is_authenticated(self):
                self.send_html(b"<h1>Authentication required</h1>", status=401)
                return
            if not self.require_same_origin_fetch():
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
        source = self.open_shared_file(name)
        if source is None:
            self.send_error(404, "File not found")
            return
        try:
            size = os.fstat(source.fileno()).st_size
        except OSError:
            source.close()
            self.send_error(404, "File not found")
            return
        source.close()
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
            if not self.require_same_origin():
                return
            self.handle_login()
            return
        if parsed.path == "/logout":
            if not self.state.is_authenticated(self):
                self.send_response(303)
                self.send_header("Location", "/")
                self.end_headers()
                return
            if not self.require_same_origin():
                return
            self.state.revoke_session(self)
            self.send_response(303)
            self.send_header("Location", "/")
            self.send_header("Set-Cookie", f"{SESSION_COOKIE}=deleted; Max-Age=0{self.state.cookie_suffix(self)}")
            self.end_headers()
            return
        if parsed.path == "/stop-share":
            if not self.state.is_authenticated(self):
                self.send_json({"error": "authentication required"}, status=401)
                return
            if not self.require_same_origin():
                return
            self.state.stop_reason = "stopped from dashboard"
            self.state.stop_event.set()
            self.send_response(204)
            self.send_header("Cache-Control", "no-store, max-age=0")
            self.send_security_headers()
            self.end_headers()
            return
        self.send_error(404, "Not found")

    def do_PUT(self) -> None:
        if self.reject_expired():
            return
        path = urlparse(self.path).path
        if not path.startswith("/upload/"):
            self.send_error(404, "Not found")
            return
        if not self.state.is_authenticated(self):
            self.send_json({"error": "authentication required"}, status=401)
            return
        if not self.require_same_origin():
            return
        name = unquote(path[len("/upload/"):])
        self.handle_upload(name)

    def upload_temp_file(self) -> tuple[str, object]:
        if not self.state.root_path_is_same():
            raise OSError("shared directory path changed")
        flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
        if hasattr(os, "O_NOFOLLOW"):
            flags |= os.O_NOFOLLOW
        if hasattr(os, "O_BINARY"):
            flags |= os.O_BINARY
        for _ in range(5):
            temp_name = f"{UPLOAD_TEMP_PREFIX}{secrets.token_hex(16)}.tmp"
            try:
                if self.state.root_fd is not None:
                    fd = os.open(temp_name, flags, 0o600, dir_fd=self.state.root_fd)
                else:
                    fd = os.open(self.state.config.root / temp_name, flags, 0o600)
                return temp_name, os.fdopen(fd, "wb", buffering=1024 * 1024)
            except FileExistsError:
                continue
        raise FileExistsError("could not allocate a unique upload temporary file")

    def remove_upload_temp(self, temp_name: str) -> None:
        if self.state.root_fd is None and not self.state.root_path_is_same():
            return
        try:
            if self.state.root_fd is not None:
                os.unlink(temp_name, dir_fd=self.state.root_fd)
            else:
                (self.state.config.root / temp_name).unlink()
        except FileNotFoundError:
            pass
        except OSError:
            pass

    def upload_target_exists(self, name: str) -> bool:
        if not self.state.root_path_is_same():
            raise OSError("shared directory path changed")
        try:
            if self.state.root_fd is not None:
                os.stat(name, dir_fd=self.state.root_fd, follow_symlinks=False)
            else:
                os.lstat(self.state.config.root / name)
            return True
        except FileNotFoundError:
            return False

    def publish_upload(self, temp_name: str, name: str) -> None:
        if not self.state.root_path_is_same():
            raise OSError("shared directory path changed")
        if self.state.root_fd is not None:
            os.link(
                temp_name,
                name,
                src_dir_fd=self.state.root_fd,
                dst_dir_fd=self.state.root_fd,
                follow_symlinks=False,
            )
            self.remove_upload_temp(temp_name)
            try:
                os.fsync(self.state.root_fd)
            except OSError:
                pass
            return
        source = self.state.config.root / temp_name
        destination = self.state.config.root / name
        if os.name == "nt":
            os.rename(source, destination)
            return
        if os.link in os.supports_follow_symlinks:
            os.link(source, destination, follow_symlinks=False)
        else:
            os.link(source, destination)
        self.remove_upload_temp(temp_name)

    def available_root_space(self) -> int | None:
        try:
            if self.state.root_fd is not None and hasattr(os, "fstatvfs"):
                filesystem = os.fstatvfs(self.state.root_fd)
                return filesystem.f_bavail * filesystem.f_frsize
            return shutil.disk_usage(self.state.config.root).free
        except OSError:
            return None

    def handle_upload(self, name: str) -> None:
        if safe_filename(name) is None or name.casefold().startswith(UPLOAD_TEMP_PREFIX.casefold()):
            self.send_json({"error": "invalid file name"}, status=400)
            return
        if self.headers.get("Transfer-Encoding"):
            self.send_json({"error": "chunked uploads are not supported"}, status=400)
            return
        lengths = self.headers.get_all("Content-Length", [])
        if not lengths:
            self.send_json({"error": "Content-Length is required"}, status=411)
            return
        if len(lengths) != 1:
            self.send_json({"error": "a single Content-Length header is required"}, status=400)
            return
        try:
            content_length = int(lengths[0])
        except ValueError:
            self.send_json({"error": "invalid Content-Length"}, status=400)
            return
        if content_length < 0:
            self.send_json({"error": "invalid Content-Length"}, status=400)
            return
        if content_length > MAX_UPLOAD_SIZE:
            self.send_json({"error": f"file exceeds the {human_size(MAX_UPLOAD_SIZE)} upload limit"}, status=413)
            return
        content_type = self.headers.get("Content-Type", "").split(";", 1)[0].strip().lower()
        if content_type != "application/octet-stream":
            self.send_json({"error": "Content-Type must be application/octet-stream"}, status=415)
            return
        if self.headers.get("Content-Encoding", "identity").lower() not in {"", "identity"}:
            self.send_json({"error": "encoded request bodies are not supported"}, status=415)
            return
        if not self.state.disk_work_semaphore.acquire(blocking=False):
            self.send_json({"error": "another upload or archive is using temporary storage; retry shortly"}, status=503)
            return

        temp_name: str | None = None
        original_timeout = self.connection.gettimeout()
        try:
            if self.upload_target_exists(name):
                self.send_json({"error": "a file with that name already exists; rename it before uploading"}, status=409)
                return
            free_space = self.available_root_space()
            if free_space is not None and content_length and free_space < content_length + DISK_SPACE_RESERVE:
                self.send_json({"error": "not enough free space for this upload"}, status=507)
                return

            temp_name, destination = self.upload_temp_file()
            self.connection.settimeout(UPLOAD_IDLE_TIMEOUT)
            remaining = content_length
            with destination:
                while remaining:
                    chunk = self.rfile.read(min(1024 * 1024, remaining))
                    if not chunk:
                        raise EOFError("upload ended before Content-Length bytes were received")
                    destination.write(chunk)
                    remaining -= len(chunk)
                destination.flush()
                os.fsync(destination.fileno())
            self.publish_upload(temp_name, name)
            temp_name = None
            self.send_json({"name": name, "size": content_length}, status=201)
        except FileExistsError:
            self.send_json({"error": "a file with that name already exists; rename it before uploading"}, status=409)
        except EOFError:
            self.send_json({"error": "upload ended before the full file was received"}, status=400)
        except socket.timeout:
            self.send_json({"error": "upload timed out while waiting for data"}, status=408)
        except OSError as exc:
            if exc.errno == errno.ENOSPC:
                status = 507
                message = "not enough free space to store the upload"
            else:
                status = 500
                message = "unable to store the uploaded file"
            self.send_json({"error": message}, status=status)
        finally:
            try:
                self.connection.settimeout(original_timeout)
            except OSError:
                pass
            if temp_name is not None:
                self.remove_upload_temp(temp_name)
            self.state.disk_work_semaphore.release()

    def handle_login(self) -> None:
        client = self.state.client_id(self)
        allowed, retry_after = self.state.allow_login_attempt(client)
        if not allowed:
            self.render_page(
                '<section class="auth-card"><div class="eyebrow">Try again later</div><h1>Too many attempts</h1><p class="muted">Try again in about one minute.</p></section>',
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
            self.render_page('<section class="auth-card"><div class="eyebrow">Password not accepted</div><h1>Access denied</h1><p class="muted">The password is incorrect.</p><a class="back" href="/">Try again</a></section>', status=401, title="Access denied · File Share")
            return

        self.state.login_success(client)
        token = self.state.create_session()
        self.send_response(303)
        self.send_header("Location", "/")
        self.send_header("Set-Cookie", f"{SESSION_COOKIE}={token}; Max-Age={SESSION_TTL}{self.state.cookie_suffix(self)}")
        self.end_headers()

    @staticmethod
    def content_disposition(name: str) -> str:
        clean = name.replace("\r", "").replace("\n", "")
        ascii_name = clean.encode("ascii", "replace").decode("ascii").replace('"', "") or "download"
        return f'attachment; filename="{ascii_name}"; filename*=UTF-8\'\'{quote(clean, safe="")}'

    def open_shared_file(self, name: str):
        if safe_filename(name) is None or name.casefold().startswith(UPLOAD_TEMP_PREFIX.casefold()) or not self.state.root_path_is_same():
            return None
        flags = os.O_RDONLY
        if hasattr(os, "O_NOFOLLOW"):
            flags |= os.O_NOFOLLOW
        if hasattr(os, "O_BINARY"):
            flags |= os.O_BINARY
        try:
            if self.state.root_fd is not None:
                fd = os.open(name, flags, dir_fd=self.state.root_fd)
            else:
                target = safe_child(self.state.config.root, name)
                if target is None:
                    return None
                fd = os.open(target, flags)
            if not stat.S_ISREG(os.fstat(fd).st_mode) or not self.state.root_path_is_same():
                os.close(fd)
                return None
            return os.fdopen(fd, "rb", buffering=1024 * 1024)
        except (OSError, ValueError):
            return None

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
        source = self.open_shared_file(name)
        if source is None:
            self.send_error(404, "File not found")
            return
        try:
            file_stat = os.fstat(source.fileno())
            size = file_stat.st_size
        except (OSError, ValueError):
            source.close()
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
            complete = sent == length and start == 0 and (size == 0 or end == size - 1)
        except (BrokenPipeError, ConnectionResetError):
            complete = False
        except OSError:
            complete = False
        finally:
            source.close()
            self.state.record_finish(name, sent, complete)

    def handle_bundle_download(self) -> None:
        if not self.state.disk_work_semaphore.acquire(blocking=False):
            self.send_json({"error": "another upload or archive is using temporary storage; retry shortly"}, status=503)
            return

        bundle: Path | None = None
        try:
            files = self.state.files()
            if not files:
                self.send_error(404, "No files to bundle")
                return

            expected_size = sum(int(item["size"]) for item in files)
            if expected_size > MAX_BUNDLE_SIZE:
                self.send_json({"error": f"shared files exceed the {human_size(MAX_BUNDLE_SIZE)} Download all limit"}, status=413)
                return
            metadata_estimate = sum(256 + len(str(item["name"]).encode("utf-8", "surrogatepass")) for item in files)
            required_space = expected_size + metadata_estimate + DISK_SPACE_RESERVE
            try:
                free_space = shutil.disk_usage(self.state.temp_root).free
            except OSError:
                free_space = None
            if free_space is not None and free_space < required_space:
                self.send_json({"error": "not enough free temporary disk space to build the archive"}, status=507)
                return

            bundle = self.state.temp_root / f"files-{secrets.token_hex(8)}.zip"
            copied = 0
            try:
                with zipfile.ZipFile(bundle, "w", compression=zipfile.ZIP_STORED, allowZip64=True) as archive:
                    for item in files:
                        name = str(item["name"])
                        source = self.open_shared_file(name)
                        if source is None:
                            continue
                        with source:
                            file_stat = os.fstat(source.fileno())
                            if copied + file_stat.st_size > MAX_BUNDLE_SIZE:
                                raise BundleTooLargeError
                            info = zipfile.ZipInfo(name)
                            try:
                                file_time = time.localtime(file_stat.st_mtime)
                                info.date_time = (
                                    file_time[:6]
                                    if 1980 <= file_time.tm_year <= 2107
                                    else (1980, 1, 1, 0, 0, 0)
                                )
                            except (OverflowError, ValueError):
                                info.date_time = (1980, 1, 1, 0, 0, 0)
                            info.compress_type = zipfile.ZIP_STORED
                            with archive.open(info, "w") as destination:
                                while True:
                                    chunk = source.read(1024 * 1024)
                                    if not chunk:
                                        break
                                    if copied + len(chunk) > MAX_BUNDLE_SIZE:
                                        raise BundleTooLargeError
                                    destination.write(chunk)
                                    copied += len(chunk)
                size = bundle.stat().st_size
            except BundleTooLargeError:
                self.send_json({"error": f"shared files exceed the {human_size(MAX_BUNDLE_SIZE)} Download all limit"}, status=413)
                return
            except (OSError, ValueError, OverflowError, zipfile.BadZipFile, zipfile.LargeZipFile):
                self.send_json({"error": "unable to create the archive; check available temporary disk space"}, status=500)
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
        finally:
            if bundle is not None:
                try:
                    bundle.unlink()
                except OSError:
                    pass
            self.state.disk_work_semaphore.release()


def login_html() -> str:
    return """
<section class="auth-card">
  <div class="eyebrow">Temporary share</div>
  <h1>Private file access</h1>
  <p class="muted">Enter the temporary password shown in the server logs.</p>
  <form method="post" action="/login" class="auth-form">
    <label for="password">Password</label>
    <input id="password" name="password" type="password" autocomplete="current-password" required>
    <button type="submit">Unlock files</button>
  </form>
</section>
"""


def dashboard_html(state: State) -> str:
    public_url = state.public_url or ""
    local_url = format_http_origin(origin_host_for_bind(state.config.host), state.config.port) + "/"
    public_display = html.escape(public_url or local_url)
    remaining = state.remaining_seconds()
    file_count = len(state.files())
    mode = "One-time download" if state.config.one_time else "Temporary access"
    if remaining is None:
        expiry_text = "Closes after first completed download" if state.config.one_time else "No automatic expiry"
    elif remaining >= 3600:
        expiry_text = f"Expires in {remaining // 3600}h {(remaining % 3600) // 60}m"
    elif remaining >= 60:
        expiry_text = f"Expires in {remaining // 60}m {remaining % 60:02d}s"
    else:
        expiry_text = f"Expires in {remaining}s"
    public_url_json = json.dumps(public_url or local_url, ensure_ascii=True)
    return f"""
<section class="dashboard" data-share-url={html.escape(public_url_json, quote=True)}>
  <div class="hero fs-hero">
    <div class="fs-hero-copy">
      <div class="eyebrow">{html.escape(mode)}</div>
      <div class="fs-title-row">
        <h1>Available files</h1>
        <span class="fs-online"><span class="status-dot" aria-hidden="true"></span> Share active</span>
      </div>
      <p class="muted">{file_count} file{'s' if file_count != 1 else ''} in {html.escape(str(state.config.root))}</p>
    </div>
    <div class="fs-header-actions">
      <form method="post" action="/logout"><button class="ghost fs-lock-btn" type="submit">Lock</button></form>
      <button id="stopShare" class="button fs-stop-btn" type="button" aria-label="Stop sharing">
        <span class="fs-stop-icon" aria-hidden="true">×</span>
        <span>Stop share</span>
      </button>
    </div>
  </div>

  <div class="fs-share-card">
    <div class="fs-share-copy">
      <div class="eyebrow">Share URL</div>
      <div class="fs-share-url" title="{public_display}">{public_display}</div>
      <div class="fs-share-meta">
        <span id="shareState">{html.escape(expiry_text)}</span>
        <span id="statsText">0 downloads, 0 B transferred</span>
      </div>
    </div>
    <div class="fs-share-actions">
      <button id="copyLink" type="button" class="ghost fs-action-btn">Copy link</button>
      <button id="showQr" type="button" class="ghost fs-action-btn" aria-controls="qrPanel" aria-expanded="false">QR code</button>
    </div>
  </div>

  <div id="qrPanel" class="qr-panel" hidden role="region" aria-labelledby="qrTitle">
    <div>
      <div class="eyebrow">Scan to open</div>
      <h2 id="qrTitle">Share link</h2>
      <p id="qrStatus" class="muted" role="status" aria-live="polite">The QR code contains only the public URL. The password is never embedded.</p>
    </div>
    <canvas id="qrCanvas" width="220" height="220" role="img" aria-label="QR code for the share URL">QR code for the share URL</canvas>
  </div>

  <div class="toolbar">
    <div class="search-wrap">
      <label class="sr-only" for="search">Search files</label>
      <input id="search" type="search" placeholder="Search files…" autocomplete="off">
    </div>
    <div class="filter-group" role="group" aria-label="File filters">
      <button class="filter active" data-filter="all" type="button" aria-pressed="true">All</button>
      <button class="filter" data-filter="archives" type="button" aria-pressed="false">ZIP</button>
      <button class="filter" data-filter="images" type="button" aria-pressed="false">Images</button>
      <button class="filter" data-filter="documents" type="button" aria-pressed="false">Docs</button>
      <button class="filter" data-filter="other" type="button" aria-pressed="false">Other</button>
    </div>
  </div>

  <div class="fs-library-head">
    <div>
      <div class="eyebrow">Files</div>
      <div class="fs-library-title"><strong id="fileCount" aria-live="polite">{file_count}</strong> <span id="fileCountLabel">{'file' if file_count == 1 else 'files'}</span></div>
    </div>
    <div class="fs-library-actions">
      <input id="uploadInput" type="file" hidden>
      <button id="uploadFile" type="button" class="ghost fs-action-btn" aria-controls="uploadProgress">Upload file</button>
      <button id="refreshFiles" type="button" class="fs-refresh-btn" aria-label="Refresh files">
        <svg viewBox="0 0 24 24" aria-hidden="true">
          <path d="M20 11a8 8 0 0 0-14.9-3M4 5v4h4M4 13a8 8 0 0 0 14.9 3M20 19v-4h-4" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"/>
        </svg>
        <span>Refresh</span>
      </button>
      <button id="downloadAll" type="button" class="fs-download-all">Download all</button>
    </div>
  </div>
  <p class="upload-note">Anyone with the share password can upload. Files are saved in this directory, existing names are never overwritten, and uploads are limited to {human_size(MAX_UPLOAD_SIZE)} each.</p>
  <p id="bundleStatus" class="upload-note" role="status" aria-live="polite" hidden></p>

  <div id="downloadProgress" class="progress-card" hidden role="region" aria-label="Download progress">
    <div class="progress-head"><strong id="progressName">Downloading</strong><span id="progressValue">0%</span></div>
    <div class="progress-track" role="progressbar" aria-label="Download progress" aria-valuemin="0" aria-valuemax="100" aria-valuenow="0"><div id="progressBar" class="progress-bar"></div></div>
    <div class="fs-transfer-status">
      <div class="fs-transfer-copy"><strong id="progressStatus" role="status" aria-live="polite">Starting download…</strong><span id="progressMeta">Preparing transfer</span></div>
      <div class="fs-transfer-actions">
        <button id="transferAction" class="fs-transfer-btn is-active" type="button" disabled aria-live="polite">
          <span class="fs-svg-wrapper" aria-hidden="true"><svg viewBox="0 0 24 24"><path d="M12 3v10m0 0 4-4m-4 4-4-4M5 17v2a2 2 0 0 0 2 2h10a2 2 0 0 0 2-2v-2" stroke="currentColor" stroke-width="2" fill="none" stroke-linecap="round" stroke-linejoin="round"/></svg></span>
          <span>Downloading</span>
        </button>
        <label class="fs-checkbox" id="downloadComplete" hidden>
          <input id="downloadDone" type="checkbox" disabled>
          <span class="checkmark">
            <svg viewBox="0 0 32 32" fill="none" aria-hidden="true">
              <rect x="4" y="4" width="24" height="24" rx="6" stroke="currentColor" stroke-width="2"/>
              <polyline points="9,17 14,22 23,11" stroke="currentColor" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round"/>
            </svg>
            <span>Downloaded</span>
          </span>
        </label>
        <button id="cancelDownload" class="ghost small" type="button">Cancel</button>
      </div>
    </div>
  </div>

  <div id="uploadProgress" class="progress-card" hidden role="region" aria-label="Upload progress">
    <div class="progress-head"><strong id="uploadName">Uploading</strong><span id="uploadPercent">0%</span></div>
    <div class="progress-track" role="progressbar" aria-label="Upload progress" aria-valuemin="0" aria-valuemax="100" aria-valuenow="0"><div id="uploadBar" class="progress-bar"></div></div>
    <div class="fs-transfer-status">
      <div class="fs-transfer-copy"><strong id="uploadStatus" role="status" aria-live="polite">Choose a file to upload</strong><span id="uploadMeta">Maximum size: {human_size(MAX_UPLOAD_SIZE)}</span></div>
      <div class="fs-transfer-actions"><button id="cancelUpload" class="ghost small" type="button">Cancel</button></div>
    </div>
  </div>

  <div id="fileLoading" class="fs-loading" aria-live="polite">
    <span class="fs-spinner" aria-hidden="true"></span>
    <span id="fileLoadingText">Loading files…</span>
  </div>

  <div id="fileList" class="file-list" role="list" aria-busy="true">
    <div class="file-skeleton" aria-hidden="true">
      <div class="file-skeleton-icon"></div>
      <div class="file-skeleton-main"><div class="file-skeleton-line wide"></div><div class="file-skeleton-line medium"></div></div>
      <div class="file-skeleton-dot"></div>
    </div>
    <div class="file-skeleton" aria-hidden="true">
      <div class="file-skeleton-icon"></div>
      <div class="file-skeleton-main"><div class="file-skeleton-line wide"></div><div class="file-skeleton-line short"></div></div>
      <div class="file-skeleton-dot"></div>
    </div>
    <div class="file-skeleton" aria-hidden="true">
      <div class="file-skeleton-icon"></div>
      <div class="file-skeleton-main"><div class="file-skeleton-line medium"></div><div class="file-skeleton-line short"></div></div>
      <div class="file-skeleton-dot"></div>
    </div>
  </div>
  <div id="emptyState" class="empty" role="status" aria-live="polite" hidden>No files are available in this share yet.</div>
</section>
"""


def is_loopback_host(host: str) -> bool:
    if host.strip().lower().rstrip(".") == "localhost":
        return True
    try:
        return ipaddress.ip_address(host.split("%", 1)[0]).is_loopback
    except ValueError:
        return False


def format_http_origin(host: str, port: int) -> str:
    normalized = host.strip().lower()
    if normalized.startswith("[") and normalized.endswith("]"):
        normalized = normalized[1:-1]
    if ":" in normalized:
        normalized = f"[{normalized.replace('%', '%25')}]"
    port_suffix = "" if port == 80 else f":{port}"
    return f"http://{normalized}{port_suffix}"


def origin_host_for_bind(host: str) -> str:
    normalized = host.strip().lower()
    if normalized in {"", "0.0.0.0"}:
        return "127.0.0.1"
    if normalized == "::":
        return "::1"
    if normalized.startswith("[") and normalized.endswith("]"):
        return normalized[1:-1]
    return host.strip()


def normalize_allowed_origin(value: str) -> str:
    parsed = urlparse(value.strip())
    if parsed.scheme.lower() not in {"http", "https"} or not parsed.netloc:
        fail(f"Invalid --allow-origin (expected http(s)://host[:port]): {value}")
    if parsed.path not in {"", "/"} or parsed.query or parsed.fragment:
        fail(f"Invalid --allow-origin (no path, query, or fragment allowed): {value}")
    return f"{parsed.scheme.lower()}://{parsed.netloc.lower()}"


def main() -> int:
    parser = argparse.ArgumentParser(description="Authenticated temporary file sharing with optional Cloudflare Quick Tunnel.")
    parser.add_argument("--version", action="version", version=f"FileShare {APP_VERSION}")
    parser.add_argument("directory", nargs="?", default=".", help="Directory to share (default: current working directory)")
    parser.add_argument("--host", default="127.0.0.1", help="Bind address (default: 127.0.0.1)")
    parser.add_argument("--port", type=int, default=0, help="Port; 0 means auto-select")
    parser.add_argument("--no-tunnel", action="store_true", help="Run only the local web server")
    expiry_group = parser.add_mutually_exclusive_group()
    expiry_group.add_argument("--expires", default="30m", help="Share lifetime, e.g. 30m, 1h, 2d (default: 30m)")
    expiry_group.add_argument("--no-expiry", action="store_true", help="Disable automatic expiration")
    parser.add_argument("--one-time", action="store_true", help="Stop the whole share after the first completed file/bundle download")
    parser.add_argument(
        "--allow-origin",
        action="append",
        default=[],
        metavar="ORIGIN",
        help="Additional trusted Origin (http(s)://host[:port]) accepted by the same-origin "
             "checks and allowed to frame the app. Use for a trusted reverse proxy or preview "
             "environment that changes the hostname. May be repeated. Default: none.",
    )
    args = parser.parse_args()

    root = Path(args.directory).expanduser()
    if not root.exists() or not root.is_dir():
        fail(f"Directory does not exist: {root}")
    root = root.resolve()
    if root.parent == root:
        fail("Refusing to share the filesystem root.")

    if not (0 <= args.port <= 65535):
        fail("Port must be between 0 and 65535.")
    if not (1 <= args.port or args.port == 0):
        fail("Invalid port.")

    expires = None if args.no_expiry else parse_duration(args.expires)
    extra_origins = frozenset(normalize_allowed_origin(value) for value in args.allow_origin)
    temp_root = Path(tempfile.mkdtemp(prefix="file-share-"))
    temp_root.chmod(0o700)
    config = Config(root=root, host=args.host, port=args.port, no_tunnel=args.no_tunnel, expires=expires, one_time=args.one_time, extra_origins=extra_origins)
    state = State(config, temp_root)

    def stop_on_signal(signum: int, _frame: object) -> None:
        state.stop_reason = "interrupted"
        state.stop_event.set()
        raise KeyboardInterrupt

    signal.signal(signal.SIGINT, stop_on_signal)
    signal.signal(signal.SIGTERM, stop_on_signal)

    try:
        try:
            state.open_root()
        except OSError as exc:
            fail(f"Unable to pin the shared directory: {exc}")
        removed = cleanup_orphaned_uploads(state)
        if removed:
            print(f"[INFO] Removed {len(removed)} orphaned upload temp file(s) from a previous interrupted run.")
        if not is_loopback_host(args.host):
            print("[WARN] This server uses plain HTTP on a non-loopback interface, even when a Cloudflare tunnel is enabled; credentials and file traffic are not encrypted on that interface.")
        load_template()
        print(f"[INFO] FileShare v{APP_VERSION}")
        print(f"[INFO] Sharing: {root}")
        print(f"[INFO] Files: {len(state.files())}")
        print(f"[INFO] Expiry: {'disabled' if expires is None else args.expires}")
        print(f"[INFO] One-time: {'yes' if args.one_time else 'no'}")
        if extra_origins:
            print(f"[INFO] Extra allowed origins: {', '.join(sorted(extra_origins))}")

        binary = ""
        if not args.no_tunnel:
            binary = ensure_cloudflared(temp_root)
            print(f"[OK] cloudflared: {binary}")

        server = http.server.ThreadingHTTPServer((config.host, config.port), ShareHandler)
        server.daemon_threads = True
        server.share_state = state  # type: ignore[attr-defined]
        state.server = server
        config.port = int(server.server_address[1])
        local_origin = format_http_origin(origin_host_for_bind(args.host), config.port)
        thread = threading.Thread(target=server.serve_forever, name="http-server", daemon=True)
        thread.start()
        print(f"[OK] Local server: {local_origin}/")

        # Prove the origin is reachable before starting the public tunnel.
        with urlopen(local_origin + "/", timeout=5) as response:
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
            cmd = [binary, "tunnel", "--no-autoupdate", "--url", local_origin]
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
            request = Request(state.public_url + "/", headers={"User-Agent": f"file-share-verifier/{APP_VERSION}"})
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
        print(f"  Local     : {local_origin}/")
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
        state.close_root()
        shutil.rmtree(temp_root, ignore_errors=True)
        print(f"[OK] Share stopped ({state.stop_reason}); temporary data removed.")


if __name__ == "__main__":
    raise SystemExit(main())
