#!/usr/bin/env python3
"""Lightweight authenticated temporary file-sharing server.

Usage:
    python3 server.py /path/to/directory

The server exposes only regular files directly inside the selected directory.
It does not recurse into subdirectories and rejects symlinks.
It can optionally start a Cloudflare Quick Tunnel using cloudflared.
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
import secrets
import shutil
import signal
import socket
import subprocess
import sys
import tempfile
import threading
import time
from urllib.error import HTTPError, URLError
from urllib.parse import parse_qs, quote, urlparse
from urllib.request import Request, urlopen

APP_VERSION = "2.0.0"
TEMPLATE_PATH = Path(__file__).resolve().parent / "templates" / "index.html"
SESSION_COOKIE = "fs_session"
SESSION_TTL = 12 * 60 * 60
LOGIN_WINDOW = 60
LOGIN_MAX_ATTEMPTS = 5
MAX_NAME_LENGTH = 255


class Config:
    def __init__(self, root: Path, host: str, port: int, no_tunnel: bool):
        self.root = root
        self.host = host
        self.port = port
        self.no_tunnel = no_tunnel


class State:
    def __init__(self, config: Config):
        self.config = config
        self.password = secrets.token_urlsafe(12)
        self.sessions: dict[str, float] = {}
        self.login_attempts: dict[str, list[float]] = {}
        self.lock = threading.RLock()
        self.server: http.server.ThreadingHTTPServer | None = None
        self.tunnel: subprocess.Popen[str] | None = None
        self.tunnel_home: Path | None = None
        self.tunnel_log: Path | None = None
        self.public_url: str | None = None
        self.stop_event = threading.Event()

    def cleanup_expired_sessions(self) -> None:
        now = time.time()
        with self.lock:
            expired = [token for token, expiry in self.sessions.items() if expiry <= now]
            for token in expired:
                self.sessions.pop(token, None)

    def client_id(self, handler: http.server.BaseHTTPRequestHandler) -> str:
        # Cloudflare supplies CF-Connecting-IP. It is preferable to the tunnel's
        # loopback peer address for rate limiting. The server is only reachable
        # locally, so this is not an exposed public listener.
        return (
            handler.headers.get("CF-Connecting-IP")
            or handler.headers.get("X-Forwarded-For", "").split(",")[0].strip()
            or handler.client_address[0]
        )

    def allow_login_attempt(self, client: str) -> bool:
        now = time.time()
        with self.lock:
            values = [t for t in self.login_attempts.get(client, []) if now - t < LOGIN_WINDOW]
            if len(values) >= LOGIN_MAX_ATTEMPTS:
                self.login_attempts[client] = values
                return False
            values.append(now)
            self.login_attempts[client] = values
            return True

    def login_success(self, client: str) -> None:
        with self.lock:
            self.login_attempts.pop(client, None)

    def create_session(self) -> str:
        token = secrets.token_urlsafe(32)
        with self.lock:
            self.sessions[token] = time.time() + SESSION_TTL
        return token

    def is_authenticated(self, handler: http.server.BaseHTTPRequestHandler) -> bool:
        self.cleanup_expired_sessions()
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
            self.sessions[token] = time.time() + SESSION_TTL
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
        # Public Quick Tunnel URLs are HTTPS, so Secure is appropriate there.
        # Local --no-tunnel mode may be plain HTTP and still needs to function.
        secure = "; Secure" if self.public_url else ""
        return f"; Path=/; HttpOnly{secure}; SameSite=Strict"


def fail(message: str, code: int = 1) -> "NoReturn":
    print(f"[ERROR] {message}", file=sys.stderr)
    raise SystemExit(code)


def is_linux() -> bool:
    return sys.platform.startswith("linux")


def command_exists(name: str) -> bool:
    return shutil.which(name) is not None


def run_checked(args: list[str], *, env: dict[str, str] | None = None) -> subprocess.CompletedProcess[str]:
    return subprocess.run(args, check=True, text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=env)


def ensure_cloudflared() -> str:
    existing = shutil.which("cloudflared")
    if existing:
        return existing

    if not is_linux():
        fail("cloudflared is not installed and automatic installation is only implemented for Linux.")

    is_root = os.geteuid() == 0
    sudo = [] if is_root else (["sudo"] if command_exists("sudo") else None)
    if sudo is None:
        fail("cloudflared is missing and neither root nor sudo is available.")

    # Prefer Cloudflare's package repository where APT is available.
    if command_exists("apt-get") and command_exists("curl"):
        keyring = "/usr/share/keyrings/cloudflare-main.gpg"
        repo = "/etc/apt/sources.list.d/cloudflared.list"
        try:
            subprocess.run(
                [*sudo, "mkdir", "-p", "/usr/share/keyrings"],
                check=True,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )
            curl = subprocess.run(
                ["curl", "-fsSL", "https://pkg.cloudflare.com/cloudflare-main.gpg"],
                check=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
            )
            p = subprocess.run([*sudo, "tee", keyring], input=curl.stdout, stdout=subprocess.DEVNULL, check=True)
            _ = p
            repo_line = "deb [signed-by=/usr/share/keyrings/cloudflare-main.gpg] https://pkg.cloudflare.com/cloudflared any main\n"
            subprocess.run([*sudo, "tee", repo], input=repo_line.encode(), stdout=subprocess.DEVNULL, check=True)
            subprocess.run([*sudo, "apt-get", "update"], check=True)
            subprocess.run([*sudo, "apt-get", "install", "-y", "cloudflared"], check=True)
            installed = shutil.which("cloudflared")
            if installed:
                return installed
        except Exception as exc:
            print(f"[WARN] APT installation failed: {exc}")
            print("[INFO] Trying official release binary fallback...")

    if not command_exists("curl"):
        fail("curl is required to install cloudflared automatically.")

    machine = os.uname().machine.lower()
    arch_map = {
        "x86_64": "amd64",
        "amd64": "amd64",
        "aarch64": "arm64",
        "arm64": "arm64",
        "armv7l": "arm",
        "armv7": "arm",
        "i386": "386",
        "i686": "386",
    }
    arch = arch_map.get(machine)
    if not arch:
        fail(f"Unsupported Linux architecture for automatic cloudflared installation: {machine}")

    # Resolve the current release metadata through GitHub's official API so the
    # binary and published digest are tied to the same release.
    api_url = "https://api.github.com/repos/cloudflare/cloudflared/releases/latest"
    req = Request(api_url, headers={"Accept": "application/vnd.github+json", "User-Agent": "file-share/2.0"})
    try:
        with urlopen(req, timeout=15) as response:
            release = json.load(response)
    except Exception as exc:
        fail(f"Could not retrieve the current cloudflared release metadata: {exc}")

    asset_name = f"cloudflared-linux-{arch}"
    asset = next((a for a in release.get("assets", []) if a.get("name") == asset_name), None)
    if not asset:
        fail(f"Official release does not contain expected asset: {asset_name}")

    download_url = asset.get("browser_download_url")
    expected_sha = asset.get("digest", "")
    if not download_url or not expected_sha.startswith("sha256:"):
        fail("Official release metadata did not provide a usable download URL and SHA-256 digest.")
    expected_sha = expected_sha.split(":", 1)[1].lower()

    with tempfile.TemporaryDirectory(prefix="cloudflared-install-") as td:
        tmp = Path(td) / "cloudflared"
        print(f"[INFO] Downloading official {asset_name}...")
        subprocess.run(["curl", "-fL", "--retry", "3", "--connect-timeout", "15", download_url, "-o", str(tmp)], check=True)
        actual = hashlib.sha256(tmp.read_bytes()).hexdigest().lower()
        if not hmac.compare_digest(actual, expected_sha):
            fail("cloudflared SHA-256 verification failed; refusing to install the binary.")
        tmp.chmod(0o755)
        target = Path("/usr/local/bin/cloudflared")
        subprocess.run([*sudo, "install", "-m", "0755", str(tmp), str(target)], check=True)

    installed = shutil.which("cloudflared")
    if not installed:
        fail("cloudflared installation completed but the binary could not be found.")
    return installed


def load_template() -> str:
    try:
        return TEMPLATE_PATH.read_text(encoding="utf-8")
    except Exception as exc:
        fail(f"Unable to load template {TEMPLATE_PATH}: {exc}")


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


def safe_child(root: Path, name: str) -> Path | None:
    if not name or name in {".", ".."} or len(name) > MAX_NAME_LENGTH:
        return None
    if "/" in name or "\\" in name or "\x00" in name:
        return None
    candidate = root / name
    try:
        if candidate.is_symlink():
            return None
        if not candidate.is_file():
            return None
        real_root = root.resolve()
        real_candidate = candidate.resolve()
        if os.path.commonpath([str(real_root), str(real_candidate)]) != str(real_root):
            return None
        return real_candidate
    except (OSError, ValueError):
        return None


def list_files(root: Path) -> list[dict[str, str | int]]:
    results: list[dict[str, str | int]] = []
    try:
        entries = sorted(root.iterdir(), key=lambda p: p.name.lower())
    except OSError:
        return results
    for entry in entries:
        if not entry.is_file() or entry.is_symlink():
            continue
        try:
            stat = entry.stat()
        except OSError:
            continue
        results.append(
            {
                "name": entry.name,
                "size": stat.st_size,
                "size_human": human_size(stat.st_size),
                "mtime": time.strftime("%Y-%m-%d %H:%M", time.localtime(stat.st_mtime)),
                "type": file_type(entry.name),
            }
        )
    return results


def render_template(template: str, content: str, title: str = "File Share") -> bytes:
    replacements = {
        "{{TITLE}}": html.escape(title),
        "{{CONTENT}}": content,
        "{{VERSION}}": html.escape(APP_VERSION),
    }
    rendered = template
    for key, value in replacements.items():
        rendered = rendered.replace(key, value)
    return rendered.encode("utf-8")


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


def file_list_html(root: Path) -> str:
    files = list_files(root)
    rows = []
    for item in files:
        name = str(item["name"])
        href = "/download?file=" + quote(name, safe="")
        rows.append(
            f'''<a class="file-row" href="{html.escape(href, quote=True)}" download>
  <span class="file-icon">{html.escape(str(item["type"])[0:4])}</span>
  <span class="file-main">
    <strong>{html.escape(name)}</strong>
    <span>{html.escape(str(item["type"]))} · {html.escape(str(item["size_human"]))} · {html.escape(str(item["mtime"]))}</span>
  </span>
  <span class="download">Download</span>
</a>'''
        )
    if not rows:
        return '<div class="empty">No regular files were found in this directory.</div>'
    return '<div class="file-list">' + "".join(rows) + "</div>"


def dashboard_html(state: State) -> str:
    public = state.public_url or ""
    origin_label = html.escape(str(state.config.root))
    public_link = html.escape(public, quote=True) if public else ""
    file_count = len(list_files(state.config.root))
    return f"""
<section class="hero">
  <div>
    <div class="eyebrow">TEMPORARY SHARE</div>
    <h1>Available files</h1>
    <p class="muted">{file_count} file{'s' if file_count != 1 else ''} · {origin_label}</p>
  </div>
  <form method="post" action="/logout"><button class="ghost" type="submit">Lock</button></form>
</section>
<div class="notice">
  <span class="status-dot"></span>
  <span>Access is temporary. Keep this URL private.</span>
</div>
{file_list_html(state.config.root)}
"""


class ShareHandler(http.server.BaseHTTPRequestHandler):
    server_version = "FileShare/2.0"

    @property
    def state(self) -> State:
        return self.server.share_state  # type: ignore[attr-defined]

    def log_message(self, fmt: str, *args: object) -> None:
        # Minimal structured-ish access logging without cookies/passwords.
        print(f"[HTTP] {self.client_address[0]} - {fmt % args}")

    def send_html(self, payload: bytes, status: int = 200) -> None:
        self.send_response(status)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(payload)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Referrer-Policy", "no-referrer")
        self.send_header("X-Frame-Options", "DENY")
        self.send_header("Content-Security-Policy", "default-src 'self'; style-src 'unsafe-inline'; form-action 'self'; frame-ancestors 'none'; base-uri 'none'")
        self.end_headers()
        self.wfile.write(payload)

    def do_GET(self) -> None:
        parsed = urlparse(self.path)
        path = parsed.path
        if path == "/favicon.ico":
            self.send_response(204)
            self.end_headers()
            return
        if path == "/" or path == "/index.html":
            if not self.state.is_authenticated(self):
                body = login_html()
            else:
                body = dashboard_html(self.state)
            template = load_template()
            self.send_html(render_template(template, body))
            return
        if path == "/download":
            if not self.state.is_authenticated(self):
                self.send_html(render_template(load_template(), login_html()), 401)
                return
            query = parse_qs(parsed.query, keep_blank_values=True)
            name = query.get("file", [""])[0]
            target = safe_child(self.state.config.root, name)
            if target is None:
                self.send_error(404, "File not found")
                return
            try:
                size = target.stat().st_size
                mime, _ = mimetypes.guess_type(target.name)
                mime = mime or "application/octet-stream"
                filename = target.name.replace("\r", "").replace("\n", "")
                disposition = f"attachment; filename*=UTF-8''{quote(filename, safe='') }"
                self.send_response(200)
                self.send_header("Content-Type", mime)
                self.send_header("Content-Length", str(size))
                self.send_header("Content-Disposition", disposition)
                self.send_header("Cache-Control", "no-store")
                self.send_header("X-Content-Type-Options", "nosniff")
                self.end_headers()
                with target.open("rb") as src:
                    shutil.copyfileobj(src, self.wfile, length=1024 * 1024)
            except (BrokenPipeError, ConnectionResetError):
                pass
            except OSError:
                self.send_error(500, "Unable to read file")
            return
        self.send_error(404, "Not found")

    def do_POST(self) -> None:
        parsed = urlparse(self.path)
        if parsed.path == "/login":
            self.handle_login()
            return
        if parsed.path == "/logout":
            self.state.revoke_session(self)
            self.send_response(303)
            self.send_header("Location", "/")
            self.send_header("Set-Cookie", f"{SESSION_COOKIE}=deleted; Max-Age=0{self.state.cookie_suffix()}")
            self.end_headers()
            return
        self.send_error(404, "Not found")

    def handle_login(self) -> None:
        client = self.state.client_id(self)
        if not self.state.allow_login_attempt(client):
            self.send_html(render_template(load_template(), '<section class="auth-card"><h1>Too many attempts</h1><p class="muted">Try again in about one minute.</p></section>'), 429)
            return

        try:
            length = int(self.headers.get("Content-Length", "0"))
        except ValueError:
            length = 0
        if length > 4096:
            self.send_error(400, "Request too large")
            return
        data = self.rfile.read(length).decode("utf-8", "replace")
        password = parse_qs(data, keep_blank_values=True).get("password", [""])[0]
        if not hmac.compare_digest(password.encode("utf-8"), self.state.password.encode("utf-8")):
            self.send_html(render_template(load_template(), '<section class="auth-card"><h1>Access denied</h1><p class="muted">The password is incorrect.</p><a class="back" href="/">Try again</a></section>'), 401)
            return

        self.state.login_success(client)
        token = self.state.create_session()
        self.send_response(303)
        self.send_header("Location", "/")
        self.send_header("Set-Cookie", f"{SESSION_COOKIE}={token}; Max-Age={SESSION_TTL}{self.state.cookie_suffix()}")
        self.end_headers()


def find_port(host: str) -> tuple[socket.socket, int]:
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind((host, 0))
    sock.listen(5)
    return sock, sock.getsockname()[1]


def start_http_server(state: State) -> tuple[http.server.ThreadingHTTPServer, threading.Thread]:
    # Bind to port 0 to let the kernel select a currently free port.
    server = http.server.ThreadingHTTPServer((state.config.host, state.config.port), ShareHandler)
    server.daemon_threads = True
    server.allow_reuse_address = True
    server.share_state = state  # type: ignore[attr-defined]
    state.server = server
    state.config.port = int(server.server_address[1])
    thread = threading.Thread(target=server.serve_forever, name="http-server", daemon=True)
    thread.start()
    return server, thread


def start_cloudflared(state: State, binary: str) -> None:
    if state.config.no_tunnel:
        print(f"[INFO] Local server: http://127.0.0.1:{state.config.port}/")
        return

    work = Path(tempfile.mkdtemp(prefix="file-share-"))
    state.tunnel_home = work / "home"
    state.tunnel_home.mkdir(mode=0o700)
    (state.tunnel_home / ".cloudflared").mkdir(mode=0o700)
    state.tunnel_log = work / "cloudflared.log"

    env = os.environ.copy()
    env["HOME"] = str(state.tunnel_home)
    env["NO_COLOR"] = "1"

    cmd = [binary, "tunnel", "--no-autoupdate", "--url", f"http://127.0.0.1:{state.config.port}"]
    log_file = state.tunnel_log.open("w", encoding="utf-8")
    state.tunnel = subprocess.Popen(cmd, stdout=log_file, stderr=subprocess.STDOUT, text=True, env=env)

    deadline = time.time() + 30
    pattern = "trycloudflare.com"
    public_url = None
    while time.time() < deadline:
        if state.tunnel.poll() is not None:
            break
        try:
            text = state.tunnel_log.read_text(encoding="utf-8", errors="replace")
        except OSError:
            text = ""
        for token in text.split():
            token = token.strip("'\"(),")
            if token.startswith("https://") and pattern in token:
                public_url = token.rstrip("/.")
                break
        if public_url:
            break
        time.sleep(0.5)

    if not public_url:
        details = state.tunnel_log.read_text(encoding="utf-8", errors="replace") if state.tunnel_log.exists() else ""
        print("[WARN] Cloudflare Quick Tunnel URL was not detected.")
        if details.strip():
            print("[WARN] cloudflared log:")
            print(details[-4000:])
        return

    state.public_url = public_url


def verify_public_url(state: State) -> bool:
    if not state.public_url:
        return False
    url = state.public_url + "/"
    req = Request(url, headers={"User-Agent": "file-share-verifier/2.0"}, method="GET")
    try:
        with urlopen(req, timeout=15) as response:
            status = getattr(response, "status", response.getcode())
            return 200 <= int(status) < 400
    except (HTTPError, URLError, TimeoutError, OSError):
        return False


def cleanup(state: State) -> None:
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

    if state.tunnel_home is not None:
        try:
            shutil.rmtree(state.tunnel_home.parent, ignore_errors=True)
        except OSError:
            pass
        state.tunnel_home = None


def print_banner(state: State, verified: bool) -> None:
    print("\n" + "=" * 66)
    print(f"  TEMPORARY FILE SHARE v{APP_VERSION}")
    print("=" * 66)
    print(f"  Directory : {state.config.root}")
    print(f"  Local     : http://127.0.0.1:{state.config.port}/")
    print("  Password  : " + state.password)
    if state.public_url:
        print("\n  PUBLIC URL:")
        print(f"  {state.public_url}/")
        print(f"  Verified  : {'YES' if verified else 'NO — could not verify from this VPS'}")
    else:
        print("\n  PUBLIC URL: not available")
    print("=" * 66)
    print("  Press Ctrl+C to stop the share and invalidate sessions.")
    print("  Keep the password and URL private.")
    print("=" * 66 + "\n")


def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(description="Authenticated temporary file sharing with optional Cloudflare Quick Tunnel.")
    p.add_argument("directory", help="Directory whose immediate regular files should be shared")
    p.add_argument("--host", default="127.0.0.1", help="Bind address (default: 127.0.0.1)")
    p.add_argument("--port", type=int, default=0, help="Port; 0 means auto-select")
    p.add_argument("--no-tunnel", action="store_true", help="Run only the local web server")
    return p.parse_args()


def main() -> int:
    args = parse_args()
    root = Path(args.directory).expanduser()
    if not root.exists() or not root.is_dir():
        fail(f"Directory does not exist: {root}")
    root = root.resolve()
    if root == Path("/"):
        fail("Refusing to share the filesystem root.")

    config = Config(root=root, host=args.host, port=args.port, no_tunnel=args.no_tunnel)
    state = State(config)

    def handle_signal(signum: int, _frame: object) -> None:
        print(f"\n[INFO] Received signal {signum}; stopping...")
        state.stop_event.set()
        raise KeyboardInterrupt

    signal.signal(signal.SIGINT, handle_signal)
    signal.signal(signal.SIGTERM, handle_signal)

    try:
        template = load_template()
        if "{{CONTENT}}" not in template:
            fail("Template is missing {{CONTENT}} placeholder.")
        print(f"[INFO] FileShare v{APP_VERSION}")
        print(f"[INFO] Sharing: {root}")
        if not args.no_tunnel:
            binary = ensure_cloudflared()
            print(f"[OK] cloudflared: {binary}")
        else:
            binary = ""

        server, thread = start_http_server(state)
        _ = server, thread
        print(f"[OK] Local server started on 127.0.0.1:{state.config.port}")

        if not args.no_tunnel:
            start_cloudflared(state, binary)
            verified = verify_public_url(state)
        else:
            verified = False
        print_banner(state, verified)

        while not state.stop_event.wait(0.5):
            if state.tunnel is not None and state.tunnel.poll() is not None:
                print("[WARN] cloudflared exited unexpectedly; public access is no longer available.")
                break
        return 0
    except KeyboardInterrupt:
        return 0
    finally:
        cleanup(state)
        print("[OK] Temporary services stopped and temporary tunnel data removed.")


if __name__ == "__main__":
    raise SystemExit(main())
