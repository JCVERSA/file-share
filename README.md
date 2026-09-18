# File Share

Minimal temporary file-sharing server for Linux VPS/container environments.

## Features

- Python standard library only for the application.
- No Flask/FastAPI dependency.
- Dark, minimal HTML interface.
- Password generated randomly at every start.
- Password is printed once in the server logs.
- Session cookies are HTTP-only, Secure, and SameSite=Strict.
- Login attempts are rate-limited.
- Only regular files directly inside the selected directory are listed.
- Subdirectories are not browsable.
- Symlinks are excluded.
- Downloads are streamed without loading the whole file into memory.
- Server listens on `127.0.0.1` by default.
- Cloudflare Quick Tunnel can expose the local server publicly.
- Existing `~/.cloudflared` configuration is not modified; the tunnel uses an isolated temporary HOME.
- `cloudflared` is installed automatically on supported Linux systems when missing.
- Official release binary fallback is SHA-256 verified using the release metadata from GitHub.
- Temporary tunnel files are removed on exit.

## Usage

```bash
python3 server.py /root/swiftslate-secrets
```

Run locally without Cloudflare:

```bash
python3 server.py /root/swiftslate-secrets --no-tunnel
```

Optional explicit port:

```bash
python3 server.py /root/swiftslate-secrets --port 8080
```

## What gets shared

The application lists only immediate regular files in the selected directory. It does not recurse into subdirectories. Symbolic links are excluded so a symlink cannot intentionally expose a different location.

## Runtime output

The terminal prints:

- local address
- random temporary password
- public Cloudflare URL when available
- whether the public URL could be verified from the VPS

Example:

```text
==================================================
  TEMPORARY FILE SHARE v2.0.0
==================================================
  Directory : /root/swiftslate-secrets
  Local     : http://127.0.0.1:43127/
  Password  : <random-password>

  PUBLIC URL:
  https://example.trycloudflare.com/
  Verified  : YES
==================================================
```

## Security notes

This is intended for temporary file transfer, not permanent hosting. Anyone who has both the public URL and the password can access the files while the process is running.

The public Cloudflare endpoint is HTTPS, but the origin connection from `cloudflared` to this local application is plain HTTP on loopback.

Do not use this to expose an entire sensitive filesystem. Share a dedicated directory containing only what you intend to transfer.

## Stop sharing

Press `Ctrl+C`. The HTTP server and Quick Tunnel are stopped and temporary tunnel state is deleted.

## Requirements

- Linux for automatic `cloudflared` installation.
- Python 3.
- Internet access is required for Cloudflare Quick Tunnel and automatic `cloudflared` installation.
- On a Linux system without `apt`, the application can fall back to the official `cloudflared` release binary when `curl` is available.

## Verification status

The application verifies locally that the server can start and the public URL, when available, is checked with a real HTTP request from the VPS. A failed public verification is reported as `Verified: NO` rather than being presented as success.
