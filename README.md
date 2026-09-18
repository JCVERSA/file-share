# File Share

Lightweight temporary file-sharing server for Linux VPS/container environments.

## What it does

- Python standard library for the backend.
- Dark, minimal interface; no heavy visual effects or gradients.
- Random password generated on every launch and printed in the terminal.
- Automatic share expiration (default: 30 minutes).
- Optional `--one-time` mode: the whole share stops after the first completed file or bundle download.
- Login rate limiting: 5 attempts per client per minute.
- Immediate regular files only; no recursive browsing.
- Symlinks are excluded.
- File-path validation and `O_NOFOLLOW` where available.
- Streaming downloads with range support for large files.
- `Download all` creates a temporary ZIP and streams it to the client.
- Client-side search and category filters.
- Copy-link button.
- QR code generated in the browser; the password is never embedded in it.
- Live expiry and transfer statistics.
- Optional download progress for files up to 50 MiB; larger files use the browser's native streaming download path.
- Local server listens on `127.0.0.1` by default.
- Cloudflare Quick Tunnel is started automatically unless `--no-tunnel` is used.
- Existing `~/.cloudflared` configuration is never modified; Quick Tunnel uses an isolated temporary `HOME`.
- If `cloudflared` is missing, the app downloads the official release binary to a temporary directory and verifies its SHA-256 digest before execution.
- No system package installation is required for the application or for the Cloudflare fallback binary.
- Temporary state is removed when the share stops.

## Usage

Default: 30-minute public share.

```bash
python3 server.py /root/swiftslate-secrets
```

Custom lifetime:

```bash
python3 server.py /root/swiftslate-secrets --expires 1h
```

One-time share:

```bash
python3 server.py /root/swiftslate-secrets --one-time
```

One-time + custom lifetime:

```bash
python3 server.py /root/swiftslate-secrets --expires 15m --one-time
```

No automatic expiry:

```bash
python3 server.py /root/swiftslate-secrets --no-expiry
```

Fixed local port:

```bash
python3 server.py /root/swiftslate-secrets --port 8080
```

Local-only mode without Cloudflare:

```bash
python3 server.py /root/swiftslate-secrets --no-tunnel
```

## Terminal output

The terminal prints the password and the public URL when the Cloudflare Quick Tunnel has been created and publicly verified.

```text
================================================================
  TEMPORARY FILE SHARE v3.0.1
================================================================
  Directory : /root/swiftslate-secrets
  Local     : http://127.0.0.1:43821/
  Password  : generated-at-runtime
  Lifetime  : 30m
  One-time  : NO

  PUBLIC URL:
  https://random-name.trycloudflare.com/
================================================================
  STATUS: READY
================================================================
```

## Security model

The Python origin binds to loopback by default. Only the selected directory's immediate regular files are exposed. The application does not browse subdirectories and ignores symbolic links.

The browser session uses an HTTP-only SameSite cookie. When the public URL exists, the cookie is also marked Secure.

The QR code contains only the public URL, never the password.

The password and public URL are separate secrets. Anyone who has both can use the share while it is active.

Share a dedicated directory rather than a broad system directory. The application refuses to share `/` itself.

## Cloudflare Quick Tunnel

Quick Tunnels generate a random `trycloudflare.com` hostname and proxy the local origin through Cloudflare. Cloudflare documents Quick Tunnels as a testing/development feature and currently limits them to 200 in-flight requests; they do not provide an SLA.

The application uses an isolated temporary Cloudflare configuration directory, so an existing user `~/.cloudflared/config.yaml` is not changed.

## QR code

The interface uses the `qrcode` browser build from jsDelivr at version 1.5.4. The library runs in the browser; the QR payload is the already-visible public URL and is not sent to a QR-generation API.

If the browser cannot load the CDN asset, the file-sharing functionality still works; only the QR display is unavailable.

## Large files

The backend streams files in 1 MiB chunks and supports byte ranges for resumable browser downloads. The optional progress UI uses an in-browser buffered request only for files up to 50 MiB to avoid forcing very large files into browser memory. Larger files use the normal browser download path.

## Stop sharing

Press `Ctrl+C`. The HTTP server and Quick Tunnel are stopped, sessions become invalid, and temporary tunnel/bundle files are removed.

## Validation status

The project is designed for local verification with Python's standard library. A real public Quick Tunnel still depends on network access from the target VPS and is reported by the runtime only after the public URL passes an HTTP health check.


## v3.0.1

Public Cloudflare URL verification is best-effort. If the VPS/container cannot resolve `trycloudflare.com`, the share stays online and the CLI reports `UNVERIFIED` instead of stopping the tunnel.
