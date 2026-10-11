# File Share


Lightweight temporary file-sharing server for Linux VPS/container environments.

## What it does

- Python standard library for the backend.
- Dark, minimal interface; no heavy visual effects or gradients.
- Integrated animated download CTA, download-all action, restrained stop-share action, refresh control, skeleton loading state, connection loader, and 3D GitHub footer link.
- Random password generated on every launch and printed in the terminal.
- Automatic share expiration (default: 30 minutes).
- Optional `--one-time` mode: the whole share stops after the first completed file or bundle download.
- Login rate limiting: 5 attempts per client per minute; proxy headers (`CF-Connecting-IP` / `X-Forwarded-For`) are trusted only from the local tunnel, so a directly connected client cannot pick its own rate-limit bucket.
- Immediate regular files only; no recursive browsing.
- Symlinks are excluded.
- File-name validation and directory-relative, no-follow file opens on POSIX; symlinks are excluded.
- Streaming downloads with range support for large files.
- `Download all` creates a temporary ZIP and streams it to the client; bundles are limited to 2 GiB of source files and checked against available temporary disk space.
- Authenticated users can upload files into the shared directory; uploads are atomic, never overwrite existing names, and are limited to 1 GiB per file.
- Only one upload or ZIP build/transfer may use the application's disk-work slot at a time.
- Client-side search and category filters.
- Copy-link button.
- GitHub project button linking to `https://github.com/JCVERSA/file-share`.
- Dashboard stop-share control with confirmation; stopping the share does not delete the source files.
- QR code generated in the browser; the password is never embedded in it.
- Live expiry and transfer statistics.
- Manual file refresh button with a spinning refresh icon and skeleton placeholders while the directory is being rescanned.
- Optional download progress for files up to 50 MiB; larger files use the browser's native streaming download path.
- Local server listens on `127.0.0.1` by default.
- Cloudflare Quick Tunnel is started automatically unless `--no-tunnel` is used.
- Existing `~/.cloudflared` configuration is never modified; Quick Tunnel uses an isolated temporary `HOME`.
- If `cloudflared` is missing, the app downloads the official release binary to a temporary directory and verifies its SHA-256 digest before execution.
- No system package installation is required for the application or for the Cloudflare fallback binary.
- Temporary state is removed when the share stops.

## Quick start

### Linux

Install or update File Share:

```bash
curl -fsSL "https://raw.githubusercontent.com/JCVERSA/file-share/main/install.sh" | sh
```

Then simply run:

```bash
fs
```

With no directory argument, File Share shares the **current working directory**.

Share a specific directory:

```bash
fs /root/swiftslate-secrets
```

Update:

```bash
fs update
```

Check the installed version:

```bash
fs --version
```

Uninstall:

```bash
fs uninstall
```

### Windows PowerShell

Install or update File Share:

```powershell
irm https://raw.githubusercontent.com/JCVERSA/file-share/main/install.ps1 | iex
```

After installation, reopen PowerShell if `fs` is not immediately available:

```powershell
fs
```

With no directory argument, it shares the **current working directory**.

Share a specific directory:

```powershell
fs "C:\Users\user\Documents\swiftslate-secrets"
```

Update:

```powershell
fs update
```

Check the installed version:

```powershell
fs --version
```

Uninstall:

```powershell
fs uninstall
```

> If you prefer not to pipe an installer from the network, download `install.sh` or `install.ps1` from the repository, inspect it, and run it locally.

## Direct Python usage

The project can still be run without the global `fs` command:

```bash
python3 server.py
```

or on Windows:

```powershell
python .\server.py . --no-tunnel
```

The directory argument remains optional; omitting it means the current working directory.

### Common options

```bash
fs --no-tunnel
fs --expires 1h
fs --no-expiry
fs --one-time
fs /path/to/folder --expires 15m --one-time
```

## Terminal output

The terminal prints the password and public URL when the Cloudflare Quick Tunnel has been created. Public URL verification is best-effort; a DNS failure inside the VPS/container does not stop an otherwise running tunnel.

```text
================================================================
  TEMPORARY FILE SHARE v3.6.1
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

The Python origin binds to loopback by default. Only the selected directory's immediate regular files are exposed. The application does not browse subdirectories and ignores symbolic links. POSIX builds pin the shared directory with a directory file descriptor and open children relative to it. Platforms without these APIs recheck the root directory identity, but cannot eliminate every path-replacement race; do not let untrusted local users modify the shared directory.

The browser session uses an HTTP-only SameSite cookie, valid for up to 12 hours or until the share stops, whichever comes first. The cookie is marked Secure only for requests that arrive at the public URL's host, where the browser's connection is HTTPS; direct plain-HTTP access (loopback or a wildcard `--host` IP) is not marked Secure, because browsers reject a Secure cookie set over plain HTTP on a non-loopback host. Same-origin checks protect login, upload, logout, and stop-share requests; Fetch Metadata checks reject cross-site download requests. With a wildcard `--host`, use the server's IP for direct access; unconfigured DNS aliases are deliberately not trusted as origins.

The QR code contains only the public URL, never the password. Its JavaScript implementation is bundled locally; no QR-generation API or third-party CDN request is used at runtime.

The password and public URL are separate secrets. Anyone who has both can view, download, and upload files while the share is active. Uploads are saved into the shared directory, do not overwrite existing names, and remain there after the share stops; remove them from the host directory when no longer needed.

Share a dedicated directory rather than a broad system directory. The application refuses to share a filesystem root (including `/` and Windows drive roots). A non-loopback `--host` uses plain HTTP even when a Cloudflare tunnel is enabled; the server has no trusted-proxy configuration. Keep it on loopback unless you understand the network exposure, and do not expose it to an untrusted network.

## Cloudflare Quick Tunnel

Quick Tunnels generate a random `trycloudflare.com` hostname and proxy the local origin through Cloudflare. Cloudflare documents Quick Tunnels as a testing/development feature and currently limits them to 200 in-flight requests; they do not provide an SLA.

The application uses an isolated temporary Cloudflare configuration directory, so an existing user `~/.cloudflared/config.yaml` is not changed.

## QR code

The dashboard uses a locally served copy of `qrcode-generator` 1.4.4 (MIT license), loaded with a SHA-512 Subresource Integrity hash. The matching checksum is stored in `static/SHA512SUMS` and checked by CI. The QR payload is the already-visible public URL and is not sent to a QR-generation API or third-party CDN.

## Large files

The backend streams files in 1 MiB chunks and supports byte ranges for resumable browser downloads. The optional download-progress UI uses an in-browser buffered request only for files up to 50 MiB to avoid forcing very large files into browser memory. Larger files use the normal browser download path.

**Download all** supports up to 2 GiB of source files and needs temporary disk space approximately equal to the files being bundled. The server checks available space and serializes ZIP creation with uploads. Individual downloads are not subject to this bundle limit.

## Uploading files

After signing in, choose **Upload file** to send one file to the shared directory. Uploads stream in bounded chunks, display progress, and are limited to 1 GiB per file. Existing files are never overwritten; if a name conflicts, rename the local file and retry. Only one upload or ZIP operation runs at a time. Anyone with the share password can upload, so share credentials only with people trusted to write into the host directory.

## Refreshing the file list

The **Refresh** button re-reads the shared directory without restarting the server or changing the public URL. While the request is in progress, the file list is replaced by lightweight skeleton rows and the refresh icon spins. If the refresh fails, the previous list is restored.

## Stop sharing

Press `Ctrl+C`. The HTTP server and Quick Tunnel are stopped, sessions become invalid, and temporary tunnel/bundle files are removed. Uploaded files remain in the shared directory; remove them from the host if they should not persist.

## Validation status

The project is designed for local verification with Python's standard library. A real public Quick Tunnel still depends on network access from the target VPS. The runtime confirms that the tunnel URL was created; public HTTP verification is best-effort and is reported as `UNVERIFIED` when the VPS/container cannot resolve or reach the public hostname.


## v3.6.1

Security and reliability fixes: the session cookie is marked `Secure` only for requests that arrive at the public URL's host (the origin always speaks plain HTTP; browsers reject a `Secure` cookie set over plain HTTP on non-loopback hosts, which broke the documented direct-access workflow in tunnel mode); login rate limiting now trusts `CF-Connecting-IP` / `X-Forwarded-For` only from loopback peers (the local Quick Tunnel), so directly connected clients can no longer bypass the limiter; idle HTTP connections are closed after 60 seconds so a stalled client cannot pin a server thread (and, through the tunnel, a Cloudflare in-flight slot); and upload temp files older than one hour left behind by a crashed run are removed at startup. The project is now released under the MIT license. CI runs a Python 3.10–3.12 matrix, a pyflakes lint step, and a PowerShell installer syntax check.

## v3.6.0

Adds authenticated, atomic uploads; upload and bundle limits; same-origin checks for state-changing actions; POSIX directory-descriptor file access; and a locally served QR library. Public Cloudflare URL verification remains best-effort: if the VPS/container cannot resolve `trycloudflare.com`, the share stays online and the CLI reports `UNVERIFIED` instead of stopping the tunnel.


## Dashboard UI

The dashboard includes upload and download progress, a non-blocking archive status, a compact 3D loading scene, skeleton loading, stop-share feedback, and the project GitHub action. Motion is automatically reduced when the browser requests `prefers-reduced-motion`.
