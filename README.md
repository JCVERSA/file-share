# File Share


Lightweight temporary file-sharing server for Linux VPS/container environments.

## What it does

- Python standard library for the backend.
- Dark, minimal interface; no heavy visual effects or gradients.
- Integrated animated download CTA, download-all action, restrained stop-share action, refresh control, skeleton loading state, connection loader, and 3D GitHub footer link.
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
  TEMPORARY FILE SHARE v3.5.1
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

## Refreshing the file list

The **Refresh** button re-reads the shared directory without restarting the server or changing the public URL. While the request is in progress, the file list is replaced by lightweight skeleton rows and the refresh icon spins. If the refresh fails, the previous list is restored.

## Stop sharing

Press `Ctrl+C`. The HTTP server and Quick Tunnel are stopped, sessions become invalid, and temporary tunnel/bundle files are removed.

## Validation status

The project is designed for local verification with Python's standard library. A real public Quick Tunnel still depends on network access from the target VPS. The runtime confirms that the tunnel URL was created; public HTTP verification is best-effort and is reported as `UNVERIFIED` when the VPS/container cannot resolve or reach the public hostname.


## v3.5.1

Public Cloudflare URL verification is best-effort. If the VPS/container cannot resolve `trycloudflare.com`, the share stays online and the CLI reports `UNVERIFIED` instead of stopping the tunnel.


## Dashboard UI

The dashboard includes scoped motion components for download progress and completion, a compact 3D loading/archive scene, skeleton loading, stop-share feedback, and the project GitHub action. Motion is automatically reduced when the browser requests `prefers-reduced-motion`.
