# File Share

A lightweight temporary file-sharing server for Linux VPSs and containers.

File Share starts a local Python HTTP server for a selected directory, protects access with a generated password, and can expose the service through a temporary Cloudflare Quick Tunnel.

## Features

- Simple Python backend using the standard library
- Clean dark web interface
- Random password generated for every share session
- Automatic expiration
- Optional one-time sharing
- Search and file-type filters
- File name, type, size, and date information
- Direct downloads
- Download all files as a ZIP
- HTTP Range support for large files and resumable downloads
- Download counters and transfer statistics
- QR code view
- Copy public URL
- Brute-force protection
- Path-traversal protection
- Symlink restrictions
- Local HTTP server bound to `127.0.0.1`
- Cloudflare Quick Tunnel support
- Automatic cleanup when the share stops

> This project is designed for temporary sharing. Do not expose sensitive files unless you understand the risks of sharing them through a public link.

---

## Quick Start

### 1. Clone the repository

```bash
git clone https://github.com/JCVERSA/file-share.git
cd file-shareil
```

### 2. Start a share

Choose the directory you want to share:

```bash
python3 server.py /root/swiftslate-secrets
```

The server will generate a temporary password and start the share session.

The terminal will display the local status, Cloudflare public URL, password, and session information.

### 3. Open the public link

Open the generated `https://*.trycloudflare.com/` URL from another device.

The password shown in the server logs is required to access the files.

---

## Command Usage

### Basic

```bash
python3 server.py /path/to/directory
```

Example:

```bash
python3 server.py /root/swiftslate-secrets
```

### Custom expiration

```bash
python3 server.py /root/swiftslate-secrets --expires 15m
```

Examples:

```bash
--expires 5m
--expires 30m
--expires 1h
--expires 2d
```

### Disable expiration

```bash
python3 server.py /root/swiftslate-secrets --no-expiry
```

Use this only when you intentionally want the session to remain active until it is stopped.

### One-time sharing

```bash
python3 server.py /root/swiftslate-secrets --one-time
```

The share is automatically stopped after the configured one-time transfer completes.

---

## Interface

The web interface provides:

- File search
- Type filters
- Download buttons
- Download-all action
- Public URL copy button
- QR code
- Expiration countdown
- Download statistics
- Transfer statistics
- Active download information

---

## Security

File Share is designed to reduce accidental exposure of unrelated files.

The server:

- Serves only the selected directory
- Refuses path traversal
- Refuses symbolic links
- Uses a generated password for each session
- Applies rate limiting to failed authentication attempts
- Keeps the local HTTP service on `127.0.0.1`
- Uses a temporary Cloudflare environment
- Removes temporary runtime data when the session ends

However, a Cloudflare Quick Tunnel creates a public URL. Anyone who has both the public URL and the current password can access the shared files while the session is active.

Do not use temporary public sharing as a replacement for a dedicated private file-storage system.

---

## Windows

File Share can also be used locally on Windows.

### Requirements

Install Python 3 and make sure `python` or `py` works in PowerShell:

```powershell
python --version
```

or:

```powershell
py --version
```

### Clone the repository

Open PowerShell:

```powershell
git clone https://github.com/JCVERSA/file-share.git
cd file-share
```

### Share a Windows directory

The `directory` argument is required.

To share the current directory:

```powershell
python .\server.py . --no-tunnel
```

With the Python launcher:

```powershell
py .\server.py . --no-tunnel
```

To share another directory, use its full path:

```powershell
python .\server.py "C:\Users\user\Documents\swiftslate-secrets" --no-tunnel
```

Use quotes when the path contains spaces.

### Example from the project folder

If PowerShell shows:

```text
PS C:\Users\user\Documents\file-share\file-share>
```

this is valid:

```powershell
python .\server.py . --no-tunnel
```

This is **not** valid because the required directory argument is missing:

```powershell
python .\server.py --no-tunnel
```

### Windows + Cloudflare Quick Tunnel

To use the public Cloudflare link, omit `--no-tunnel`:

```powershell
python .\server.py "C:\Users\user\Documents\swiftslate-secrets"
```

The application will display the generated public URL and password in the terminal when the tunnel is available.

For a local-only Windows test, use:

```powershell
--no-tunnel
```

The local server will be available at the address displayed in the terminal, typically using `127.0.0.1` and an automatically selected port.

### Useful Windows commands

Check the current directory:

```powershell
Get-Location
```

List files:

```powershell
Get-ChildItem
```

Move to the project:

```powershell
cd "C:\Users\user\Documents\file-share\file-share"
```

Stop the share:

```text
Ctrl+C
```

## Requirements

The project is designed to run on common Linux VPSs and containers.

Required:

- Python 3
- A Linux environment
- Internet access for the Cloudflare tunnel
- `cloudflared`

The project can install or use `cloudflared` according to its runtime setup.

---

## Project Structure

```text
file-share/
├── server.py
├── templates/
│   └── index.html
└── README.md
```

---

## How It Works

```text
Selected directory
        │
        ▼
Python HTTP server
127.0.0.1
        │
        ▼
Cloudflare Quick Tunnel
        │
        ▼
Public HTTPS URL
        │
        ▼
Browser on another device
```

The local server remains bound to localhost while Cloudflare provides the temporary public endpoint.

---

## Stopping a Share

Press:

```text
Ctrl+C
```

The server stops the temporary services and removes its temporary runtime data.

The original shared directory is not intentionally modified by the sharing process.

---

## Troubleshooting

### The public URL is displayed but cannot be verified locally

This can happen when the VPS/container has DNS restrictions or cannot resolve the public `trycloudflare.com` hostname.

The tunnel URL may still be usable from another device.

Check that:

```bash
cloudflared --version
```

works and that the local server is healthy.

### Port problems

The server uses a free local port automatically unless configured otherwise by the current implementation.

### Python check

```bash
python3 --version
```

---

## Important Notes

Cloudflare Quick Tunnels are intended for temporary/testing use.

For long-term production file hosting, use a dedicated private storage or file-serving architecture instead of keeping a Quick Tunnel permanently active.

---

## License

See the repository license file for the current licensing terms.

---

## Repository

Official repository:

```text
https://github.com/JCVERSA/file-share
```

Clone:

```bash
git clone https://github.com/JCVERSA/file-share.git
cd file-shareil
```
