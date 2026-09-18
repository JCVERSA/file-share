#!/bin/sh
set -eu

REPO="JCVERSA/file-share"
BRANCH="main"
ARCHIVE_URL="https://github.com/$REPO/archive/refs/heads/$BRANCH.zip"
RAW_BASE="https://raw.githubusercontent.com/$REPO/$BRANCH"

APP_NAME="file-share"
COMMAND_NAME="fs"

USER_DATA_DIR="${XDG_DATA_HOME:-$HOME/.local/share}/$APP_NAME"
if [ "$(id -u)" -eq 0 ] && [ -d /usr/local/bin ] && [ -w /usr/local/bin ]; then
    USER_BIN_DIR="/usr/local/bin"
else
    USER_BIN_DIR="${XDG_BIN_HOME:-$HOME/.local/bin}"
fi
BACKUP_DIR="$USER_DATA_DIR/backups"
INSTALL_DIR="$USER_DATA_DIR/current"

UPDATE_MODE=0
DRY_RUN=0
FORCE=0
SOURCE_DIR=""

log()  { printf '[INFO] %s\n' "$*"; }
ok()   { printf '[OK] %s\n' "$*"; }
warn() { printf '[WARN] %s\n' "$*" >&2; }
die()  { printf '[ERROR] %s\n' "$*" >&2; exit 1; }

usage() {
    cat <<EOF
File Share installer

Install or update:
  curl -fsSL $RAW_BASE/install.sh | sh

Options:
  --update         Explicit update mode
  --dry-run        Download and validate, but do not install
  --force          Reinstall even when the same version is installed
  --source-dir DIR Install from an existing checkout instead of GitHub
  --help           Show this help
EOF
}

while [ "$#" -gt 0 ]; do
    case "$1" in
        --update) UPDATE_MODE=1 ;;
        --dry-run) DRY_RUN=1 ;;
        --force) FORCE=1 ;;
        --source-dir)
            shift
            [ "$#" -gt 0 ] || die "--source-dir requires a directory"
            SOURCE_DIR=$1
            ;;
        --help|-h) usage; exit 0 ;;
        *) die "Unknown option: $1" ;;
    esac
    shift
done

command_exists() { command -v "$1" >/dev/null 2>&1; }

command_exists python3 || die "Python 3 is required. Install Python 3, then run the installer again."
command_exists curl || die "curl is required. Install curl, then run the installer again."

if ! command_exists unzip; then
    :
fi

TMP_ROOT="$(mktemp -d "${TMPDIR:-/tmp}/file-share-install.XXXXXX")"
cleanup() { rm -rf "$TMP_ROOT"; }
trap cleanup EXIT INT TERM

ARCHIVE="$TMP_ROOT/file-share.zip"
EXTRACT_DIR="$TMP_ROOT/extracted"
STAGE_DIR="$TMP_ROOT/staged"

extract_archive() {
    mkdir -p "$EXTRACT_DIR"
    python3 - "$ARCHIVE" "$EXTRACT_DIR" <<'PY'
import sys, zipfile
archive, destination = sys.argv[1], sys.argv[2]
with zipfile.ZipFile(archive) as zf:
    zf.extractall(destination)
PY
    FOUND=""
    for d in "$EXTRACT_DIR"/*; do
        if [ -f "$d/server.py" ] && [ -d "$d/templates" ]; then
            FOUND="$d"
            break
        fi
    done
    [ -n "$FOUND" ] || die "Downloaded archive does not contain a valid File Share project."
    printf '%s\n' "$FOUND"
}

if [ -n "$SOURCE_DIR" ]; then
    SOURCE_DIR=$(CDPATH= cd -- "$SOURCE_DIR" && pwd)
    [ -f "$SOURCE_DIR/server.py" ] || die "Invalid source directory: $SOURCE_DIR"
    [ -d "$SOURCE_DIR/templates" ] || die "Missing templates directory in $SOURCE_DIR"
    PROJECT_DIR="$SOURCE_DIR"
    log "Installing from local source: $PROJECT_DIR"
else
    log "Downloading File Share from $REPO/$BRANCH..."
    curl -fL --retry 3 --connect-timeout 15 --silent --show-error "$ARCHIVE_URL" -o "$ARCHIVE" || die "Failed to download the repository archive."
    PROJECT_DIR="$(extract_archive)"
fi

REMOTE_VERSION="$(python3 - "$PROJECT_DIR/server.py" <<'PY'
import re, sys
text=open(sys.argv[1], encoding='utf-8').read()
m=re.search(r'^APP_VERSION\s*=\s*[\"\']([^\"\']+)[\"\']', text, re.M)
if not m: raise SystemExit('APP_VERSION not found')
print(m.group(1))
PY
)" || die "Could not determine the File Share version."

printf '%s' "$REMOTE_VERSION" | grep -Eq '^[0-9]+\.[0-9]+\.[0-9]+$' || die "Invalid File Share version: $REMOTE_VERSION"

CURRENT_VERSION=""
if [ -f "$INSTALL_DIR/server.py" ]; then
    CURRENT_VERSION="$(python3 - "$INSTALL_DIR/server.py" <<'PY'
import re, sys
text=open(sys.argv[1], encoding='utf-8').read()
m=re.search(r'^APP_VERSION\s*=\s*[\"\']([^\"\']+)[\"\']', text, re.M)
print(m.group(1) if m else '')
PY
)"
fi

if [ -n "$CURRENT_VERSION" ] && [ "$CURRENT_VERSION" = "$REMOTE_VERSION" ] && [ "$FORCE" -eq 0 ] && [ "$DRY_RUN" -eq 0 ]; then
    ok "File Share $CURRENT_VERSION is already installed."
    exit 0
fi

if [ -n "$CURRENT_VERSION" ] && [ "$FORCE" -eq 0 ]; then
    if python3 - "$CURRENT_VERSION" "$REMOTE_VERSION" <<'PY'
import sys
def v(s): return tuple(map(int, s.split('.')))
sys.exit(0 if v(sys.argv[1]) > v(sys.argv[2]) else 1)
PY
    then
        warn "Installed version $CURRENT_VERSION is newer than downloaded version $REMOTE_VERSION; refusing to downgrade."
        exit 0
    fi
fi

if [ "$DRY_RUN" -eq 1 ]; then
    ok "Validated File Share $REMOTE_VERSION."
    if [ -n "$CURRENT_VERSION" ]; then
        log "Installed version: $CURRENT_VERSION"
    fi
    exit 0
fi

mkdir -p "$USER_DATA_DIR" "$BACKUP_DIR" "$USER_BIN_DIR"
rm -rf "$STAGE_DIR"
mkdir -p "$STAGE_DIR"
cp -R "$PROJECT_DIR"/. "$STAGE_DIR"/
rm -rf "$STAGE_DIR/__pycache__" "$STAGE_DIR/.git" "$STAGE_DIR/.github"

# Validate the staged project before touching the active installation.
python3 -m py_compile "$STAGE_DIR/server.py"
python3 - "$STAGE_DIR/server.py" <<'PY'
import re, sys
from pathlib import Path
p=Path(sys.argv[1])
text=p.read_text(encoding='utf-8')
m=re.search(r'^APP_VERSION\s*=\s*[\"\']([^\"\']+)[\"\']', text, re.M)
if not m: raise SystemExit('APP_VERSION missing')
if not (p.parent / 'templates' / 'index.html').is_file(): raise SystemExit('templates/index.html missing')
print(f"Validated File Share {m.group(1)}")
PY

BACKUP=""
if [ -d "$INSTALL_DIR" ]; then
    BACKUP="$BACKUP_DIR/$(date +%Y%m%d-%H%M%S)-${CURRENT_VERSION:-unknown}"
    mv "$INSTALL_DIR" "$BACKUP"
fi

if ! mv "$STAGE_DIR" "$INSTALL_DIR"; then
    if [ -n "$BACKUP" ] && [ -d "$BACKUP" ]; then
        mv "$BACKUP" "$INSTALL_DIR" || true
    fi
    die "Could not activate the new File Share installation. Previous version was restored when possible."
fi

cat > "$USER_BIN_DIR/$COMMAND_NAME" <<EOF
#!/bin/sh
set -eu
INSTALL_DIR="$INSTALL_DIR"
INSTALLER="\$INSTALL_DIR/install.sh"
UNINSTALLER="\$INSTALL_DIR/uninstall.sh"
PYTHON="$(command -v python3 || true)"
[ -n "\$PYTHON" ] || { echo "[ERROR] python3 not found in PATH." >&2; exit 1; }

case "\${1:-}" in
    update|self-update)
        shift
        exec sh "\$INSTALLER" --update "\$@"
        ;;
    uninstall)
        exec sh "\$UNINSTALLER"
        ;;
    version|--version|-V)
        exec "\$PYTHON" "\$INSTALL_DIR/server.py" --version
        ;;
    help|-h|--help)
        exec "\$PYTHON" "\$INSTALL_DIR/server.py" --help
        ;;
    *)
        exec "\$PYTHON" "\$INSTALL_DIR/server.py" "\$@"
        ;;
esac
EOF
chmod +x "$USER_BIN_DIR/$COMMAND_NAME"

# The running installer may be stdin; install a stable remote-updating copy instead.
cat > "$INSTALL_DIR/install.sh" <<EOF
#!/bin/sh
exec curl -fsSL "$RAW_BASE/install.sh" | sh -s -- "\$@"
EOF
chmod +x "$INSTALL_DIR/install.sh"

cat > "$INSTALL_DIR/uninstall.sh" <<EOF
#!/bin/sh
set -eu
rm -f "$USER_BIN_DIR/$COMMAND_NAME"
rm -rf "$USER_DATA_DIR"
printf '[OK] File Share removed.\n'
printf '[INFO] Your shared directories were not modified.\n'
EOF
chmod +x "$INSTALL_DIR/uninstall.sh"

PROFILE_HINT=""
case ":${PATH:-}:" in
    *":$USER_BIN_DIR:"*) ;;
    *)
        PROFILE_HINT="Add $USER_BIN_DIR to PATH"
        for profile in "$HOME/.profile" "$HOME/.bashrc" "$HOME/.zshrc"; do
            [ -f "$profile" ] || continue
            if ! grep -Fq "$USER_BIN_DIR" "$profile" 2>/dev/null; then
                printf '\n# File Share\nexport PATH="$USER_BIN_DIR:$PATH"\n' >> "$profile"
            fi
        done
        ;;
esac

ok "File Share $REMOTE_VERSION installed."
ok "Command: $COMMAND_NAME"
if [ -n "$CURRENT_VERSION" ]; then
    ok "Previous version: $CURRENT_VERSION"
fi
if [ -n "$PROFILE_HINT" ]; then
    warn "$USER_BIN_DIR was added to your shell profiles. Open a new shell or run: export PATH=\"$USER_BIN_DIR:\$PATH\""
fi
printf '\n'
printf 'Try: fs --version\n'
printf '     fs\n'
printf '     fs update\n'
