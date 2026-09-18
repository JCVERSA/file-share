#!/bin/sh
set -eu
APP_NAME="file-share"
USER_DATA_DIR="${XDG_DATA_HOME:-$HOME/.local/share}/$APP_NAME"
USER_BIN_DIR="${XDG_BIN_HOME:-$HOME/.local/bin}"
rm -f "$USER_BIN_DIR/fs"
rm -rf "$USER_DATA_DIR"
printf '[OK] File Share removed.\n'
printf '[INFO] Shared directories were not modified.\n'
