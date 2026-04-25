#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
DEST="${EWS_BOX_DEST:-$ROOT_DIR/vagrant/boxes/ews-win11.box}"
SOURCE="${1:-${EWS_BOX_SOURCE:-}}"
REGISTER="${EWS_BOX_REGISTER:-1}"

usage() {
  cat <<'EOF'
Usage:
  bash scripts/install_ews_windows_box.sh /path/to/ews-win11.box
  EWS_BOX_URL=https://example.invalid/ews-win11.box bash scripts/install_ews_windows_box.sh
  EWS_BOX_SOURCE='labssh@192.168.1.3:/C:/Users/labssh/Downloads/ews-win11.box' bash scripts/install_ews_windows_box.sh

Environment:
  EWS_BOX_DEST      Destination path. Default: vagrant/boxes/ews-win11.box
  EWS_BOX_REGISTER  Register with Vagrant after install. Default: 1

The .box file is intentionally not committed to git.
EOF
}

if [[ -z "$SOURCE" && -n "${EWS_BOX_URL:-}" ]]; then
  SOURCE="$EWS_BOX_URL"
fi

if [[ -z "$SOURCE" ]]; then
  usage >&2
  exit 1
fi

mkdir -p "$(dirname "$DEST")"

case "$SOURCE" in
  http://*|https://*)
    command -v curl >/dev/null 2>&1 || {
      echo "curl is required to download $SOURCE" >&2
      exit 1
    }
    echo "[ews-box] downloading $SOURCE"
    curl -L --fail --continue-at - --output "$DEST" "$SOURCE"
    ;;
  *:*)
    command -v scp >/dev/null 2>&1 || {
      echo "scp is required to copy $SOURCE" >&2
      exit 1
    }
    echo "[ews-box] copying $SOURCE"
    scp "$SOURCE" "$DEST"
    ;;
  *)
    [[ -f "$SOURCE" ]] || {
      echo "source box not found: $SOURCE" >&2
      exit 1
    }
    echo "[ews-box] copying local box $SOURCE"
    cp "$SOURCE" "$DEST"
    ;;
esac

size_bytes="$(stat -c '%s' "$DEST")"
if (( size_bytes < 1073741824 )); then
  echo "installed box is suspiciously small: $DEST ($size_bytes bytes)" >&2
  exit 1
fi

sha256sum "$DEST" | tee "$DEST.sha256"
echo "[ews-box] installed $DEST"

if [[ "$REGISTER" == "1" ]]; then
  bash "$ROOT_DIR/scripts/register_ews_windows_box.sh" "$DEST"
fi
