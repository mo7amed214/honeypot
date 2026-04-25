#!/usr/bin/env bash
set -euo pipefail

if ! command -v vagrant >/dev/null 2>&1; then
  echo "vagrant is not installed on this host" >&2
  exit 1
fi

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
BOX_FILE="${1:-$ROOT_DIR/vagrant/boxes/ews-win11.box}"
BOX_NAME="${HONEYPOT_EWS_BOX_NAME:-honeypot/ews-win11-local}"

if [[ ! -f "$BOX_FILE" ]]; then
  echo "Windows EWS box not found: $BOX_FILE" >&2
  echo "Create or copy a packaged box there first." >&2
  exit 1
fi

echo "Registering Windows EWS box:"
echo "  name: $BOX_NAME"
echo "  file: $BOX_FILE"
vagrant box add --force --name "$BOX_NAME" "$BOX_FILE"

cat <<EOF

Windows EWS box registered.

Next steps:
  export HONEYPOT_VAGRANT_PROFILE=laptop1-safe
  export HONEYPOT_EWS_MODE=windows
  export HONEYPOT_EWS_BOX=$BOX_NAME
  vagrant destroy -f ews
  vagrant up ews
EOF
