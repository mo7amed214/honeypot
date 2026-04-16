#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
DEMO_DIR="$ROOT_DIR/demos"
PYTHON_BIN="${PYTHON_BIN:-/usr/bin/python3}"

if [[ -x "$ROOT_DIR/.venv-demo/bin/python" ]] && \
  "$ROOT_DIR/.venv-demo/bin/python" -m streamlit --version >/dev/null 2>&1; then
  PYTHON_BIN="$ROOT_DIR/.venv-demo/bin/python"
fi

if ! "$PYTHON_BIN" -m streamlit --version >/dev/null 2>&1; then
  echo "[demo] streamlit is not installed."
  echo "[demo] Install with: pip install -r $DEMO_DIR/requirements.txt"
  exit 1
fi

cd "$ROOT_DIR"
exec "$PYTHON_BIN" -m streamlit run "$DEMO_DIR/streamlit_demo.py" --server.port 8501 --server.address 0.0.0.0
