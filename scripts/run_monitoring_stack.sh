#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

docker compose -f "$ROOT_DIR/compose/docker-compose.monitoring.yml" up -d grafana

if ! ss -ltn | grep -q ':5001 '; then
  setsid -f python3 "$ROOT_DIR/scripts/historian_api_proxy.py" \
    --port 5001 \
    --upstream "${HISTORIAN_PROXY_UPSTREAM:-http://192.168.1.10:5000}" \
    > /tmp/historian_api_proxy.log 2>&1
fi

python3 "$ROOT_DIR/scripts/import_soc_dashboard.py"
python3 "$ROOT_DIR/scripts/import_opcua_telemetry_dashboard.py"

streamlit_healthy() {
  curl -fsS --max-time 3 http://127.0.0.1:8501/_stcore/health >/dev/null 2>&1
}

start_streamlit() {
  setsid -f python3 -m streamlit run "$ROOT_DIR/demos/streamlit_demo.py" \
    --server.port 8501 \
    --server.address 0.0.0.0 \
    --server.headless true \
    > /tmp/honeypot_streamlit.log 2>&1
}

if ! streamlit_healthy; then
  while read -r pid; do
    if [[ -n "$pid" && "$pid" != "$$" && "$pid" != "${BASHPID:-}" ]]; then
      kill "$pid" 2>/dev/null || true
    fi
  done < <(pgrep -f "streamlit run $ROOT_DIR/demos/streamlit_demo.py" || true)
  sleep 1
  start_streamlit
  for _ in {1..12}; do
    if streamlit_healthy; then
      break
    fi
    sleep 1
  done
fi

echo "Grafana SOC: http://127.0.0.1:3000/d/adx2v2p/soc-honeypot-detection-dashboard"
echo "Grafana OPC UA telemetry: http://127.0.0.1:3000/d/opcua-physics-telemetry/physics-aware-opc-ua-telemetry"
echo "Streamlit:   http://127.0.0.1:8501"
echo "Wazuh:       https://127.0.0.1"

if ! streamlit_healthy; then
  echo "WARN: Streamlit did not pass health check; see /tmp/honeypot_streamlit.log"
fi
