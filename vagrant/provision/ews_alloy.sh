#!/usr/bin/env bash
# Ship EWS honeypot and PERA telemetry into the Purdue 3.5 bastion stack.
set -euo pipefail

LOKI_PUSH_URL="${P35_LOKI_PUSH_URL:-http://192.168.56.11:3100/loki/api/v1/push}"
ALLOY_HTTP_ADDR="${P35_ALLOY_HTTP_ADDR:-192.168.56.5}"
ALLOY_HTTP_PORT="${P35_ALLOY_HTTP_PORT:-12345}"
SMOKE_LOG="/var/log/p35-ew/alloy-smoke.log"

export DEBIAN_FRONTEND=noninteractive

install_alloy() {
  apt-get update -y
  apt-get install -y ca-certificates curl gnupg
  install -d -m 0755 /etc/apt/keyrings
  if [[ ! -s /etc/apt/keyrings/grafana.asc ]]; then
    curl -fsSL https://apt.grafana.com/gpg-full.key -o /etc/apt/keyrings/grafana.asc
  fi
  echo "deb [signed-by=/etc/apt/keyrings/grafana.asc] https://apt.grafana.com stable main" \
    > /etc/apt/sources.list.d/grafana.list
  apt-get update -y
  apt-get install -y alloy
}

if ! command -v alloy >/dev/null 2>&1; then
  install_alloy
fi

mkdir -p /etc/alloy /var/lib/alloy/data /var/log/p35-ew
touch "${SMOKE_LOG}"
chmod 0644 "${SMOKE_LOG}"

cat > /etc/alloy/config.alloy <<EOF
logging {
  level  = "info"
  format = "logfmt"
}

loki.write "bastion" {
  endpoint {
    url = "${LOKI_PUSH_URL}"
  }
}

local.file_match "ews_auth" {
  path_targets = [
    {
      __path__  = "/var/log/auth.log",
      job       = "ews_auth",
      host      = "ews",
      role      = "level3_ews",
      component = "sshd",
      source    = "ews_host",
      repo      = "host",
      category  = "auth",
    },
  ]
  sync_period = "10s"
}

loki.source.file "ews_auth" {
  targets       = local.file_match.ews_auth.targets
  forward_to    = [loki.write.bastion.receiver]
  tail_from_end = true
}

local.file_match "ews_honeypot" {
  path_targets = [
    {
      __path__  = "/var/log/zeek/*.log",
      job       = "ews_honeypot_zeek",
      host      = "ews",
      role      = "level3_ews",
      component = "zeek",
      source    = "honeypot",
      repo      = "honeypot",
      category  = "network",
    },
    {
      __path__  = "/opt/honeypot/monitoring/wazuh/live-alerts/alerts.json",
      job       = "ews_honeypot_wazuh",
      host      = "ews",
      role      = "level3_ews",
      component = "wazuh",
      source    = "honeypot",
      repo      = "honeypot",
      category  = "edr",
    },
    {
      __path__  = "/opt/honeypot/monitoring/ml/integration_live_*.jsonl",
      job       = "ews_honeypot_ml",
      host      = "ews",
      role      = "level3_ews",
      component = "ml_correlator",
      source    = "ml",
      repo      = "honeypot",
      category  = "session_correlation",
    },
    {
      __path__  = "/opt/honeypot/services/historian/logs/*.jsonl",
      job       = "ews_honeypot_historian",
      host      = "ews",
      role      = "level3_ews",
      component = "historian",
      source    = "honeypot",
      repo      = "honeypot",
      category  = "historian",
    },
  ]
  sync_period = "10s"
}

loki.source.file "ews_honeypot" {
  targets       = local.file_match.ews_honeypot.targets
  forward_to    = [loki.write.bastion.receiver]
  tail_from_end = true
}

local.file_match "ews_pera" {
  path_targets = [
    {
      __path__  = "/opt/pera/logs/scada_honeypot_audit.json",
      job       = "ews_pera_audit",
      host      = "ews",
      role      = "level3_ews",
      component = "scada_audit",
      source    = "pera",
      repo      = "pera",
      category  = "ics_process",
    },
    {
      __path__  = "/opt/pera/logs/scada_mtu.log",
      job       = "ews_pera_scada",
      host      = "ews",
      role      = "level3_ews",
      component = "scada_mtu",
      source    = "pera",
      repo      = "pera",
      category  = "ics_process",
    },
  ]
  sync_period = "10s"
}

loki.source.file "ews_pera" {
  targets       = local.file_match.ews_pera.targets
  forward_to    = [loki.write.bastion.receiver]
  tail_from_end = false
}

local.file_match "ews_smoke" {
  path_targets = [
    {
      __path__  = "${SMOKE_LOG}",
      job       = "ews_alloy_smoke",
      host      = "ews",
      role      = "level3_ews",
      component = "alloy",
      source    = "ews",
      repo      = "collector",
      category  = "collector_health",
    },
  ]
  sync_period = "5s"
}

loki.source.file "ews_smoke" {
  targets       = local.file_match.ews_smoke.targets
  forward_to    = [loki.write.bastion.receiver]
  tail_from_end = true
}
EOF

usermod -aG adm alloy || true
cat > /etc/default/alloy <<EOF
CONFIG_FILE="/etc/alloy/config.alloy"
CUSTOM_ARGS="--server.http.listen-addr=${ALLOY_HTTP_ADDR}:${ALLOY_HTTP_PORT}"
EOF

systemctl daemon-reload
systemctl enable alloy
systemctl restart alloy

printf '{"schema_version":"p35.attack.v1","event_type":"collector_health.ews_alloy_ready","category":"collector_health","host":"ews","role":"level3_ews","component":"alloy","source":"ews","outcome":"ready"}\n' >> "${SMOKE_LOG}"
