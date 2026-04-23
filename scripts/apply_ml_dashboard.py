from __future__ import annotations

import argparse
import base64
import json
from pathlib import Path
from typing import Any, Dict, List
from urllib import request


ML_ROW_TITLE = "ML Correlated Sessions"
ML_PANEL_IDS = {90, 91, 92, 93, 94, 95, 96, 97, 98}
SESSION_PANEL_TITLE_OVERRIDES = {
    "Primary rule (24h)": "Primary rule (session)",
    "Top high-risk rule (24h)": "Top high-risk rule (session)",
}
SESSION_PANEL_QUERY_OVERRIDES = {
    "Primary rule (24h)": 'topk(1, max by (rule_id, rule_description, rule_level) (count_over_time({job="ml",source="ml",kind="session_detection_event",session_id=~"$session_id"} | json rule_id="rule_id", rule_description="rule_description", rule_level="rule_level" | rule_id!="" [$__range])))',
    "Asset classes hit": 'count(sum by (asset_class) (count_over_time({job="ml",source="ml",kind="session_detection_event",session_id=~"$session_id"} | json asset_class="asset_class" | asset_class!="" [$__range])))',
    "Top high-risk rule (24h)": 'topk(1, max by (rule_id, rule_description, rule_level) (count_over_time({job="ml",source="ml",kind="session_detection_event",session_id=~"$session_id"} | json rule_id="rule_id", rule_description="rule_description", rule_level="rule_level" | rule_id!="" | rule_level=~"([7-9]|[1-9][0-9]+)" [$__range])))',
    "Historian web evidence": 'sum(last_over_time({job="ml",source="ml",kind="session_detection_summary",session_id=~"$session_id"} | json | unwrap observed_historian_web_count [$__range])) or vector(0)',
    "SMB access": 'sum(last_over_time({job="ml",source="ml",kind="session_detection_summary",session_id=~"$session_id"} | json | unwrap observed_smb_access_count [$__range])) or vector(0)',
    "OPC UA path": 'sum(last_over_time({job="ml",source="ml",kind="session_detection_summary",session_id=~"$session_id"} | json | unwrap observed_opcua_path_count [$__range])) or vector(0)',
    "Write-like": 'sum(last_over_time({job="ml",source="ml",kind="session_detection_summary",session_id=~"$session_id"} | json | unwrap observed_write_like_count [$__range])) or vector(0)',
    "Critical write": 'sum(last_over_time({job="ml",source="ml",kind="session_detection_summary",session_id=~"$session_id"} | json | unwrap observed_critical_write_count [$__range])) or vector(0)',
    "Process anomaly": 'sum(last_over_time({job="ml",source="ml",kind="session_detection_summary",session_id=~"$session_id"} | json | unwrap observed_process_anomaly_count [$__range])) or vector(0)',
    "Process anomalies": 'sum(last_over_time({job="ml",source="ml",kind="session_detection_summary",session_id=~"$session_id"} | json | unwrap observed_process_anomaly_count [$__range])) or vector(0)',
    "Write-like events": 'sum(last_over_time({job="ml",source="ml",kind="session_detection_summary",session_id=~"$session_id"} | json | unwrap observed_write_like_count [$__range])) or vector(0)',
    "EWS access and commands": '{job="ml",source="ml",kind="session_detection_event",session_id=~"$session_id"} | json evidence_key="evidence_key", rule_id="rule_id", matched_step="matched_step", attack_stage="attack_stage", asset_class="asset_class", rule_description="rule_description" | evidence_key=~"host_access|host_command|host_scriptblock|staged_tool" | line_format "step={{.matched_step}} | rule={{.rule_id}} | stage={{.attack_stage}} | evidence={{.evidence_key}} | asset={{.asset_class}} | detail={{.rule_description}}"',
    "Application activity": '{job="ml",source="ml",kind="session_detection_event",session_id=~"$session_id"} | json evidence_key="evidence_key", rule_id="rule_id", matched_step="matched_step", attack_stage="attack_stage", asset_class="asset_class", rule_description="rule_description" | evidence_key=~"historian_web|write_like|critical_write|process_anomaly|staged_tool" | line_format "step={{.matched_step}} | rule={{.rule_id}} | stage={{.attack_stage}} | evidence={{.evidence_key}} | asset={{.asset_class}} | detail={{.rule_description}}"',
    "Network / OT path": '{job="ml",source="ml",kind="session_detection_event",session_id=~"$session_id"} | json evidence_key="evidence_key", rule_id="rule_id", matched_step="matched_step", attack_stage="attack_stage", asset_class="asset_class", rule_description="rule_description" | evidence_key=~"historian_web|smb_access|opcua_path|write_like|critical_write|discovery" | line_format "step={{.matched_step}} | rule={{.rule_id}} | stage={{.attack_stage}} | evidence={{.evidence_key}} | asset={{.asset_class}} | detail={{.rule_description}}"',
    "Latest OT impact events": '{job="ml",source="ml",kind="session_detection_event",session_id=~"$session_id"} | json evidence_key="evidence_key", rule_id="rule_id", matched_step="matched_step", attack_stage="attack_stage", rule_description="rule_description", data_uid="data_uid", data_tag="data_tag", data_service="data_service", data_confidence="data_confidence" | evidence_key=~"process_anomaly|write_like|critical_write|staged_tool" | line_format "rule={{.rule_id}} step={{.matched_step}} stage={{.attack_stage}} uid={{ if .data_uid }}{{ .data_uid }}{{ else }}-{{ end }} target={{ if .data_tag }}{{ .data_tag }}{{ else if .data_service }}{{ .data_service }}{{ else }}-{{ end }} confidence={{ if .data_confidence }}{{ .data_confidence }}{{ else }}-{{ end }} note={{ .rule_description }}"',
    "By attack stage": 'sum by (attack_stage) (count_over_time({job="ml",source="ml",kind="session_detection_event",session_id=~"$session_id"} | json attack_stage="attack_stage" | attack_stage!="" [$__range]))',
    "By asset class": 'sum by (asset_class) (count_over_time({job="ml",source="ml",kind="session_detection_event",session_id=~"$session_id"} | json asset_class="asset_class" | asset_class!="" [$__range]))',
    "Top rule descriptions": 'topk(10, sum by (rule_description) (count_over_time({job="ml",source="ml",kind="session_detection_event",session_id=~"$session_id"} | json rule_description="rule_description" | rule_description!="" [$__range])))',
    "Priority incident feed": '{job="ml",source="ml",kind="session_detection_event",session_id=~"$session_id"} | json rule_level="rule_level", rule_id="rule_id", matched_step="matched_step", attack_stage="attack_stage", asset_class="asset_class", rule_description="rule_description", data_uid="data_uid" | rule_level=~"([7-9]|[1-9][0-9]+)" | line_format "rule={{.rule_id}} step={{.matched_step}} stage={{.attack_stage}} asset={{.asset_class}} uid={{ if .data_uid }}{{ .data_uid }}{{ else }}-{{ end }} note={{ .rule_description }}"',
    "Session correlation digest": '{job="ml",source="ml",kind="session_detection_event",session_id=~"$session_id"} | json rule_level="rule_level", rule_id="rule_id", matched_step="matched_step", attack_stage="attack_stage", asset_class="asset_class", data_uid="data_uid", data_confidence="data_confidence" | rule_level=~"([7-9]|[1-9][0-9]+)" | line_format "rule={{.rule_id}} step={{.matched_step}} stage={{.attack_stage}} asset={{.asset_class}} uid={{ if .data_uid }}{{ .data_uid }}{{ else }}-{{ end }} confidence={{ if .data_confidence }}{{ .data_confidence }}{{ else }}-{{ end }}"',
}


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Append or refresh ML panels on the SOC Grafana dashboard.")
    parser.add_argument("--grafana-url", default="http://localhost:3000")
    parser.add_argument("--username", default="admin")
    parser.add_argument("--password", default="admin")
    parser.add_argument("--dashboard-uid", default="adx2v2p")
    parser.add_argument("--ml-summary-path", default="monitoring/ml/model_summary.jsonl")
    parser.add_argument(
        "--export-path",
        default="monitoring/grafana/soc_honeypot_detection_dashboard_ml.json",
    )
    return parser.parse_args()


def auth_header(username: str, password: str) -> Dict[str, str]:
    token = base64.b64encode(f"{username}:{password}".encode()).decode()
    return {"Authorization": f"Basic {token}"}


def http_json(url: str, method: str = "GET", payload: Dict[str, Any] | None = None, headers: Dict[str, str] | None = None) -> Dict[str, Any]:
    final_headers = {"Content-Type": "application/json"}
    if headers:
        final_headers.update(headers)
    data = None if payload is None else json.dumps(payload).encode()
    req = request.Request(url, data=data, headers=final_headers, method=method)
    with request.urlopen(req) as resp:
        return json.loads(resp.read().decode())


def discover_loki_uid(dashboard: Dict[str, Any]) -> str:
    for panel in dashboard.get("panels", []):
        datasource = panel.get("datasource")
        if isinstance(datasource, dict) and datasource.get("type") == "loki" and datasource.get("uid"):
            return str(datasource["uid"])
    raise SystemExit("Could not discover Loki datasource UID from dashboard.")


def cleanup_existing_ml_panels(panels: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    cleaned: List[Dict[str, Any]] = []
    for panel in panels:
        if panel.get("id") in ML_PANEL_IDS:
            continue
        if panel.get("type") == "row" and panel.get("title") == ML_ROW_TITLE:
            continue
        cleaned.append(panel)
    return cleaned


def retune_live_wazuh_panels(panels: List[Dict[str, Any]]) -> None:
    for panel in panels:
        if panel.get("id") in ML_PANEL_IDS:
            continue
        title = str(panel.get("title"))
        if title in SESSION_PANEL_TITLE_OVERRIDES:
            panel["title"] = SESSION_PANEL_TITLE_OVERRIDES[title]
        override_expr = SESSION_PANEL_QUERY_OVERRIDES.get(title) or SESSION_PANEL_QUERY_OVERRIDES.get(str(panel.get("title")))
        if override_expr:
            for target in panel.get("targets", []):
                if isinstance(target.get("expr"), str):
                    target["expr"] = override_expr


def ensure_session_textbox_variable(dashboard: Dict[str, Any]) -> None:
    templating = dashboard.setdefault("templating", {}).setdefault("list", [])
    current_value = ".*"
    for variable in templating:
        if variable.get("name") == "session_id":
            current = variable.get("current", {})
            raw = str(current.get("value", current.get("text", ".*")) or ".*")
            current_value = ".*" if raw in {"$__all", "All", ""} else raw
            break
    dashboard["templating"]["list"] = [
        {
            "name": "session_id",
            "label": "Session scope",
            "type": "textbox",
            "description": "Paste a specific demo session ID for the live attack console. Use .* for all recent sessions.",
            "hide": 0,
            "query": current_value,
            "current": {"selected": True, "text": current_value, "value": current_value},
            "skipUrlSync": False,
        }
    ]


def build_stat_panel(
    panel_id: int,
    title: str,
    description: str,
    expr: str,
    x: int,
    *,
    unit: str = "short",
    thresholds: Dict[str, Any] | None = None,
) -> Dict[str, Any]:
    return {
        "id": panel_id,
        "type": "stat",
        "title": title,
        "description": description,
        "gridPos": {"h": 5, "w": 6, "x": x, "y": 48},
        "datasource": {"type": "loki", "uid": "__LOKI_UID__"},
        "targets": [
            {
                "refId": "A",
                "datasource": {"type": "loki", "uid": "__LOKI_UID__"},
                "editorMode": "code",
                "expr": expr,
                "instant": True,
                "queryType": "instant",
            }
        ],
        "fieldConfig": {
            "defaults": {
                "color": {"mode": "thresholds"},
                "mappings": [{"type": "special", "options": {"match": "null", "result": {"text": "No data"}}}],
                "thresholds": thresholds
                or {"mode": "absolute", "steps": [{"color": "green", "value": 0}, {"color": "orange", "value": 1}, {"color": "red", "value": 2}]},
                "unit": unit,
            },
            "overrides": [],
        },
        "options": {
            "colorMode": "background",
            "graphMode": "none",
            "justifyMode": "center",
            "orientation": "auto",
            "reduceOptions": {"calcs": ["lastNotNull"], "fields": "", "values": False},
            "textMode": "auto",
        },
    }


def build_logs_panel(panel_id: int, title: str, description: str, expr: str, x: int, y: int, w: int, h: int) -> Dict[str, Any]:
    return {
        "id": panel_id,
        "type": "logs",
        "title": title,
        "description": description,
        "gridPos": {"h": h, "w": w, "x": x, "y": y},
        "datasource": {"type": "loki", "uid": "__LOKI_UID__"},
        "targets": [
            {
                "refId": "A",
                "datasource": {"type": "loki", "uid": "__LOKI_UID__"},
                "editorMode": "code",
                "expr": expr,
                "queryType": "range",
            }
        ],
        "options": {
            "dedupStrategy": "none",
            "enableLogDetails": True,
            "prettifyLogMessage": False,
            "showCommonLabels": False,
            "showControls": False,
            "showLabels": False,
            "showTime": True,
            "sortOrder": "Descending",
            "wrapLogMessage": True,
        },
    }


def build_text_panel(panel_id: int, title: str, markdown: str, x: int, y: int, w: int, h: int = 2) -> Dict[str, Any]:
    return {
        "id": panel_id,
        "type": "text",
        "title": title,
        "gridPos": {"h": h, "w": w, "x": x, "y": y},
        "options": {"content": markdown, "mode": "markdown"},
        "transparent": True,
    }


def replace_loki_uid(panels: List[Dict[str, Any]], loki_uid: str) -> None:
    for panel in panels:
        datasource = panel.get("datasource")
        if isinstance(datasource, dict) and datasource.get("uid") == "__LOKI_UID__":
            datasource["uid"] = loki_uid
        for target in panel.get("targets", []):
            td = target.get("datasource")
            if isinstance(td, dict) and td.get("uid") == "__LOKI_UID__":
                td["uid"] = loki_uid


def load_readiness(summary_path: Path) -> str:
    if not summary_path.exists():
        return "baseline_only"
    rows = [line.strip() for line in summary_path.read_text(encoding="utf-8").splitlines() if line.strip()]
    if not rows:
        return "baseline_only"
    return str(json.loads(rows[-1]).get("thesis_readiness", "baseline_only"))


def build_ready_panels() -> List[Dict[str, Any]]:
    return [
        build_text_panel(
            98,
            "Session focus",
            "This dashboard is session-scoped end to end.  \nPaste a specific Streamlit demo ID in `Session scope` to filter both the live detections and the ML correlation rows. Use `.*` for all recent sessions.",
            0,
            48,
            24,
            2,
        ),
        build_stat_panel(
            91,
            "Correlated sessions in view",
            "Full correlated sessions visible in the current dashboard time window and session scope.",
            'sum(count_over_time({job="ml",source="ml",kind="correlated_session_summary",session_id=~"$session_id"}[$__range]))',
            0,
        ),
        build_stat_panel(
            92,
            "Critical sessions in view",
            "Correlated sessions currently marked critical inside the selected window and session scope.",
            'sum(count_over_time({job="ml",source="ml",kind="correlated_session_summary",session_id=~"$session_id",predicted_danger_label="critical"}[$__range]))',
            6,
        ),
        build_stat_panel(
            93,
            "Highest risk in view",
            "Highest predicted danger score among the selected correlated sessions.",
            'max_over_time({job="ml",source="ml",kind="correlated_session_summary",session_id=~"$session_id"} | json | unwrap predicted_danger_score [$__range])',
            12,
            unit="percentunit",
            thresholds={"mode": "absolute", "steps": [{"color": "green", "value": 0}, {"color": "orange", "value": 0.55}, {"color": "red", "value": 0.80}]},
        ),
        build_stat_panel(
            94,
            "Distinct intents in view",
            "How many distinct analyst-facing session intents are visible right now.",
            'count(sum by (predicted_session_intent_hybrid) (count_over_time({job="ml",source="ml",kind="correlated_session_summary",session_id=~"$session_id"}[$__range])))',
            18,
        ),
        build_logs_panel(
            95,
            "Correlated session summaries",
            "Analyst-facing ML summaries for full correlated sessions.",
            '{job="ml",source="ml",kind="correlated_session_summary",session_id=~"$session_id"} | json | line_format "priority={{.predicted_priority}} risk={{.predicted_danger_label}} intent={{.predicted_session_intent_hybrid}} session={{.session_id}} assets={{.asset_path}} path={{.stage_path}} note={{.summary_text}}"',
            0,
            54,
            12,
            9,
        ),
        build_logs_panel(
            96,
            "Session progression",
            "Prefix-level risk buildup for each correlated session.",
            '{job="ml",source="ml",kind="session_progression",session_id=~"$session_id"} | json | line_format "session={{.session_id}} step={{.event_count}}/{{.total_event_count}} risk={{.predicted_danger_label}} score={{.predicted_danger_score}} intent={{.predicted_session_intent_hybrid}} stage={{.predicted_dominant_stage}} path={{.stage_path}}"',
            12,
            54,
            12,
            9,
        ),
        build_logs_panel(
            97,
            "Priority incident queue",
            "High-priority correlated sessions the SOC should triage first.",
            '{job="ml",source="ml",kind="correlated_session_summary",session_id=~"$session_id"} | json | predicted_priority=~"P1|P2" | line_format "priority={{.predicted_priority}} risk={{.predicted_danger_label}} intent={{.predicted_session_intent_hybrid}} session={{.session_id}} note={{.summary_text}}"',
            0,
            63,
            24,
            8,
        ),
    ]


def build_baseline_panels() -> List[Dict[str, Any]]:
    return [
        build_stat_panel(
            91,
            "ML readiness",
            "Current assessment of whether the dataset/model are good enough for strong thesis claims.",
            'last_over_time({job="ml",source="ml",kind="model_summary"} | json | unwrap thesis_readiness_score [30d])',
            0,
        ),
        build_stat_panel(
            92,
            "Labeled sessions",
            "How many unique base sessions the model was trained from.",
            'last_over_time({job="ml",source="ml",kind="model_summary"} | json | unwrap unique_base_sessions [30d])',
            6,
        ),
        build_stat_panel(
            93,
            "Unique paths",
            "How many distinct full-session stage paths exist in the current training set.",
            'last_over_time({job="ml",source="ml",kind="model_summary"} | json | unwrap unique_stage_paths [30d])',
            12,
        ),
        build_stat_panel(
            94,
            "Eval intent accuracy",
            "Held-out hybrid session-intent accuracy.",
            'last_over_time({job="ml",source="ml",kind="model_summary"} | json | unwrap eval_intent_accuracy_hybrid [30d])',
            18,
            unit="percentunit",
            thresholds={"mode": "absolute", "steps": [{"color": "red", "value": 0}, {"color": "orange", "value": 0.6}, {"color": "green", "value": 0.8}]},
        ),
        build_logs_panel(
            95,
            "Model assessment",
            "Latest ML readiness verdict and the reasons behind it.",
            '{job="ml",source="ml",kind="model_summary"} | json | line_format "readiness={{.thesis_readiness}} sessions={{.unique_base_sessions}} paths={{.unique_stage_paths}} benign={{.benign_full_sessions}} intents={{.unique_session_intents}} eval_intent_acc={{.eval_intent_accuracy_hybrid}} verdict={{.verdict}} note={{.summary_text}}"',
            0,
            54,
            10,
            8,
        ),
        build_logs_panel(
            96,
            "Session risk predictions",
            "Full-session and prefix-level danger predictions from the LSTM baseline.",
            '{job="ml",source="ml",kind=~"session_prediction|session_progression",session_id=~"$session_id"} | json | line_format "session={{.session_id}} split={{.split}} step={{.event_count}}/{{.total_event_count}} full={{.is_full_session}} score={{.predicted_danger_score}} label={{.predicted_danger_label}} intent={{.predicted_session_intent_hybrid}} stage={{.predicted_dominant_stage}} path={{.stage_path}}"',
            10,
            54,
            14,
            8,
        ),
    ]


def main() -> None:
    args = parse_args()
    headers = auth_header(args.username, args.password)
    payload = http_json(
        f"{args.grafana_url.rstrip('/')}/api/dashboards/uid/{args.dashboard_uid}",
        headers=headers,
    )

    dashboard = payload["dashboard"]
    loki_uid = discover_loki_uid(dashboard)
    ensure_session_textbox_variable(dashboard)
    panels = cleanup_existing_ml_panels(dashboard.get("panels", []))
    retune_live_wazuh_panels(panels)
    max_bottom = max(panel["gridPos"]["y"] + panel["gridPos"]["h"] for panel in panels)

    readiness = load_readiness(Path(args.ml_summary_path))
    ml_panels = build_ready_panels() if readiness == "soc_analyst_ready" else build_baseline_panels()
    replace_loki_uid(ml_panels, loki_uid)

    ml_row = {"collapsed": False, "gridPos": {"h": 1, "w": 24, "x": 0, "y": max_bottom}, "id": 90, "panels": [], "title": ML_ROW_TITLE, "type": "row"}
    stat_y = max_bottom + 3
    logs_y = stat_y + 5
    queue_y = logs_y + 9
    for panel in ml_panels:
        if panel["id"] == 98:
            panel["gridPos"]["y"] = max_bottom + 1
    for panel in ml_panels:
        if panel["id"] in {91, 92, 93, 94}:
            panel["gridPos"]["y"] = stat_y
    for panel in ml_panels:
        if panel["id"] in {95, 96}:
            panel["gridPos"]["y"] = logs_y
        if panel["id"] == 97:
            panel["gridPos"]["y"] = queue_y
    panels.extend([ml_row, *ml_panels])
    dashboard["panels"] = panels
    dashboard["version"] = int(payload["meta"]["version"])
    dashboard["refresh"] = "10s"
    dashboard["time"] = {"from": "now-2h", "to": "now"}

    result = http_json(
        f"{args.grafana_url.rstrip('/')}/api/dashboards/db",
        method="POST",
        payload={"dashboard": dashboard, "folderId": payload["meta"]["folderId"], "overwrite": True},
        headers=headers,
    )
    dashboard["version"] = int(result.get("version", dashboard["version"]))
    export_path = Path(args.export_path)
    export_path.parent.mkdir(parents=True, exist_ok=True)
    export_path.write_text(json.dumps(dashboard, indent=2), encoding="utf-8")
    print(json.dumps({"updated": True, "uid": args.dashboard_uid, "version": result.get("version"), "status": result.get("status"), "readiness": readiness}, indent=2))


if __name__ == "__main__":
    main()
