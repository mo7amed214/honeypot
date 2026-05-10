from __future__ import annotations

import argparse
import base64
import json
from pathlib import Path
from typing import Any
from urllib import error, request


DATASOURCE_UID = "historian-infinity"
DATASOURCE_TYPE = "yesoreyeram-infinity-datasource"
EXPORT_PATH = Path("monitoring/grafana/opcua_physics_telemetry_dashboard.json")

TAGS = [
    ("line1_conveyor_speed_mpm", "Line 1 Conveyor Speed", "m/min", "Assembly Line 1"),
    ("line1_vibration_mm_s", "Line 1 Vibration", "mm/s", "Assembly Line 1"),
    ("robot_arm_3_cycle_count", "Robot Arm 3 Cycle Count", "cycles", "Assembly Line 1"),
    ("station1_motor_rpm", "Station 1 Motor RPM", "rpm", "Assembly Line 1"),
    ("station1_part_count", "Station 1 Part Count", "parts", "Assembly Line 1"),
    ("station2_fault_count", "Station 2 Fault Count", "faults", "Welding Cell"),
    ("weld_arc_voltage_v", "Weld Arc Voltage", "V", "Welding Cell"),
    ("weld_cell_temperature_c", "Weld Cell Temperature", "degC", "Welding Cell"),
    ("weld_wire_feed_speed_mmin", "Weld Wire Feed Speed", "m/min", "Welding Cell"),
    ("packaging_rate_units_min", "Packaging Rate", "units/min", "Packaging Station"),
    ("pkg_reject_count", "Package Reject Count", "units", "Packaging Station"),
    ("pkg_seal_temp_c", "Package Seal Temperature", "degC", "Packaging Station"),
    ("air_pressure_bar", "Air Pressure", "bar", "Utilities"),
    ("cooling_water_temp_c", "Cooling Water Temperature", "degC", "Utilities"),
    ("plant_power_kw", "Plant Power", "kW", "Utilities"),
]


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Import the OPC UA telemetry dashboard into Grafana.")
    parser.add_argument("--grafana-url", default="http://127.0.0.1:3000")
    parser.add_argument("--username", default="admin")
    parser.add_argument("--password", default="admin")
    parser.add_argument("--historian-url", default="http://host.docker.internal:5001")
    return parser.parse_args()


def auth_headers(username: str, password: str) -> dict[str, str]:
    token = base64.b64encode(f"{username}:{password}".encode()).decode()
    return {"Authorization": f"Basic {token}", "Content-Type": "application/json"}


def http_json(base: str, headers: dict[str, str], path: str, method: str = "GET", payload: Any | None = None) -> Any:
    data = None if payload is None else json.dumps(payload).encode()
    req = request.Request(f"{base.rstrip('/')}{path}", data=data, headers=headers, method=method)
    with request.urlopen(req, timeout=30) as resp:
        raw = resp.read().decode()
        return json.loads(raw) if raw else {}


def ensure_datasource(base: str, headers: dict[str, str], historian_url: str) -> None:
    datasources = http_json(base, headers, "/api/datasources")
    existing = next((ds for ds in datasources if ds.get("uid") == DATASOURCE_UID), None)
    payload = {
        "uid": DATASOURCE_UID,
        "orgId": 1,
        "name": "Historian API",
        "type": DATASOURCE_TYPE,
        "access": "proxy",
        "url": historian_url,
        "basicAuth": False,
        "isDefault": False,
        "jsonData": {"auth_method": "none", "global_queries": []},
        "readOnly": False,
    }
    if existing:
        payload.update({"id": existing["id"], "version": existing.get("version", 1)})
        try:
            http_json(base, headers, f"/api/datasources/uid/{DATASOURCE_UID}", "PUT", payload)
        except error.HTTPError as exc:
            if exc.code != 409:
                raise
        return
    http_json(base, headers, "/api/datasources", "POST", payload)


def historian_query(tag: str, ref_id: str = "A") -> dict[str, Any]:
    return {
        "refId": ref_id,
        "datasource": {"type": DATASOURCE_TYPE, "uid": DATASOURCE_UID},
        "type": "json",
        "source": "url",
        "format": "timeseries",
        "url": f"/api/grafana/history?tag={tag}",
        "url_options": {"method": "GET", "data": ""},
        "parser": "backend",
        "root_selector": "",
        "columns": [
            {"selector": "timestamp", "text": "Time", "type": "timestamp"},
            {"selector": "value", "text": tag, "type": "number"},
        ],
    }


def stat_panel(panel_id: int, tag: str, title: str, unit: str, x: int, y: int) -> dict[str, Any]:
    return {
        "id": panel_id,
        "type": "stat",
        "title": title,
        "description": f"Latest historian value for {tag}. Unit: {unit}.",
        "gridPos": {"h": 4, "w": 6, "x": x, "y": y},
        "datasource": {"type": DATASOURCE_TYPE, "uid": DATASOURCE_UID},
        "targets": [historian_query(tag)],
        "fieldConfig": {
            "defaults": {
                "unit": "short",
                "decimals": 2,
                "mappings": [],
                "thresholds": {
                    "mode": "absolute",
                    "steps": [{"color": "green", "value": 0}, {"color": "orange", "value": 1}, {"color": "red", "value": 10}],
                },
            },
            "overrides": [],
        },
        "options": {
            "reduceOptions": {"values": False, "calcs": ["lastNotNull"], "fields": ""},
            "orientation": "auto",
            "textMode": "auto",
            "colorMode": "value",
            "graphMode": "area",
            "justifyMode": "center",
        },
    }


def timeseries_panel(panel_id: int, tag: str, title: str, unit: str, x: int, y: int, w: int = 8, h: int = 6) -> dict[str, Any]:
    return {
        "id": panel_id,
        "type": "timeseries",
        "title": f"{title} ({unit})",
        "description": f"OPC UA historian trend for {tag}. Sudden jumps or flat-lines are useful for MITM/write-manipulation discussion.",
        "gridPos": {"h": h, "w": w, "x": x, "y": y},
        "datasource": {"type": DATASOURCE_TYPE, "uid": DATASOURCE_UID},
        "targets": [historian_query(tag)],
        "fieldConfig": {
            "defaults": {
                "unit": "short",
                "custom": {
                    "drawStyle": "line",
                    "lineInterpolation": "smooth",
                    "lineWidth": 2,
                    "fillOpacity": 14,
                    "gradientMode": "opacity",
                    "showPoints": "never",
                    "spanNulls": False,
                },
            },
            "overrides": [],
        },
        "options": {
            "legend": {"displayMode": "list", "placement": "bottom", "showLegend": True},
            "tooltip": {"mode": "single", "sort": "none"},
        },
    }


def build_dashboard() -> dict[str, Any]:
    panels: list[dict[str, Any]] = [
        {
            "id": 1,
            "type": "text",
            "title": "Physics-Aware OPC UA Telemetry",
            "gridPos": {"h": 3, "w": 24, "x": 0, "y": 0},
            "options": {
                "mode": "markdown",
                "content": "Live historian trends for the 15 OPC UA process tags. Use this view during MITM/write-manipulation steps to show physical process values shifting, jumping, or freezing before the SOC dashboard summarizes detections.",
            },
        }
    ]

    focus = [
        ("weld_cell_temperature_c", "Weld Cell Temp", "degC"),
        ("weld_arc_voltage_v", "Weld Arc Voltage", "V"),
        ("line1_conveyor_speed_mpm", "Conveyor Speed", "m/min"),
        ("air_pressure_bar", "Air Pressure", "bar"),
    ]
    for idx, (tag, title, unit) in enumerate(focus):
        panels.append(stat_panel(10 + idx, tag, title, unit, idx * 6, 3))

    y = 7
    panel_id = 100
    for index, (tag, title, unit, _area) in enumerate(TAGS):
        x = (index % 3) * 8
        if index and index % 3 == 0:
            y += 6
        panels.append(timeseries_panel(panel_id, tag, title, unit, x, y))
        panel_id += 1

    return {
        "uid": "opcua-physics-telemetry",
        "title": "Physics-Aware OPC UA Telemetry",
        "tags": ["honeypot", "opcua", "historian", "physics", "telemetry"],
        "timezone": "browser",
        "schemaVersion": 41,
        "version": 1,
        "refresh": "5s",
        "time": {"from": "now-7d", "to": "now"},
        "templating": {"list": []},
        "panels": panels,
    }


def main() -> None:
    args = parse_args()
    headers = auth_headers(args.username, args.password)
    ensure_datasource(args.grafana_url, headers, args.historian_url)
    dashboard = build_dashboard()
    result = http_json(args.grafana_url, headers, "/api/dashboards/db", "POST", {"dashboard": dashboard, "folderId": 0, "overwrite": True})
    EXPORT_PATH.parent.mkdir(parents=True, exist_ok=True)
    EXPORT_PATH.write_text(json.dumps(dashboard, indent=2), encoding="utf-8")
    print(json.dumps({"imported": True, "uid": dashboard["uid"], "url": result.get("url")}, indent=2))


if __name__ == "__main__":
    main()
