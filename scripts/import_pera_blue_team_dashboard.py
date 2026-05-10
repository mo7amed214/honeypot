from __future__ import annotations

import argparse
import base64
import json
import time
from pathlib import Path
from typing import Any
from urllib import error, request


REPO_ROOT = Path(__file__).resolve().parents[2]
DEFAULT_DASHBOARD_CANDIDATES = [
    REPO_ROOT / "PERA-integration-ready-" / "blue_team" / "grafana" / "dashboards" / "blue_team_ti_console.json",
    Path("/opt/pera/blue_team/grafana/dashboards/blue_team_ti_console.json"),
    Path("../PERA-integration-ready-/blue_team/grafana/dashboards/blue_team_ti_console.json"),
    Path("../pera/blue_team/grafana/dashboards/blue_team_ti_console.json"),
]
DEFAULT_INFLUX_URL = "http://172.30.70.10:8086"
DEFAULT_INFLUX_TOKEN = "bt-supersecret-token-change-me"
DATASOURCE_NAME = "InfluxDB"
DATASOURCE_UID = "influxdb-honeypot"


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Import the PERA Blue Team Grafana dashboard into this Grafana instance."
    )
    parser.add_argument("--grafana-url", default="http://127.0.0.1:3000")
    parser.add_argument("--username", default="admin")
    parser.add_argument("--password", default="admin")
    parser.add_argument("--dashboard", default="")
    parser.add_argument("--influx-url", default=DEFAULT_INFLUX_URL)
    parser.add_argument("--influx-org", default="thesis")
    parser.add_argument("--influx-bucket", default="honeypot")
    parser.add_argument("--influx-token", default=DEFAULT_INFLUX_TOKEN)
    parser.add_argument("--wait-seconds", type=int, default=60)
    return parser.parse_args()


def auth_headers(username: str, password: str) -> dict[str, str]:
    token = base64.b64encode(f"{username}:{password}".encode()).decode()
    return {"Authorization": f"Basic {token}", "Content-Type": "application/json"}


def http_json(
    base: str,
    path: str,
    headers: dict[str, str],
    method: str = "GET",
    payload: Any | None = None,
) -> Any:
    data = None if payload is None else json.dumps(payload).encode()
    req = request.Request(f"{base.rstrip('/')}{path}", data=data, headers=headers, method=method)
    with request.urlopen(req, timeout=30) as resp:
        raw = resp.read().decode()
        return json.loads(raw) if raw else {}


def wait_for_grafana(base: str, headers: dict[str, str], wait_seconds: int) -> None:
    deadline = time.time() + wait_seconds
    last_error: Exception | None = None
    while time.time() < deadline:
        try:
            http_json(base, "/api/health", headers)
            return
        except Exception as exc:
            last_error = exc
            time.sleep(2)
    raise SystemExit(f"Grafana did not become ready within {wait_seconds}s: {last_error}")


def datasource_payload(
    args: argparse.Namespace,
    uid: str,
    existing: dict[str, Any] | None = None,
) -> dict[str, Any]:
    payload: dict[str, Any] = {
        "uid": uid,
        "orgId": 1,
        "name": DATASOURCE_NAME,
        "type": "influxdb",
        "access": "proxy",
        "url": args.influx_url,
        "basicAuth": False,
        "isDefault": False,
        "jsonData": {
            "version": "Flux",
            "organization": args.influx_org,
            "defaultBucket": args.influx_bucket,
            "tlsSkipVerify": True,
        },
        "secureJsonData": {"token": args.influx_token},
        "readOnly": False,
    }
    if existing:
        payload["id"] = existing["id"]
        payload["version"] = existing.get("version", 1)
    return payload


def ensure_influx_datasource(base: str, headers: dict[str, str], args: argparse.Namespace) -> str:
    datasources = http_json(base, "/api/datasources", headers)
    existing = next(
        (
            ds
            for ds in datasources
            if ds.get("uid") == DATASOURCE_UID
            or (ds.get("name") == DATASOURCE_NAME and ds.get("type") == "influxdb")
        ),
        None,
    )
    if existing:
        uid = str(existing["uid"])
        payload = datasource_payload(args, uid, existing)
        try:
            http_json(base, f"/api/datasources/uid/{uid}", headers, "PUT", payload)
        except error.HTTPError as exc:
            if exc.code != 409:
                raise
        return uid

    http_json(base, "/api/datasources", headers, "POST", datasource_payload(args, DATASOURCE_UID))
    return DATASOURCE_UID


def replace_influx_uid(value: Any, datasource_uid: str) -> None:
    if isinstance(value, dict):
        datasource = value.get("datasource")
        if isinstance(datasource, dict) and datasource.get("type") == "influxdb":
            datasource["uid"] = datasource_uid
        for child in value.values():
            replace_influx_uid(child, datasource_uid)
    elif isinstance(value, list):
        for child in value:
            replace_influx_uid(child, datasource_uid)


def main() -> None:
    args = parse_args()
    dashboard_path = Path(args.dashboard) if args.dashboard else next(
        (candidate for candidate in DEFAULT_DASHBOARD_CANDIDATES if candidate.exists()),
        DEFAULT_DASHBOARD_CANDIDATES[0],
    )
    if not dashboard_path.exists():
        raise SystemExit(f"Dashboard JSON not found: {dashboard_path}")

    headers = auth_headers(args.username, args.password)
    wait_for_grafana(args.grafana_url, headers, args.wait_seconds)
    datasource_uid = ensure_influx_datasource(args.grafana_url, headers, args)

    dashboard = json.loads(dashboard_path.read_text(encoding="utf-8"))
    dashboard["id"] = None
    replace_influx_uid(dashboard, datasource_uid)
    result = http_json(
        args.grafana_url,
        "/api/dashboards/db",
        headers,
        "POST",
        {"dashboard": dashboard, "folderId": 0, "overwrite": True},
    )
    print(
        json.dumps(
            {
                "imported": True,
                "dashboard_uid": dashboard.get("uid"),
                "datasource_uid": datasource_uid,
                "influx_url": args.influx_url,
                "url": result.get("url"),
            },
            indent=2,
        )
    )


if __name__ == "__main__":
    try:
        main()
    except error.HTTPError as exc:
        detail = exc.read().decode(errors="replace")
        raise SystemExit(f"Grafana API error {exc.code}: {detail}") from exc
