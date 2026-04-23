from __future__ import annotations

import argparse
import base64
import json
import time
from pathlib import Path
from typing import Any
from urllib import error, request


DEFAULT_DASHBOARD = "monitoring/grafana/soc_honeypot_detection_dashboard_ml.json"


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Import the SOC Grafana dashboard and point it at Loki.")
    parser.add_argument("--grafana-url", default="http://127.0.0.1:3000")
    parser.add_argument("--username", default="admin")
    parser.add_argument("--password", default="admin")
    parser.add_argument("--dashboard", default=DEFAULT_DASHBOARD)
    parser.add_argument("--loki-url", default="http://host.docker.internal:3100")
    parser.add_argument("--wait-seconds", type=int, default=60)
    return parser.parse_args()


def auth_headers(username: str, password: str) -> dict[str, str]:
    token = base64.b64encode(f"{username}:{password}".encode()).decode()
    return {"Authorization": f"Basic {token}", "Content-Type": "application/json"}


def http_json(base: str, path: str, headers: dict[str, str], method: str = "GET", payload: Any | None = None) -> Any:
    data = None if payload is None else json.dumps(payload).encode()
    req = request.Request(f"{base.rstrip('/')}{path}", data=data, headers=headers, method=method)
    with request.urlopen(req, timeout=20) as resp:
        raw = resp.read().decode()
        return json.loads(raw) if raw else {}


def wait_for_grafana(base: str, headers: dict[str, str], wait_seconds: int) -> None:
    deadline = time.time() + wait_seconds
    last_error: Exception | None = None
    while time.time() < deadline:
        try:
            http_json(base, "/api/health", headers)
            return
        except Exception as exc:  # Grafana resets connections while booting.
            last_error = exc
            time.sleep(2)
    raise SystemExit(f"Grafana did not become ready within {wait_seconds}s: {last_error}")


def ensure_loki_datasource(base: str, headers: dict[str, str], loki_url: str) -> str:
    datasources = http_json(base, "/api/datasources", headers)
    loki = next((ds for ds in datasources if ds.get("name") == "Loki" or ds.get("type") == "loki"), None)
    if loki:
        uid = str(loki["uid"])
        payload = {
            "id": loki["id"],
            "uid": uid,
            "orgId": 1,
            "name": "Loki",
            "type": "loki",
            "access": "proxy",
            "url": loki_url,
            "basicAuth": False,
            "isDefault": True,
            "jsonData": loki.get("jsonData") or {},
            "version": loki.get("version", 1),
            "readOnly": False,
        }
        try:
            http_json(base, f"/api/datasources/uid/{uid}", headers, "PUT", payload)
        except error.HTTPError as exc:
            if exc.code != 409:
                raise
        return uid

    payload = {
        "name": "Loki",
        "type": "loki",
        "access": "proxy",
        "url": loki_url,
        "basicAuth": False,
        "isDefault": True,
        "jsonData": {},
    }
    created = http_json(base, "/api/datasources", headers, "POST", payload)
    return str(created.get("datasource", {}).get("uid") or created.get("uid"))


def replace_loki_uid(value: Any, loki_uid: str) -> None:
    if isinstance(value, dict):
        datasource = value.get("datasource")
        if isinstance(datasource, dict) and datasource.get("type") == "loki":
            datasource["uid"] = loki_uid
        for child in value.values():
            replace_loki_uid(child, loki_uid)
    elif isinstance(value, list):
        for child in value:
            replace_loki_uid(child, loki_uid)


def main() -> None:
    args = parse_args()
    headers = auth_headers(args.username, args.password)
    wait_for_grafana(args.grafana_url, headers, args.wait_seconds)
    loki_uid = ensure_loki_datasource(args.grafana_url, headers, args.loki_url)

    dashboard = json.loads(Path(args.dashboard).read_text(encoding="utf-8"))
    dashboard["id"] = None
    replace_loki_uid(dashboard, loki_uid)
    result = http_json(
        args.grafana_url,
        "/api/dashboards/db",
        headers,
        "POST",
        {"dashboard": dashboard, "folderId": 0, "overwrite": True},
    )
    print(json.dumps({"imported": True, "dashboard_uid": dashboard.get("uid"), "datasource_uid": loki_uid, "result": result}, indent=2))


if __name__ == "__main__":
    try:
        main()
    except error.HTTPError as exc:
        detail = exc.read().decode(errors="replace")
        raise SystemExit(f"Grafana API error {exc.code}: {detail}") from exc
