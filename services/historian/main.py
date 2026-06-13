"""
Historian web portal — deception asset mimicking an industrial process historian.

Serves a FastAPI web application that presents as an OSIsoft PI Web API endpoint.
Process tag values are streamed in continuously from the OPC UA server via the
opcua_ingest.py background task and stored in a local SQLite database.

Deception design:
  - HTTP response headers impersonate Microsoft-IIS / PI Web API to increase
    realism and resist fingerprinting by generic web scanners.
  - Authentication uses weak default credentials (john / Cisco) that also appear
    in the SMB honey share, establishing the cross-layer credential-reuse lure.
  - All login attempts, API queries, and anomalous ingest values are emitted as
    structured events via event_logger.py for downstream Wazuh and Zeek detection.

Environment variables:
  DB_PATH              Path to the SQLite database  (default: historian.db)
  HISTORIAN_USERNAME   Login username               (default: john)
  HISTORIAN_PASSWORD   Login password               (default: Cisco)
  SERVER_BASE          Public base URL for link generation

Start via Docker Compose:
  docker compose -f compose/docker-compose.historian.yml up -d
"""

import base64
import os
import sqlite3
import time
import uuid
from collections import Counter

from fastapi import FastAPI, Form, Request
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse
from fastapi.templating import Jinja2Templates
from starlette.middleware.base import BaseHTTPMiddleware

from event_logger import emit_event

active_sessions: dict[str, dict[str, str]] = {}

app = FastAPI(docs_url=None, redoc_url=None, openapi_url=None)
templates = Jinja2Templates(directory="templates")


class IndustrialHeadersMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request, call_next):
        response = await call_next(request)
        response.headers["Server"] = "Microsoft-IIS/10.0"
        response.headers["X-Powered-By"] = "ASP.NET"
        response.headers["X-PIWebAPI-Version"] = "1.13.0.6518"
        response.headers["X-Frame-Options"] = "SAMEORIGIN"
        response.headers["X-Content-Type-Options"] = "nosniff"
        return response


app.add_middleware(IndustrialHeadersMiddleware)

DB_PATH = os.getenv("DB_PATH", "historian.db")
PI_SERVER_NAME = "PLANT-PI-01"
PI_SERVER_WEBID = "s0UbkMxHpJ0RGPlantPi01Server000"
AF_SERVER_WEBID = "s0AfServerPlantAF010000000000000"
SERVER_BASE = os.getenv("SERVER_BASE", "http://localhost:5000")

AUTH_USERNAME = os.getenv("HISTORIAN_USERNAME", "john")
AUTH_PASSWORD = os.getenv("HISTORIAN_PASSWORD", "Cisco")

CANONICAL_TAGS = [
    "line1_conveyor_speed_mpm",
    "station1_motor_rpm",
    "robot_arm_3_cycle_count",
    "line1_vibration_mm_s",
    "station1_part_count",
    "weld_cell_temperature_c",
    "weld_arc_voltage_v",
    "weld_wire_feed_speed_mmin",
    "station2_fault_count",
    "packaging_rate_units_min",
    "pkg_seal_temp_c",
    "pkg_reject_count",
    "air_pressure_bar",
    "plant_power_kw",
    "cooling_water_temp_c",
]

AREA_ORDER = ["Assembly Line 1", "Welding Cell", "Packaging Station", "Utilities"]


def get_db_connection():
    # Use timeout/busy_timeout to tolerate brief concurrent writes.
    conn = sqlite3.connect(DB_PATH, timeout=10)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA busy_timeout=10000")
    return conn


def client_ip(request: Request) -> str:
    return request.client.host if request.client else ""


def get_tag_webid(tag: str) -> str:
    b64 = base64.b64encode(f"{PI_SERVER_NAME}\\{tag}".encode()).decode().replace("=", "")
    return "F1DP" + b64[:28]


def get_session(request: Request):
    token = request.cookies.get("historian_session", "")
    return active_sessions.get(token)


def capture_basic_auth(request: Request) -> None:
    auth = request.headers.get("Authorization", "")
    if not auth.startswith("Basic "):
        return
    try:
        decoded = base64.b64decode(auth[6:]).decode("utf-8", errors="replace")
        username, _, password = decoded.partition(":")
        emit_event(
            event_type="basic_auth_capture",
            src_ip=client_ip(request),
            username=username,
            route=request.url.path,
            status="captured",
            user_agent=request.headers.get("User-Agent", ""),
            extra={"password": password},
        )
    except Exception:
        emit_event(
            event_type="basic_auth_capture",
            src_ip=client_ip(request),
            route=request.url.path,
            status="decode_error",
            user_agent=request.headers.get("User-Agent", ""),
        )


async def capture_submitted_credentials(request: Request) -> None:
    username = request.query_params.get("username", "")
    password = request.query_params.get("password", "")
    content_type = request.headers.get("content-type", "")

    if not username and not password and (
        "application/x-www-form-urlencoded" in content_type or "multipart/form-data" in content_type
    ):
        form_data = await request.form()
        username = str(form_data.get("username", ""))
        password = str(form_data.get("password", ""))

    if username or password:
        emit_event(
            event_type="credential_submission",
            src_ip=client_ip(request),
            username=username,
            route=request.url.path,
            status="captured",
            user_agent=request.headers.get("User-Agent", ""),
            extra={"password": password},
        )


@app.get("/")
def root_redirect():
    return RedirectResponse(url="/login", status_code=302)


@app.get("/login", response_class=HTMLResponse)
def login_get(request: Request):
    remembered_username = request.cookies.get("historian_last_user", "")
    return templates.TemplateResponse(
        request=request,
        name="login.html",
        context={
            "request": request,
            "error": request.query_params.get("error", ""),
            "remembered_username": remembered_username,
        },
    )


@app.post("/login")
async def login_post(
    request: Request,
    username: str = Form(""),
    password: str = Form(""),
):
    ts_iso = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
    ip = client_ip(request)
    user_agent = request.headers.get("User-Agent", "")
    username = (username or "").strip()
    password = (password or "").strip()
    has_credentials = bool(username and password)
    credentials_valid = has_credentials and username == AUTH_USERNAME and password == AUTH_PASSWORD
    status = "success" if credentials_valid else "failed"

    conn = get_db_connection()
    conn.execute(
        "INSERT INTO login_attempts (timestamp, src_ip, username, password, user_agent) VALUES (?,?,?,?,?)",
        (ts_iso, ip, username, password, user_agent),
    )
    conn.commit()
    conn.close()

    emit_event(
        event_type="login_attempt",
        src_ip=ip,
        username=username,
        route="/login",
        status=status,
        user_agent=user_agent,
    )

    if not has_credentials:
        return templates.TemplateResponse(
            request=request,
            name="login.html",
            context={"request": request, "error": "Username and password are required."},
            status_code=401,
        )
    if not credentials_valid:
        return templates.TemplateResponse(
            request=request,
            name="login.html",
            context={"request": request, "error": "Invalid username or password."},
            status_code=401,
        )

    token = str(uuid.uuid4())
    active_sessions[token] = {"username": username}
    resp = RedirectResponse(url="/portal", status_code=302)
    resp.set_cookie("historian_session", token, httponly=True, samesite="lax")
    # UI preference cookie to prefill username on next visit (not used for auth).
    resp.set_cookie("historian_last_user", username, max_age=60 * 60 * 24 * 30, samesite="lax")
    return resp


@app.get("/api")
def api_root(request: Request):
    emit_event(event_type="api_probe", src_ip=client_ip(request), route="/api", status="success")
    return {"service": "historian", "status": "running", "version": "3.4.440.2"}


@app.get("/api/grafana/latest")
def grafana_latest(request: Request):
    conn = get_db_connection()
    rows = conn.execute(
        """
        WITH latest AS (
            SELECT tag, MAX(id) AS max_id
            FROM telemetry
            GROUP BY tag
        )
        SELECT m.tag,
               t.value,
               t.timestamp,
               COALESCE(t.quality, 'n/a') AS quality,
               m.area,
               m.unit,
               m.equipment
        FROM tag_metadata m
        LEFT JOIN latest l ON l.tag = m.tag
        LEFT JOIN telemetry t ON t.id = l.max_id
        WHERE m.tag IN ({placeholders})
        ORDER BY CASE m.area
          WHEN 'Assembly Line 1' THEN 1
          WHEN 'Welding Cell' THEN 2
          WHEN 'Packaging Station' THEN 3
          WHEN 'Utilities' THEN 4
          ELSE 99 END,
          m.tag
        """.format(placeholders=",".join("?" for _ in CANONICAL_TAGS)),
        tuple(CANONICAL_TAGS),
    ).fetchall()
    conn.close()

    emit_event(
        event_type="grafana_latest",
        src_ip=client_ip(request),
        route="/api/grafana/latest",
        status="success",
        user_agent=request.headers.get("User-Agent", ""),
    )
    return [dict(r) for r in rows]


@app.get("/api/grafana/history")
def grafana_history(tag: str, request: Request):
    if tag not in CANONICAL_TAGS:
        emit_event(
            event_type="grafana_history",
            src_ip=client_ip(request),
            route="/api/grafana/history",
            tag=tag,
            status="not_found",
            user_agent=request.headers.get("User-Agent", ""),
        )
        return JSONResponse(status_code=404, content={"error": "tag not found"})

    try:
        conn = get_db_connection()
        rows = conn.execute(
            "SELECT timestamp, value, quality FROM telemetry WHERE tag = ? ORDER BY timestamp DESC LIMIT 2000",
            (tag,),
        ).fetchall()
        conn.close()
    except sqlite3.OperationalError:
        emit_event(
            event_type="grafana_history",
            src_ip=client_ip(request),
            route="/api/grafana/history",
            tag=tag,
            status="db_locked",
            user_agent=request.headers.get("User-Agent", ""),
        )
        return []

    emit_event(
        event_type="grafana_history",
        src_ip=client_ip(request),
        route="/api/grafana/history",
        tag=tag,
        status="success",
        user_agent=request.headers.get("User-Agent", ""),
    )
    return [dict(r) for r in rows]


@app.get("/tags")
def list_tags(request: Request):
    conn = get_db_connection()
    rows = conn.execute("SELECT tag FROM tag_metadata ORDER BY tag").fetchall()
    conn.close()
    emit_event(event_type="list_tags", src_ip=client_ip(request), route="/tags", status="success")
    return {"tags": [r["tag"] for r in rows]}


@app.get("/history")
def get_history(tag: str, request: Request):
    conn = get_db_connection()
    meta_row = conn.execute("SELECT tag FROM tag_metadata WHERE tag = ?", (tag,)).fetchone()
    if not meta_row:
        conn.close()
        emit_event(
            event_type="query_history",
            src_ip=client_ip(request),
            route="/history",
            tag=tag,
            status="not_found",
            user_agent=request.headers.get("User-Agent", ""),
        )
        return {"error": "tag not found"}

    rows = conn.execute(
        "SELECT timestamp, value, quality FROM telemetry WHERE tag = ? ORDER BY timestamp DESC LIMIT 200",
        (tag,),
    ).fetchall()
    conn.close()

    if not rows:
        emit_event(
            event_type="query_history",
            src_ip=client_ip(request),
            route="/history",
            tag=tag,
            status="not_found",
            user_agent=request.headers.get("User-Agent", ""),
        )
        return {"error": "tag not found"}

    emit_event(
        event_type="query_history",
        src_ip=client_ip(request),
        route="/history",
        tag=tag,
        status="success",
        user_agent=request.headers.get("User-Agent", ""),
    )
    return {"tag": tag, "values": [dict(r) for r in rows]}


@app.get("/piwebapi")
@app.get("/piwebapi/")
async def piwebapi_root(request: Request):
    capture_basic_auth(request)
    emit_event(event_type="pi_probe", src_ip=client_ip(request), route=request.url.path, status="success")
    return {
        "Links": {
            "Self": f"{SERVER_BASE}/piwebapi/",
            "DataServers": f"{SERVER_BASE}/piwebapi/dataservers",
            "AssetServers": f"{SERVER_BASE}/piwebapi/assetservers",
            "System": f"{SERVER_BASE}/piwebapi/system",
            "Home": f"{SERVER_BASE}/piwebapi/home",
        }
    }


@app.get("/piwebapi/system")
async def piwebapi_system(request: Request):
    capture_basic_auth(request)
    emit_event(event_type="pi_probe", src_ip=client_ip(request), route=request.url.path, status="success")
    return {
        "WebId": "sys0PlantPi01System00000000000000",
        "Id": "3e9b1e0a-a1b2-c3d4-e5f6-012345678901",
        "Name": "PI Web API 2023",
        "Version": "1.13.0.6518",
        "ProductTitle": "OSIsoft PI Web API 2023",
        "CrawlerPath": f"\\\\{PI_SERVER_NAME}",
        "Links": {"Self": f"{SERVER_BASE}/piwebapi/system"},
    }


@app.get("/piwebapi/dataservers")
async def piwebapi_dataservers(request: Request):
    capture_basic_auth(request)
    emit_event(event_type="pi_probe", src_ip=client_ip(request), route=request.url.path, status="success")
    return {
        "Items": [
            {
                "WebId": PI_SERVER_WEBID,
                "Id": "d1a2b3c4-5678-9012-abcd-ef0123456789",
                "Name": PI_SERVER_NAME,
                "Path": f"\\\\{PI_SERVER_NAME}",
                "IsConnected": True,
                "ServerVersion": "3.4.440.2",
                "ServerTime": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
                "TimeZone": "UTC",
                "Links": {
                    "Self": f"{SERVER_BASE}/piwebapi/dataservers/{PI_SERVER_WEBID}",
                    "Points": f"{SERVER_BASE}/piwebapi/dataservers/{PI_SERVER_WEBID}/points",
                },
            }
        ]
    }


@app.get("/piwebapi/assetservers")
async def piwebapi_assetservers(request: Request):
    capture_basic_auth(request)
    emit_event(event_type="pi_probe", src_ip=client_ip(request), route=request.url.path, status="success")
    return {
        "Items": [
            {
                "WebId": AF_SERVER_WEBID,
                "Id": "a1b2c3d4-1234-5678-abcd-ef0123456789",
                "Name": "PLANT-AF-01",
                "Path": "\\\\PLANT-AF-01",
                "IsConnected": True,
                "ServerVersion": "2.10.8.14046",
                "Links": {
                    "Self": f"{SERVER_BASE}/piwebapi/assetservers/{AF_SERVER_WEBID}",
                    "Databases": f"{SERVER_BASE}/piwebapi/assetservers/{AF_SERVER_WEBID}/assetdatabases",
                },
            }
        ]
    }


@app.get("/piwebapi/dataservers/{webid}/points")
async def piwebapi_points(request: Request, webid: str, nameFilter: str = "*", count: int = 100):
    capture_basic_auth(request)
    conn = get_db_connection()
    rows = conn.execute("SELECT * FROM tag_metadata ORDER BY tag LIMIT ?", (min(count, 200),)).fetchall()
    conn.close()

    items = []
    for row in rows:
        wid = row["webid"] or get_tag_webid(row["tag"])
        items.append(
            {
                "WebId": wid,
                "Id": str(uuid.uuid5(uuid.NAMESPACE_DNS, row["tag"])),
                "Name": row["tag"],
                "Path": row["pi_path"] or f"\\\\{PI_SERVER_NAME}\\{row['tag']}",
                "Descriptor": row["description"],
                "PointClass": "classic",
                "PointType": "Float32",
                "EngineeringUnits": row["unit"],
                "Step": False,
                "Links": {
                    "Self": f"{SERVER_BASE}/piwebapi/points/{wid}",
                    "RecordedData": f"{SERVER_BASE}/piwebapi/streams/{wid}/recorded",
                    "Value": f"{SERVER_BASE}/piwebapi/streams/{wid}/value",
                },
            }
        )

    emit_event(
        event_type="pi_points_query",
        src_ip=client_ip(request),
        route=request.url.path,
        status="success",
        user_agent=request.headers.get("User-Agent", ""),
        extra={"filter": nameFilter, "server_webid": webid},
    )
    return {"Items": items}


@app.get("/piwebapi/streams/{webid}/value")
async def piwebapi_stream_value(request: Request, webid: str):
    capture_basic_auth(request)
    conn = get_db_connection()
    row = conn.execute(
        "SELECT t.tag, t.timestamp, t.value, t.quality, m.unit "
        "FROM telemetry t JOIN tag_metadata m ON t.tag = m.tag "
        "WHERE m.webid = ? ORDER BY t.id DESC LIMIT 1",
        (webid,),
    ).fetchone()
    conn.close()

    if not row:
        emit_event(event_type="pi_stream_value", src_ip=client_ip(request), route=request.url.path, status="not_found")
        return JSONResponse(status_code=404, content={"Message": f"No point found with WebId: {webid}"})

    emit_event(
        event_type="pi_stream_value",
        src_ip=client_ip(request),
        route=request.url.path,
        tag=row["tag"],
        status="success",
        user_agent=request.headers.get("User-Agent", ""),
    )
    return {
        "Timestamp": row["timestamp"],
        "Value": row["value"],
        "UnitsAbbreviation": row["unit"],
        "Good": row["quality"] == "Good",
        "Questionable": row["quality"] == "Uncertain",
        "Substituted": False,
    }


@app.get("/piwebapi/streams/{webid}/recorded")
async def piwebapi_stream_recorded(request: Request, webid: str, count: int = 100):
    capture_basic_auth(request)
    conn = get_db_connection()
    tag_row = conn.execute("SELECT tag FROM tag_metadata WHERE webid = ?", (webid,)).fetchone()

    if not tag_row:
        conn.close()
        emit_event(event_type="pi_stream_recorded", src_ip=client_ip(request), route=request.url.path, status="not_found")
        return JSONResponse(status_code=404, content={"Message": "No point found with WebId: " + webid})

    rows = conn.execute(
        "SELECT timestamp, value, quality FROM telemetry WHERE tag = ? ORDER BY timestamp DESC LIMIT ?",
        (tag_row["tag"], min(count, 200)),
    ).fetchall()
    conn.close()

    emit_event(
        event_type="pi_stream_recorded",
        src_ip=client_ip(request),
        route=request.url.path,
        tag=tag_row["tag"],
        status="success",
        user_agent=request.headers.get("User-Agent", ""),
    )
    return {
        "Items": [
            {
                "Timestamp": r["timestamp"],
                "Value": r["value"],
                "Good": r["quality"] == "Good",
                "Questionable": r["quality"] == "Uncertain",
                "Substituted": False,
            }
            for r in rows
        ]
    }


@app.get("/piwebapi/home")
async def piwebapi_home(request: Request):
    capture_basic_auth(request)
    emit_event(event_type="pi_probe", src_ip=client_ip(request), route=request.url.path, status="unauthorized")
    return JSONResponse(
        status_code=401,
        content={
            "Message": "Authorization has been denied for this request.",
            "Errors": [{"Message": "Authorization has been denied for this request."}],
        },
    )


@app.get("/admin")
@app.post("/admin")
async def decoy_admin(request: Request):
    capture_basic_auth(request)
    await capture_submitted_credentials(request)
    emit_event(
        event_type="decoy_probe",
        src_ip=client_ip(request),
        route=request.url.path,
        status="blocked",
        user_agent=request.headers.get("User-Agent", ""),
    )
    return JSONResponse(
        status_code=403,
        content={
            "error": "Access denied",
            "message": "Administrator access requires MFA. Contact IT Security (ext. 4400).",
        },
    )


@app.get("/config")
async def decoy_config(request: Request):
    capture_basic_auth(request)
    await capture_submitted_credentials(request)
    emit_event(
        event_type="decoy_probe",
        src_ip=client_ip(request),
        route=request.url.path,
        status="unauthorized",
        user_agent=request.headers.get("User-Agent", ""),
    )
    return JSONResponse(status_code=401, content={"error": "Unauthorized", "message": "Authentication required."})


@app.get("/management")
async def decoy_management(request: Request):
    capture_basic_auth(request)
    await capture_submitted_credentials(request)
    emit_event(
        event_type="decoy_probe",
        src_ip=client_ip(request),
        route=request.url.path,
        status="blocked",
        user_agent=request.headers.get("User-Agent", ""),
    )
    return JSONResponse(status_code=403, content={"error": "Access denied"})


@app.get("/portal", response_class=HTMLResponse)
def portal_home(request: Request):
    session = get_session(request)
    if not session:
        return RedirectResponse(url="/login", status_code=302)
    emit_event(
        event_type="portal_visit",
        src_ip=client_ip(request),
        username=session.get("username", ""),
        route=request.url.path,
        status="success",
        user_agent=request.headers.get("User-Agent", ""),
    )
    return templates.TemplateResponse(request=request, name="index.html", context={"request": request})


@app.get("/portal/tags", response_class=HTMLResponse)
def portal_tags(request: Request):
    session = get_session(request)
    if not session:
        return RedirectResponse(url="/login", status_code=302)

    conn = get_db_connection()
    rows = conn.execute(
        "SELECT tag, unit, area, description, equipment, status "
        "FROM tag_metadata "
        "ORDER BY CASE area "
        "  WHEN 'Assembly Line 1' THEN 1 "
        "  WHEN 'Welding Cell' THEN 2 "
        "  WHEN 'Packaging Station' THEN 3 "
        "  WHEN 'Utilities' THEN 4 "
        "  ELSE 99 END, tag"
    ).fetchall()
    conn.close()

    areas: dict = {}
    for row in rows:
        row_dict = dict(row)
        areas.setdefault(row_dict["area"], []).append(row_dict)

    emit_event(
        event_type="portal_tags",
        src_ip=client_ip(request),
        username=session.get("username", ""),
        route=request.url.path,
        status="success",
        user_agent=request.headers.get("User-Agent", ""),
    )
    return templates.TemplateResponse(request=request, name="tags.html", context={"request": request, "areas": areas})


@app.get("/portal/history/live")
def portal_history_live(request: Request, tag: str, since: str = ""):
    session = get_session(request)
    if not session:
        return JSONResponse(status_code=401, content={"error": "unauthorized"})

    try:
        conn = get_db_connection()
        if since:
            rows = conn.execute(
                "SELECT timestamp, value, quality FROM telemetry "
                "WHERE tag = ? AND timestamp > ? ORDER BY timestamp DESC LIMIT 50",
                (tag, since),
            ).fetchall()
        else:
            rows = conn.execute(
                "SELECT timestamp, value, quality FROM telemetry WHERE tag = ? ORDER BY timestamp DESC LIMIT 1",
                (tag,),
            ).fetchall()
        conn.close()
    except sqlite3.OperationalError:
        emit_event(
            event_type="portal_live_poll",
            src_ip=client_ip(request),
            username=session.get("username", ""),
            route=request.url.path,
            tag=tag,
            status="db_locked",
            user_agent=request.headers.get("User-Agent", ""),
        )
        return JSONResponse(content={"rows": []})

    emit_event(
        event_type="portal_live_poll",
        src_ip=client_ip(request),
        username=session.get("username", ""),
        route=request.url.path,
        tag=tag,
        status="success",
        user_agent=request.headers.get("User-Agent", ""),
    )
    return JSONResponse(content={"rows": [dict(r) for r in rows]})


@app.get("/portal/history", response_class=HTMLResponse)
def portal_history(request: Request, tag: str | None = None):
    session = get_session(request)
    if not session:
        return RedirectResponse(url="/login", status_code=302)

    values = None
    error = None
    meta = None
    status = "success"

    if tag:
        conn = get_db_connection()
        meta_row = conn.execute("SELECT * FROM tag_metadata WHERE tag = ?", (tag,)).fetchone()
        if not meta_row:
            conn.close()
            error = "Tag not found in canonical 15-tag model."
            status = "not_found"
            emit_event(
                event_type="portal_history_query",
                src_ip=client_ip(request),
                username=session.get("username", ""),
                route=request.url.path,
                tag=tag,
                status=status,
                user_agent=request.headers.get("User-Agent", ""),
            )
            return templates.TemplateResponse(
                request=request,
                name="history.html",
                context={"request": request, "tag": tag, "values": None, "error": error, "meta": None},
            )

        rows = conn.execute(
            "SELECT timestamp, value, quality FROM telemetry WHERE tag = ? ORDER BY timestamp DESC LIMIT 200",
            (tag,),
        ).fetchall()
        conn.close()

        meta = dict(meta_row)

        if not rows:
            error = "No history yet for this tag."
            status = "not_found"
        else:
            values = [dict(r) for r in rows]
    else:
        status = "empty_query"

    emit_event(
        event_type="portal_history_query",
        src_ip=client_ip(request),
        username=session.get("username", ""),
        route=request.url.path,
        tag=tag or "",
        status=status,
        user_agent=request.headers.get("User-Agent", ""),
    )
    return templates.TemplateResponse(
        request=request,
        name="history.html",
        context={"request": request, "tag": tag, "values": values, "error": error, "meta": meta},
    )


@app.get("/portal/overview", response_class=HTMLResponse)
def portal_overview(request: Request):
    session = get_session(request)
    if not session:
        return RedirectResponse(url="/login", status_code=302)

    conn = get_db_connection()
    total_tags = conn.execute("SELECT COUNT(*) FROM tag_metadata").fetchone()[0]
    total_rows = conn.execute("SELECT COUNT(*) FROM telemetry").fetchone()[0]
    latest = conn.execute(
        """
        WITH latest AS (
            SELECT tag, MAX(id) AS max_id
            FROM telemetry
            GROUP BY tag
        )
        SELECT m.tag,
               t.timestamp,
               t.value,
               COALESCE(t.quality, 'Good') AS quality,
               m.unit,
               m.area,
               m.description,
               m.equipment,
               m.status
        FROM tag_metadata m
        LEFT JOIN latest l ON l.tag = m.tag
        LEFT JOIN telemetry t ON t.id = l.max_id
        ORDER BY CASE m.area
          WHEN 'Assembly Line 1' THEN 1
          WHEN 'Welding Cell' THEN 2
          WHEN 'Packaging Station' THEN 3
          WHEN 'Utilities' THEN 4
          ELSE 99 END,
          m.tag
        """
    ).fetchall()
    conn.close()

    areas: dict = {}
    area_counter: Counter = Counter()
    for row in latest:
        row_dict = dict(row)
        if row_dict.get("timestamp") is None:
            row_dict["timestamp"] = "n/a"
        if row_dict.get("value") is None:
            row_dict["value"] = "n/a"
        if row_dict.get("quality") is None:
            row_dict["quality"] = "n/a"
        areas.setdefault(row_dict["area"], []).append(row_dict)
        area_counter[row_dict["area"]] += 1

    area_counts = []
    for area in AREA_ORDER:
        if area in area_counter:
            area_counts.append({"area": area, "tag_count": area_counter[area]})

    from datetime import datetime, timezone

    refreshed_at = datetime.now(tz=timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
    emit_event(
        event_type="portal_overview",
        src_ip=client_ip(request),
        username=session.get("username", ""),
        route=request.url.path,
        status="success",
        user_agent=request.headers.get("User-Agent", ""),
    )
    return templates.TemplateResponse(
        request=request,
        name="overview.html",
        context={
            "request": request,
            "total_tags": total_tags,
            "total_rows": total_rows,
            "area_counts": [dict(r) for r in area_counts],
            "areas": areas,
            "refreshed_at": refreshed_at,
        },
    )
