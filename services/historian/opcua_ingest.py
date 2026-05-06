import asyncio
import json
import os
import random
import sqlite3
import urllib.request
from datetime import datetime, timezone
from typing import Dict, Optional, Tuple
from urllib.parse import urlparse

try:
    from asyncua import Client
except ModuleNotFoundError as exc:
    raise SystemExit(
        "Missing Python dependency 'asyncua'. Install services/historian/requirements.txt or run via docker compose."
    ) from exc

from event_logger import emit_event

DB_PATH = os.getenv("DB_PATH", "historian.db")
SCADA_L2_URL = os.getenv("SCADA_L2_URL", "")
OPCUA_URL = os.getenv("OPCUA_URL", "opc.tcp://localhost:4840")
NAMESPACE = os.getenv("NAMESPACE", "http://manufacturing.example/opcua")
POLL_INTERVAL_SECONDS = float(os.getenv("POLL_INTERVAL_SECONDS", "3.0"))
TAGS = {
    "line1_conveyor_speed_mpm": {"path": "line1_conveyor_speed_mpm", "min": 0.0, "max": 30.0, "max_step": 4.0},
    "station1_motor_rpm": {"path": "station1_motor_rpm", "min": 0.0, "max": 1520.0, "max_step": 60.0},
    "robot_arm_3_cycle_count": {"path": "robot_arm_3_cycle_count", "min": 0.0, "max": 1e7, "max_step": 100.0},
    "line1_vibration_mm_s": {"path": "line1_vibration_mm_s", "min": 0.0, "max": 2.5, "max_step": 0.5},
    "station1_part_count": {"path": "station1_part_count", "min": 0.0, "max": 1e7, "max_step": 20.0},
    "weld_cell_temperature_c": {"path": "weld_cell_temperature_c", "min": 40.0, "max": 120.0, "max_step": 6.0},
    "weld_arc_voltage_v": {"path": "weld_arc_voltage_v", "min": 18.0, "max": 30.0, "max_step": 2.0},
    "weld_wire_feed_speed_mmin": {"path": "weld_wire_feed_speed_mmin", "min": 0.0, "max": 8.0, "max_step": 1.0},
    "station2_fault_count": {"path": "station2_fault_count", "min": 0.0, "max": 9999.0, "max_step": 10.0},
    "packaging_rate_units_min": {"path": "packaging_rate_units_min", "min": 0.0, "max": 80.0, "max_step": 5.0},
    "pkg_seal_temp_c": {"path": "pkg_seal_temp_c", "min": 160.0, "max": 200.0, "max_step": 3.0},
    "pkg_reject_count": {"path": "pkg_reject_count", "min": 0.0, "max": 9999.0, "max_step": 10.0},
    "air_pressure_bar": {"path": "air_pressure_bar", "min": 4.5, "max": 7.5, "max_step": 0.5},
    "plant_power_kw": {"path": "plant_power_kw", "min": 80.0, "max": 280.0, "max_step": 20.0},
    "cooling_water_temp_c": {"path": "cooling_water_temp_c", "min": 10.0, "max": 40.0, "max_step": 2.0},
}


# PERA Level 2 physics keys → Level 3 historian tag names
L2_TAG_MAP: Dict[str, str] = {
    "node04_measured_rpm":    "line1_conveyor_speed_mpm",
    "node06_measured_temp":   "weld_cell_temperature_c",
    "node08_measured_pressure": "air_pressure_bar",
    "node09_measured_level":  "weld_wire_feed_speed_mmin",
    "node10_defect_prob":     "pkg_reject_count",
    "node15_ambient_temp":    "cooling_water_temp_c",
}


def _http_get_json(url: str) -> dict:
    with urllib.request.urlopen(url, timeout=5) as resp:
        return json.loads(resp.read())


def _get_latest_opcua(conn: sqlite3.Connection, tag: str) -> Optional[float]:
    row = conn.execute(
        "SELECT value FROM telemetry WHERE tag=? AND source='OPCUA' ORDER BY id DESC LIMIT 1",
        (tag,),
    ).fetchone()
    return float(row[0]) if row else None


async def scada_l2_poll(conn: sqlite3.Connection) -> None:
    if not SCADA_L2_URL:
        return
    data_url = f"{SCADA_L2_URL}/api/data"
    print(f"[l2_poll] starting → {data_url}")
    emit_event(
        event_type="l2_poll_start",
        src_ip=SCADA_L2_URL,
        route="scada_l2_poll",
        status="starting",
        extra={"url": data_url},
    )
    while True:
        try:
            data = await asyncio.to_thread(_http_get_json, data_url)
            ts = utc_now_iso()
            rows = []
            for l2_key, l3_tag in L2_TAG_MAP.items():
                raw = data.get(l2_key)
                if raw is None:
                    continue
                value = float(raw)
                rows.append((l3_tag, ts, value, "Good", "SCADA_L2"))
                opcua_val = _get_latest_opcua(conn, l3_tag)
                if opcua_val is not None and opcua_val != 0.0:
                    deviation = abs(value - opcua_val) / abs(opcua_val)
                    if deviation > 0.20:
                        emit_event(
                            event_type="cross_level_mismatch",
                            route="scada_l2_poll",
                            tag=l3_tag,
                            status="medium",
                            extra={
                                "l2_value": round(value, 4),
                                "opcua_value": round(opcua_val, 4),
                                "deviation_pct": round(deviation * 100, 1),
                                "l2_key": l2_key,
                            },
                        )
            if rows:
                write_batch(conn, rows)
            print(f"[l2_poll] {ts} wrote {len(rows)} tags from SCADA L2")
        except Exception as exc:
            print(f"[l2_poll] error: {exc}")
            emit_event(
                event_type="l2_poll_error",
                route="scada_l2_poll",
                status="error",
                extra={"error": str(exc), "url": data_url},
            )
        await asyncio.sleep(5.0)


def opcua_target_host(url: str) -> str:
    parsed = urlparse(url)
    if parsed.hostname:
        return parsed.hostname
    # Fallback for malformed values that still resemble host:port
    if "://" in url:
        tail = url.split("://", 1)[1]
        return tail.split(":", 1)[0].split("/", 1)[0]
    return ""


def utc_now_iso() -> str:
    return datetime.now(tz=timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def ensure_schema(conn: sqlite3.Connection):
    cursor = conn.cursor()
    cursor.execute(
        """
        CREATE TABLE IF NOT EXISTS telemetry (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            tag TEXT NOT NULL,
            timestamp TEXT NOT NULL,
            value REAL NOT NULL,
            quality TEXT NOT NULL DEFAULT 'Good',
            source TEXT NOT NULL DEFAULT 'OPCUA'
        )
        """
    )
    columns = {row[1] for row in cursor.execute("PRAGMA table_info(telemetry)").fetchall()}
    if "quality" not in columns:
        cursor.execute("ALTER TABLE telemetry ADD COLUMN quality TEXT NOT NULL DEFAULT 'Good'")
    if "source" not in columns:
        cursor.execute("ALTER TABLE telemetry ADD COLUMN source TEXT NOT NULL DEFAULT 'OPCUA'")
    conn.commit()


def assess_quality(tag: str, value: float, previous: Optional[float]) -> str:
    cfg = TAGS[tag]
    if value < cfg["min"] or value > cfg["max"]:
        return "Bad"
    if previous is not None and abs(value - previous) > cfg["max_step"]:
        return "Uncertain"
    return "Good"


def process_state(current: Dict[str, float], previous: Dict[str, float]) -> str:
    speed = current["line1_conveyor_speed_mpm"]
    cycles = current["robot_arm_3_cycle_count"]
    prev_cycles = previous.get("robot_arm_3_cycle_count", cycles)
    if speed < 0.5 and cycles <= prev_cycles:
        return "IDLE"
    if speed > 0.5 and cycles > prev_cycles:
        return "RUNNING"
    return "TRANSITION"


def detect_mitm_signals(
    current: Dict[str, float],
    previous: Dict[str, float],
    unchanged_counts: Dict[str, int],
) -> Optional[Tuple[str, str, str, dict]]:
    speed = current["line1_conveyor_speed_mpm"]
    prev_speed = previous.get("line1_conveyor_speed_mpm", speed)
    temp = current["weld_cell_temperature_c"]
    prev_temp = previous.get("weld_cell_temperature_c", temp)
    cycles = current["robot_arm_3_cycle_count"]
    prev_cycles = previous.get("robot_arm_3_cycle_count", cycles)

    # The physics model restarts line speed from 0.0 to a stable floor
    # near 12.5 m/min, which should not be treated as tampering.
    is_expected_legacy_restart = (
        prev_speed < 0.5
        and speed >= 11.5
        and cycles > prev_cycles
    )

    if abs(speed - prev_speed) > 6.5 and not is_expected_legacy_restart:
        return (
            "opcua_payload_step",
            "high",
            "Conveyor speed changed faster than process physics envelope",
            {"prev": prev_speed, "curr": speed, "delta": round(speed - prev_speed, 3)},
        )

    if speed > 0.8 and unchanged_counts.get("weld_cell_temperature_c", 0) >= 5:
        return (
            "stuck_value_pattern",
            "medium",
            "Temperature remained static while line appears active",
            {"temperature": temp, "streak": unchanged_counts["weld_cell_temperature_c"]},
        )

    if speed > 1.1 and cycles <= prev_cycles and abs(temp - prev_temp) > 0.6:
        return (
            "cross_signal_mismatch",
            "high",
            "Conveyor is moving but count did not advance",
            {
                "speed": speed,
                "cycles_prev": prev_cycles,
                "cycles_curr": cycles,
                "temp_delta": round(temp - prev_temp, 3),
            },
        )

    return None


def write_batch(conn: sqlite3.Connection, rows: list[tuple]):
    conn.execute("BEGIN")
    conn.executemany("INSERT INTO telemetry (tag, timestamp, value, quality, source) VALUES (?,?,?,?,?)", rows)
    conn.commit()


async def main():
    target_host = opcua_target_host(OPCUA_URL)
    print(f"[ingest] connecting to {OPCUA_URL}")
    print(f"[ingest] profile=canonical15 namespace={NAMESPACE}")
    print(f"[ingest] DB_PATH={DB_PATH} tags={len(TAGS)}")
    emit_event(
        event_type="ingest_start",
        src_ip=target_host,
        route="opcua_ingest",
        status="starting",
        extra={"target_endpoint": OPCUA_URL},
    )

    conn = sqlite3.connect(DB_PATH, timeout=10)
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA busy_timeout=10000")
    ensure_schema(conn)

    previous_values: Dict[str, float] = {}
    unchanged_counts: Dict[str, int] = {tag: 0 for tag in TAGS}
    poll_count = 0
    retry_delay = 2.0

    while True:
        try:
            async with Client(url=OPCUA_URL) as client:
                nsidx = await client.get_namespace_index(NAMESPACE)
                node_map = {
                    tag: await client.nodes.root.get_child(["0:Objects", f"{nsidx}:AssemblyLine", f"{nsidx}:{cfg['path']}"])
                    for tag, cfg in TAGS.items()
                }
                print(f"[ingest] connected - {len(node_map)} tags mapped")
                emit_event(
                    event_type="ingest_connection",
                    src_ip=target_host,
                    route="opcua_ingest",
                    status="connected",
                    extra={"target_endpoint": OPCUA_URL},
                )
                retry_delay = 2.0

                while True:
                    poll_count += 1
                    ts = utc_now_iso()
                    current_values: Dict[str, float] = {}
                    rows = []

                    for tag, node in node_map.items():
                        value = float(await node.read_value())
                        current_values[tag] = value
                        previous_value = previous_values.get(tag)
                        if previous_value is not None and value == previous_value:
                            unchanged_counts[tag] = unchanged_counts.get(tag, 0) + 1
                        else:
                            unchanged_counts[tag] = 0

                        quality = assess_quality(tag, value, previous_value)
                        rows.append((tag, ts, value, quality, "OPCUA"))

                    state = process_state(current_values, previous_values)
                    signal = detect_mitm_signals(current_values, previous_values, unchanged_counts)
                    write_batch(conn, rows)

                    event_msg = ""
                    if signal:
                        detector, severity, _, details = signal
                        emit_event(
                            event_type="ingest_anomaly",
                            route="opcua_ingest",
                            tag="line1_conveyor_speed_mpm",
                            status=severity,
                            extra={"detector": detector, **details},
                        )
                        event_msg = f" | alert={detector} severity={severity}"

                    speed_val = current_values["line1_conveyor_speed_mpm"]
                    temp_val = current_values["weld_cell_temperature_c"]
                    cycles_val = current_values["robot_arm_3_cycle_count"]

                    print(
                        f"[{ts}] poll={poll_count} state={state} speed={speed_val:.2f} "
                        f"temp={temp_val:.2f} "
                        f"count={cycles_val:.0f}{event_msg}"
                    )

                    previous_values = current_values
                    jitter = random.uniform(-0.6, 0.8)
                    await asyncio.sleep(max(1.0, POLL_INTERVAL_SECONDS + jitter))

        except Exception as exc:
            print(f"[ingest] error: {exc} retry in {retry_delay:.1f}s")
            emit_event(
                event_type="ingest_connection",
                src_ip=target_host,
                route="opcua_ingest",
                status="error",
                extra={"error": str(exc), "target_endpoint": OPCUA_URL},
            )
            await asyncio.sleep(retry_delay)
            retry_delay = min(15.0, retry_delay + 1.5)


async def _run_all(l2_conn: sqlite3.Connection) -> None:
    await asyncio.gather(main(), scada_l2_poll(l2_conn))


if __name__ == "__main__":
    try:
        if SCADA_L2_URL:
            l2_conn = sqlite3.connect(DB_PATH, timeout=10)
            l2_conn.execute("PRAGMA journal_mode=WAL")
            l2_conn.execute("PRAGMA busy_timeout=10000")
            ensure_schema(l2_conn)
            asyncio.run(_run_all(l2_conn))
        else:
            asyncio.run(main())
    except KeyboardInterrupt:
        print("[ingest] stopped")
        emit_event(event_type="ingest_stop", route="opcua_ingest", status="stopped")