import asyncio
import os
import random
import sqlite3
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


def opcua_target_host(url: str) -> str:
    parsed = urlparse(url)
    if parsed.hostname:
        return parsed.hostname
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


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        print("[ingest] stopped")
        emit_event(event_type="ingest_stop", route="opcua_ingest", status="stopped")
