import asyncio
import os
import random
import sqlite3
from datetime import datetime, timezone
from typing import Dict, Optional, Tuple

try:
    from asyncua import Client
except ModuleNotFoundError as exc:
    raise SystemExit(
        "Missing Python dependency 'asyncua'. Install historian_service/requirements.txt or run via docker compose."
    ) from exc

from event_logger import emit_event

DB_PATH = os.getenv("DB_PATH", "historian.db")
OPCUA_URL = os.getenv("OPCUA_URL", "opc.tcp://localhost:4840")
NAMESPACE = os.getenv("NAMESPACE", "http://manufacturing.example/opcua")
POLL_INTERVAL_SECONDS = float(os.getenv("POLL_INTERVAL_SECONDS", "3.0"))
INGEST_PROFILE = os.getenv("INGEST_PROFILE", "legacy15")

LEGACY_TAGS = {
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

MINIMAL6_TAGS = {
    "LineRunning": {"path": "LineRunning", "min": 0.0, "max": 1.0, "max_step": 1.0},
    "ConveyorSpeed": {"path": "ConveyorSpeed", "min": 0.0, "max": 2.0, "max_step": 0.35},
    "Station1Temperature": {"path": "Station1Temperature", "min": 20.0, "max": 90.0, "max_step": 2.5},
    "BatchCount": {"path": "BatchCount", "min": 0.0, "max": 1e9, "max_step": 20.0},
    "RejectCount": {"path": "RejectCount", "min": 0.0, "max": 1e7, "max_step": 5.0},
    "EmergencyStop": {"path": "EmergencyStop", "min": 0.0, "max": 1.0, "max_step": 1.0},
}

TAG_PROFILES = {
    "legacy15": LEGACY_TAGS,
    "minimal6": MINIMAL6_TAGS,
}

TAGS = TAG_PROFILES.get(INGEST_PROFILE, LEGACY_TAGS)


def pick_value(values: Dict[str, float], *candidates: str, default: float = 0.0) -> float:
    for candidate in candidates:
        if candidate in values:
            return values[candidate]
    return default


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
    speed = pick_value(current, "line1_conveyor_speed_mpm", "ConveyorSpeed")
    cycles = pick_value(current, "robot_arm_3_cycle_count", "BatchCount")
    prev_cycles = pick_value(previous, "robot_arm_3_cycle_count", "BatchCount", default=cycles)
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
    speed_key = "line1_conveyor_speed_mpm" if "line1_conveyor_speed_mpm" in current else "ConveyorSpeed"
    temp_key = "weld_cell_temperature_c" if "weld_cell_temperature_c" in current else "Station1Temperature"
    count_key = "robot_arm_3_cycle_count" if "robot_arm_3_cycle_count" in current else "BatchCount"

    if speed_key not in current or temp_key not in current or count_key not in current:
        return None

    speed = current[speed_key]
    prev_speed = previous.get(speed_key, speed)
    temp = current[temp_key]
    prev_temp = previous.get(temp_key, temp)
    cycles = current[count_key]
    prev_cycles = previous.get(count_key, cycles)

    # The physics model restarts legacy15 line speed from 0.0 to a stable floor
    # near 12.5 m/min, which should not be treated as tampering.
    is_expected_legacy_restart = (
        speed_key == "line1_conveyor_speed_mpm"
        and prev_speed < 0.5
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

    if speed > 0.8 and unchanged_counts.get(temp_key, 0) >= 5:
        return (
            "stuck_value_pattern",
            "medium",
            "Temperature remained static while line appears active",
            {"temperature": temp, "streak": unchanged_counts[temp_key]},
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
    print(f"[ingest] connecting to {OPCUA_URL}")
    print(f"[ingest] profile={INGEST_PROFILE} namespace={NAMESPACE}")
    print(f"[ingest] DB_PATH={DB_PATH} tags={len(TAGS)}")
    emit_event(event_type="ingest_start", route="opcua_ingest", status="starting")

    conn = sqlite3.connect(DB_PATH)
    ensure_schema(conn)

    previous_values: Dict[str, float] = {}
    unchanged_counts: Dict[str, int] = {tag: 0 for tag in TAGS}
    poll_count = 0
    retry_delay = 2.0

    while True:
        try:
            async with Client(url=OPCUA_URL) as client:
                try:
                    assembly_node = client.get_node("ns=1;s=AssemblyLine")
                    await assembly_node.read_browse_name()
                    node_map = {tag: client.get_node(f"ns=1;s={cfg['path']}") for tag, cfg in TAGS.items()}
                    for node in node_map.values():
                        await node.read_browse_name()
                except Exception as direct_exc:
                    print(f"[ingest] direct node-id mapping failed: {direct_exc}")
                    nsidx = await client.get_namespace_index(NAMESPACE)
                    node_map = {
                        tag: await client.nodes.root.get_child(["0:Objects", f"{nsidx}:AssemblyLine", f"{nsidx}:{cfg['path']}"])
                        for tag, cfg in TAGS.items()
                    }
                print(f"[ingest] connected - {len(node_map)} tags mapped")
                emit_event(event_type="ingest_connection", route="opcua_ingest", status="connected")
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
                        alert_tag = "line1_conveyor_speed_mpm" if "line1_conveyor_speed_mpm" in current_values else "ConveyorSpeed"
                        emit_event(
                            event_type="ingest_anomaly",
                            route="opcua_ingest",
                            tag=alert_tag,
                            status=severity,
                            extra={"detector": detector, **details},
                        )
                        event_msg = f" | alert={detector} severity={severity}"

                    speed_val = pick_value(current_values, "line1_conveyor_speed_mpm", "ConveyorSpeed")
                    temp_val = pick_value(current_values, "weld_cell_temperature_c", "Station1Temperature")
                    cycles_val = pick_value(current_values, "robot_arm_3_cycle_count", "BatchCount")

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
            emit_event(event_type="ingest_connection", route="opcua_ingest", status="error", extra={"error": str(exc)})
            await asyncio.sleep(retry_delay)
            retry_delay = min(15.0, retry_delay + 1.5)


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        print("[ingest] stopped")
        emit_event(event_type="ingest_stop", route="opcua_ingest", status="stopped")