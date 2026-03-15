import sqlite3
import random
import math
import os
import base64
from datetime import datetime, timedelta, timezone

PI_SERVER_NAME = "PLANT-PI-01"
DB_PATH        = os.getenv("DB_PATH", "historian.db")
SENTINEL       = os.path.join(os.path.dirname(DB_PATH), ".db_seeded")
FORCE_RESEED   = os.getenv("FORCE_RESEED", "0") == "1"

def make_webid(tag: str) -> str:
    b64 = base64.b64encode(f"{PI_SERVER_NAME}\\{tag}".encode()).decode().replace("=", "")
    return "F1DP" + b64[:28]

conn = sqlite3.connect(DB_PATH, timeout=30)
cursor = conn.cursor()

# Always run lightweight table creation (safe with concurrent readers)
cursor.execute("""
CREATE TABLE IF NOT EXISTS telemetry (
    id        INTEGER PRIMARY KEY AUTOINCREMENT,
    tag       TEXT    NOT NULL,
    timestamp TEXT    NOT NULL,
    value     REAL    NOT NULL,
    quality   TEXT    NOT NULL DEFAULT 'Good',
    source    TEXT    NOT NULL DEFAULT 'OPCUA'
)""")

cursor.execute("""
CREATE TABLE IF NOT EXISTS tag_metadata (
    tag       TEXT PRIMARY KEY,
    unit      TEXT,
    area      TEXT,
    description TEXT,
    equipment TEXT,
    status    TEXT DEFAULT 'ONLINE',
    webid     TEXT,
    pi_path   TEXT
)""")

cursor.execute("""
CREATE TABLE IF NOT EXISTS login_attempts (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp  TEXT NOT NULL,
    src_ip     TEXT,
    username   TEXT,
    password   TEXT,
    user_agent TEXT
)""")
conn.commit()

# Sentinel: only do the heavy seed once (or if FORCE_RESEED=1)
if os.path.exists(SENTINEL) and not FORCE_RESEED:
    print("historian.db already seeded (delete /data/.db_seeded or set FORCE_RESEED=1 to re-seed)")
    conn.close()
    exit(0)

# Clear and re-seed process tables (DML — safe with concurrent readers via WAL)
# login_attempts is intentionally NOT cleared — captured credentials must survive restarts
cursor.execute("DELETE FROM telemetry")
cursor.execute("DELETE FROM tag_metadata")

# --- tag definitions ---
_base_meta = [
    # Assembly Line 1
    ("line1_conveyor_speed_mpm",     "m/min",     "Assembly Line 1",   "Main belt conveyor speed",                  "Conveyor Drive VFD-01",   "ONLINE"),
    ("station1_motor_rpm",           "RPM",       "Assembly Line 1",   "Station 1 drive motor speed",               "Motor MCB-ST1",           "ONLINE"),
    ("robot_arm_3_cycle_count",      "cycles",    "Assembly Line 1",   "Robot arm 3 cumulative cycle counter",       "Robot RA-3",              "ONLINE"),
    ("line1_vibration_mm_s",         "mm/s",      "Assembly Line 1",   "Line 1 main frame vibration level",          "Vibration Sensor VS-L1",  "ONLINE"),
    ("station1_part_count",          "units",     "Assembly Line 1",   "Parts processed at station 1",               "Counter CT-ST1",          "ONLINE"),
    # Welding Cell
    ("weld_cell_temperature_c",      "\u00b0C",   "Welding Cell",      "Welding cell ambient temperature",           "Temp Sensor TS-WC1",      "ONLINE"),
    ("weld_arc_voltage_v",           "V",         "Welding Cell",      "Welding arc voltage",                        "Welder WLD-01",           "ONLINE"),
    ("weld_wire_feed_speed_mmin",    "m/min",     "Welding Cell",      "Wire feed speed",                            "Wire Feeder WF-01",       "ONLINE"),
    ("station2_fault_count",         "faults",    "Welding Cell",      "Cumulative fault counter",                   "PLC PLC-WC",              "ONLINE"),
    # Packaging Station
    ("packaging_rate_units_min",     "units/min", "Packaging Station", "Packaging throughput rate",                  "Packaging Machine PKG-01","ONLINE"),
    ("pkg_seal_temp_c",              "\u00b0C",   "Packaging Station", "Heat seal bar temperature",                  "Sealer SB-01",            "ONLINE"),
    ("pkg_reject_count",             "units",     "Packaging Station", "Rejected packages cumulative counter",        "Vision System VS-PKG",    "ONLINE"),
    # Utilities
    ("air_pressure_bar",             "bar",       "Utilities",         "Compressed air header pressure",             "Compressor COMP-01",      "ONLINE"),
    ("plant_power_kw",               "kW",        "Utilities",         "Total plant power draw",                     "Energy Meter EM-MAIN",    "ONLINE"),
    ("cooling_water_temp_c",         "\u00b0C",   "Utilities",         "Cooling water return temperature",           "Cooling Tower CT-01",     "ONLINE"),
]

metadata = [row + (make_webid(row[0]), f"\\\\{PI_SERVER_NAME}\\{row[0]}") for row in _base_meta]

cursor.executemany(
    "INSERT INTO tag_metadata (tag, unit, area, description, equipment, status, webid, pi_path) VALUES (?,?,?,?,?,?,?,?)",
    metadata
)

# --- Quality helper ---
def pick_quality():
    r = random.random()
    if r < 0.02:  return "Bad"
    if r < 0.06:  return "Uncertain"
    return "Good"

# --- Sinusoidal / PID-style telemetry  (ISO 8601 timestamps) ---
# Seed 120 minutes of history ending RIGHT NOW so the portal always looks live
end_time   = datetime.now(tz=timezone.utc)
start_time = end_time - timedelta(minutes=119)
data = []

for i in range(120):
    ts = (start_time + timedelta(minutes=i)).strftime("%Y-%m-%dT%H:%M:%SZ")
    t  = float(i)
    s  = math.sin
    p  = math.pi
    data.extend([
        # Assembly Line 1 — conveyor PID setpoint 20 m/min
        ("line1_conveyor_speed_mpm",     ts, round(20.0  + 1.2 *s(2*p*t/18) + random.uniform(-0.10, 0.10), 2), pick_quality()),
        ("station1_motor_rpm",           ts, round(1480  + 15  *s(2*p*t/22) + random.uniform(-2.0,   2.0 ), 1), pick_quality()),
        ("robot_arm_3_cycle_count",      ts, 5000 + i,                                                           "Good"),
        ("line1_vibration_mm_s",         ts, round(max(0.05, 0.14 + 0.06*s(2*p*t/10) + random.uniform(-0.01, 0.01)), 3), pick_quality()),
        ("station1_part_count",          ts, 200 + i * 3,                                                        "Good"),
        # Welding Cell — temperature with thermal lag
        ("weld_cell_temperature_c",      ts, round(71.5  + 4.0 *s(2*p*t/30) + random.uniform(-0.3,   0.3 ), 2), pick_quality()),
        ("weld_arc_voltage_v",           ts, round(25.0  + 1.2 *s(2*p*t/8 ) + random.uniform(-0.2,   0.2 ), 2), pick_quality()),
        ("weld_wire_feed_speed_mmin",    ts, round(5.1   + 0.2 *s(2*p*t/12) + random.uniform(-0.05,  0.05), 2), pick_quality()),
        ("station2_fault_count",         ts, random.choice([0, 0, 0, 0, 0, 1]),                                  pick_quality()),
        # Packaging Station
        ("packaging_rate_units_min",     ts, round(46.0  + 3.0 *s(2*p*t/25) + random.uniform(-0.5,   0.5 ), 2), pick_quality()),
        ("pkg_seal_temp_c",              ts, round(181.5 + 2.5 *s(2*p*t/15) + random.uniform(-0.2,   0.2 ), 1), pick_quality()),
        ("pkg_reject_count",             ts, int(i * 0.4),                                                       "Good"),
        # Utilities — compressor cycle on air pressure
        ("air_pressure_bar",             ts, round(6.05  + 0.20*s(2*p*t/8 ) + random.uniform(-0.02,  0.02), 3), pick_quality()),
        ("plant_power_kw",               ts, round(202.0 + 12  *s(2*p*t/20) + random.uniform(-1.0,   1.0 ), 1), pick_quality()),
        ("cooling_water_temp_c",         ts, round(21.0  + 2.0 *s(2*p*t/35) + random.uniform(-0.1,   0.1 ), 2), pick_quality()),
    ])

cursor.executemany(
    "INSERT INTO telemetry (tag, timestamp, value, quality, source) VALUES (?,?,?,?,'OPCUA')",
    data
)

conn.commit()
conn.close()

# Write sentinel so subsequent container restarts skip the seed
with open(SENTINEL, "w") as f:
    f.write(datetime.now(tz=timezone.utc).isoformat())

print(f"historian.db seeded: {len(metadata)} tags across 4 areas, {len(data)} telemetry rows")
