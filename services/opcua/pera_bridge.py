#!/usr/bin/env python3
"""
pera_bridge.py — optional sidecar that feeds PERA Level 2 physics data
into the Level 3 OPC-UA server node store.

Activated only when SCADA_L2_URL is set.  The C OPC-UA server skips
writing the four mapped nodes in that case (SCADA_L2_URL env var is
passed to it too), so there is no race between the two writers.

Without SCADA_L2_URL the process sleeps indefinitely — Docker keeps it
alive but it consumes no CPU, and Level 3 runs exactly as without PERA.

Mapped tags (PERA → OPC-UA, all same physical units):
  node04_measured_rpm  → line1_conveyor_speed_mpm   (RPM × 0.20 → m/min)
  node06_measured_temp → weld_cell_temperature_c     (°C, 1:1)
  node08_measured_pressure → air_pressure_bar        (bar, 1:1)
  node15_ambient_temp  → cooling_water_temp_c        (°C, 1:1)
"""

import asyncio
import json
import os
import time
import urllib.request

SCADA_L2_URL = os.getenv("SCADA_L2_URL", "")
OPCUA_URL = os.getenv("OPCUA_URL", "opc.tcp://opcua:4840")
NAMESPACE = "http://manufacturing.example/opcua"
POLL_INTERVAL = float(os.getenv("PERA_BRIDGE_INTERVAL", "2.0"))

MAPPING = {
    "node04_measured_rpm":      ("line1_conveyor_speed_mpm", 0.20),
    "node06_measured_temp":     ("weld_cell_temperature_c",  1.00),
    "node08_measured_pressure": ("air_pressure_bar",         1.00),
    "node15_ambient_temp":      ("cooling_water_temp_c",     1.00),
}


def _fetch_pera() -> dict:
    with urllib.request.urlopen(f"{SCADA_L2_URL}/api/data", timeout=4) as r:
        return json.loads(r.read())


async def run() -> None:
    from asyncua import Client

    retry_delay = 3.0
    while True:
        try:
            async with Client(url=OPCUA_URL) as client:
                nsidx = await client.get_namespace_index(NAMESPACE)
                nodes = {
                    pera_key: await client.nodes.root.get_child(
                        ["0:Objects", f"{nsidx}:AssemblyLine", f"{nsidx}:{opcua_tag}"]
                    )
                    for pera_key, (opcua_tag, _) in MAPPING.items()
                }
                print(f"[pera_bridge] OPC-UA connected — bridging {len(nodes)} tags", flush=True)
                retry_delay = 3.0

                while True:
                    try:
                        data = await asyncio.to_thread(_fetch_pera)
                        for pera_key, (_, scale) in MAPPING.items():
                            raw = data.get(pera_key)
                            if raw is None:
                                continue
                            await nodes[pera_key].write_value(float(raw) * scale)
                    except Exception as exc:
                        print(f"[pera_bridge] poll error: {exc}", flush=True)
                    await asyncio.sleep(POLL_INTERVAL)

        except Exception as exc:
            print(f"[pera_bridge] connection error: {exc} — retry in {retry_delay:.0f}s", flush=True)
            await asyncio.sleep(retry_delay)
            retry_delay = min(30.0, retry_delay * 1.5)


if __name__ == "__main__":
    if not SCADA_L2_URL:
        print("[pera_bridge] SCADA_L2_URL not set — passive (Level 3 standalone mode)", flush=True)
        while True:
            time.sleep(3600)
    else:
        print(f"[pera_bridge] starting  PERA={SCADA_L2_URL}  OPC-UA={OPCUA_URL}", flush=True)
        try:
            asyncio.run(run())
        except KeyboardInterrupt:
            print("[pera_bridge] stopped", flush=True)
