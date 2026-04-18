import argparse
import asyncio

from asyncua import Client


SYNC_PROFILE = [
    {
        "phase": "cache_reseed",
        "line1_conveyor_speed_mpm": 8.4,
        "line1_vibration_mm_s": 1.92,
        "air_pressure_bar": 5.2,
        "weld_cell_temperature_c": 66.4,
        "plant_power_kw": 182.0,
    },
    {
        "phase": "cache_flush",
        "line1_conveyor_speed_mpm": 24.8,
        "line1_vibration_mm_s": 2.34,
        "air_pressure_bar": 6.9,
        "weld_cell_temperature_c": 79.1,
        "plant_power_kw": 276.0,
    },
]


async def run(endpoint: str, cycles: int, pause: float) -> None:
    client = Client(endpoint)
    await client.connect()
    print(f"[+] Connected to OPC UA server at {endpoint}")
    print(f"[+] Replaying staged telemetry sync for {cycles} cycles...")

    try:
        for idx in range(cycles):
            profile = SYNC_PROFILE[idx % len(SYNC_PROFILE)]
            for tag, value in profile.items():
                if tag == "phase":
                    continue
                node = client.get_node(f"ns=2;s={tag}")
                await node.write_value(float(value))

            print(f"[+] Cycle {idx + 1}/{cycles} written ({profile['phase']})")
            await asyncio.sleep(pause)
    finally:
        await client.disconnect()
        print("[+] Staged telemetry sync complete")


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Replay a staged telemetry sync toward the OPC UA server.")
    parser.add_argument("--endpoint", default="opc.tcp://192.168.1.11:4840")
    parser.add_argument("--cycles", type=int, default=18)
    parser.add_argument("--pause", type=float, default=1.0)
    return parser.parse_args()


if __name__ == "__main__":
    args = parse_args()
    asyncio.run(run(args.endpoint, args.cycles, args.pause))
