# OPC UA Server

This folder contains the standalone physics-aware OPC UA server used by the historian ingest.

## Build

```bash
cd services/opcua/opcua_server
make build
```

Or use:

```bash
./build.sh
```

## Run

```bash
cd services/opcua/opcua_server
make run
```

Or use:

```bash
./run.sh
```

The server listens on `opc.tcp://0.0.0.0:4840`.
