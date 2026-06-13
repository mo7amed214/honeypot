# Level 3 Industrial Honeynet

> A high-interaction industrial control system honeynet focused on Purdue Level 3
> (Site Operations), with a three-layer detection stack and a session-scoped ML
> classification pipeline.

**Bachelor's Thesis — German University in Cairo (GUC), 2026**  
Supervised by Dr. Amr Mohamed Saber

---

## What This Is

Industrial cyberattacks — from Stuxnet to the 2015 Ukraine power grid incident —
unfold at **Purdue Level 3**: the control room layer where engineers manage
production. Most deception-based defences focus on lower OT layers or the
enterprise perimeter. Level 3 is the gap.

This project builds a fully reproducible Level 3 honeynet for a discrete
manufacturing assembly-line setting. It combines:

- **Four deception assets** that look and behave like a real factory control room
- **Three independent monitoring layers** (network, host, application) feeding a
  unified Grafana SOC dashboard
- **A session-level ML pipeline** (`SessionAttentionLSTM`) that classifies full
  attacker sessions rather than individual alerts — achieving 94.7% danger-label
  accuracy and raising a critical alert one full step before the most destructive
  attack phase

### Headline Results

| Metric | Value |
|---|---|
| Kill chain detection coverage | 7 / 7 instrumented phases (100%) |
| ML danger-label accuracy | 94.70% |
| 5-fold cross-validation mean | 97.59% |
| Improvement over rule-based baseline | +40 percentage points |
| Early warning lead time | 1 phase before tag manipulation |
| AI adversarial validation | Every action detected (Claude Opus, unscripted) |

---

## Architecture

```
                      ┌───────────────────────────────────────────────┐
  ATTACKER            │           LEVEL 3 — SITE OPERATIONS            │
  (external) ───────► │                                                 │
                      │  ┌──────────────┐    ┌───────────────────────┐ │
  Level 3.5           │  │     EWS       │    │  Operational File     │ │
  Jump Host ─SSH/RDP─►│  │ Windows 11   │    │  Share  (SMB / 445)   │ │
                      │  │ SSH + RDP    │    │  Honey credentials    │ │
                      │  └──────┬───────┘    └───────────────────────┘ │
                      │         │ Historian access                       │
                      │         ▼                  OPC UA telemetry     │
  LEVEL 2             │  ┌──────────────┐  ◄──────────────────────────┤
  OPC UA server ──────►  │  Historian   │                               │
  (physics sim)       │  │  Web Portal  │                               │
                      │  └──────────────┘                               │
                      └───────────────────────────────────────────────┘
                                      │ telemetry
                                      ▼
                      ┌───────────────────────────────────────────────┐
                      │          MONITORING & TELEMETRY LAYER          │
                      │                                                 │
                      │  Sysmon  — Windows host events (EWS)           │
                      │  Zeek    — passive network sensor               │
                      │  Wazuh   — SIEM, correlation, alerting          │
                      │                                                 │
                      │  └─► Grafana SOC Dashboard  :3000              │
                      │  └─► SessionAttentionLSTM   (session ML)       │
                      └───────────────────────────────────────────────┘
```

---

## Repository Layout

```
honeypot/
│
├── services/
│   ├── historian/          # FastAPI web portal — process historian (time-series store)
│   ├── opcua/              # OPC UA server with stateful physics simulation (15 tags)
│   ├── smb/                # Samba honey share with credential-adjacent honey files
│   └── ews/                # EWS provisioning scripts (Vagrant / VirtualBox / Windows 11)
│
├── ml/
│   └── lstm_session/       # SessionAttentionLSTM — train, infer, publish
│       ├── train.py                    # Model architecture + training loop
│       ├── session_builder.py          # Session assembly, encoding, vocabulary
│       ├── infer.py                    # Single-session inference CLI
│       ├── session_detection.py        # Live Loki polling → real-time session builder
│       ├── publish_live_session.py     # Writes predictions back to Loki
│       └── generate_curated_sessions.py  # Synthetic session corpus generation
│
├── monitoring/
│   ├── grafana/            # Dashboard JSON provisioning (SOC + OPC UA telemetry)
│   ├── wazuh/              # 26 custom detection rules (severity levels 4–13)
│   ├── zeek/               # Zeek scripts, including ARP MITM detector (rule 100308)
│   ├── loki/               # Loki log aggregation config
│   ├── promtail/           # Promtail scrape config (Wazuh + historian + ML output)
│   └── ml/                 # ML pipeline output — session JSONlines published to Loki
│
├── demos/
│   ├── streamlit_demo.py   # 8-phase interactive attack console (live SSH execution)
│   └── payloads/           # Tag manipulation payload used in Phase 8
│
├── compose/                # Docker Compose entrypoints (historian, monitoring, ML, Wazuh)
├── scripts/                # Deployment, smoke-test, and operations helpers
├── vagrant/                # Reproducible VM lab definition (5-VM Vagrantfile)
├── integrations/           # Level 3.5 ingress contract for external integration tests
├── docs/                   # Architecture notes, lab hardening, telemetry schemas
└── artifacts/              # Scenario run outputs — ground_truth.jsonl per session
```

---

## Prerequisites

| Dependency | Version | Purpose |
|---|---|---|
| Docker + Docker Compose v2 | ≥ 24 | All containerised services |
| Python | 3.11+ | ML pipeline, scripts |
| PyTorch | CPU is sufficient | SessionAttentionLSTM |
| Vagrant + VirtualBox | any recent | Full VM lab only |

---

## Quick Start

### 1 — Start the monitoring stack

```bash
bash scripts/run_wazuh_stack.sh         # Wazuh Manager + Indexer + Dashboard
bash scripts/run_monitoring_stack.sh    # Grafana + Loki + Promtail
```

| Dashboard | URL | Default credentials |
|---|---|---|
| Grafana SOC | http://localhost:3000 | `admin / admin` |
| Wazuh | https://localhost | `admin / SecretPassword` |

### 2 — Start the deception services

```bash
bash scripts/run_historian_stack.sh     # Historian portal + OPC UA server
```

Historian portal opens at **http://localhost:5000** (login: `john / Cisco`)

### 3 — Launch the interactive attack console

```bash
bash scripts/run_streamlit_demo.sh
```

Attack console: **http://localhost:8501**

Steps through an 8-phase kill chain with live SSH execution against the EWS.
Evidence panels show Grafana and Wazuh alerts after each phase.

### 4 — Run the ML pipeline

```bash
bash scripts/train_lstm_session_model.sh    # Train on collected artifacts
bash scripts/run_ml_pipeline.sh            # Infer + publish to Loki + Grafana
```

Model output lands in `ml/runs/latest/`. The SOC dashboard updates automatically.

---

## Full VM Lab (Vagrant)

Reproduces the full isolated two-laptop lab topology with five VMs:

```bash
bash scripts/run_vagrant_lab.sh
```

| VM | IP | Role |
|---|---|---|
| ews | 192.168.56.5 | Engineering Workstation (Windows 11 Enterprise) |
| smb | 192.168.56.7 | Operational file share |
| historian | 192.168.56.10 | Process historian portal |
| opcua | 192.168.56.11 | OPC UA server |
| zeek | 192.168.56.13 | Passive network sensor |

Smoke-test the lab after provisioning:

```bash
bash scripts/smoke_vagrant_lab.sh
```

Default credentials on all Vagrant guests: `john / Cisco`

See [vagrant/README.md](vagrant/README.md) for profile switching and the Windows
EWS box setup guide.

---

## ML Pipeline — SessionAttentionLSTM

Rather than classifying individual alerts, the pipeline assembles each attacker
interaction into a **session** — an ordered sequence of events — and classifies
the session as a whole.

```
Raw telemetry  (Wazuh alerts · Zeek logs · Sysmon events)
        │
        ▼
  Session Builder
  Groups events by session ID, maps rule IDs to attack-stage labels,
  expands each session into N progressive prefixes for training.
        │
        ▼
  Encoder
  Maps 6 categorical fields (asset class, source/target asset, event kind,
  rule ID, agent name) to embedding indices.
  Appends 5 numeric features per timestep (rule level, duration, …).
        │
        ▼
  SessionAttentionLSTM
  ┌─ Embedding layers  (6 categorical fields × learned dims)
  ├─ Bidirectional LSTM  (hidden = 64, 2 layers)
  ├─ Query-based attention  (context vector over all hidden states)
  ├─ Dropout  (p = 0.20)
  └─ Three output heads:
       ├─ danger_label    → {low, medium, high, critical}
       ├─ dominant_stage  → multi-class over stage vocabulary
       └─ session_intent  → {benign_operations, discovery_scan, host_recon,
                              credential_access, collection, ot_recon, ot_impact}
        │
        ▼
  Hybrid Scoring Overlay
  Deterministic path rules (e.g. opcua_write → ot_impact) override the model
  output for high-confidence paths, ensuring critical-path sessions are never
  under-scored.
        │
        ▼
  Loki Publication → Grafana SOC Dashboard (10 s auto-refresh)
```

### Training corpus

- **1,682** labelled training examples
- **369** unique sessions
- **7** intent classes
- **26** custom Wazuh detection rules

### Accuracy results (held-out test set)

| Classifier | Danger label | Attack stage | Session intent |
|---|---|---|---|
| Majority class baseline | 45% | 28% | 44% |
| Rule-based baseline | 54% | 19% | 53% |
| **SessionAttentionLSTM** | **94.70%** | **94.45%** | **95.12%** |
| — with hybrid overlay | — | — | **100%** |
| 5-fold cross-validation | **97.59%** | — | — |

### Early warning

The model escalates to `CRITICAL` at Phase 7 (ARP adversary-in-the-middle) —
one full phase before the tag manipulation payload executes at Phase 8. An
analyst receives a critical-priority alert before any process value is falsified.

### Training

```bash
bash scripts/train_lstm_session_model.sh
```

Or directly via Docker Compose:

```bash
docker compose -f compose/docker-compose.ml.yml run --rm lstm-session-model \
  python -m ml.lstm_session.train --epochs 40 --hidden 64 --layers 2
```

### Single-session inference

```bash
docker compose -f compose/docker-compose.ml.yml run --rm lstm-session-model \
  python ml/lstm_session/infer.py \
  --model-path ml/runs/latest/model.pt \
  --session-file artifacts/scenario-runs/<session-id>/ground_truth.jsonl
```

---

## Deception Assets

| Asset | Protocol | Port | Deception role |
|---|---|---|---|
| Engineering Workstation (EWS) | SSH / RDP | 22, 3389 | Primary high-interaction host; Windows 11 Enterprise with honey files on desktop |
| Historian portal | HTTP | 5000 | Process data web portal with live OPC UA ingest; realistic PI Web API HTTP surface |
| SMB file share | SMB | 445 | Operational documents including credential-adjacent honey files that lure attackers to EWS |
| OPC UA server | OPC UA | 4840 | 15 stateful process tags driven by physics simulation; any node enumeration is an IOC |

All four assets intentionally share a single credential pair (`john / Cisco`) to
maximise cross-layer evidence generation — a single discoverable credential is
sufficient to guide an attacker through every Level 3 asset without additional
lure mechanisms.

---

## Kill Chain Detection Coverage

| Phase | MITRE Technique | Detected by | Result |
|---|---|---|---|
| 1 — Initial foothold | T0866 | Out of scope by design | — |
| 2 — Network discovery | T0846 | Zeek — network scan | **DETECTED** |
| 3 — SMB credential harvest | T0811 | Zeek — SMB file access | **DETECTED** |
| 4 — Pivot to EWS | T0866 | Wazuh — logon event | **DETECTED** |
| 5 — Historian access | T0802 | Zeek + historian application | **DETECTED** |
| 6 — OPC UA reconnaissance | T0861 | Zeek — OPC UA connection | **DETECTED** |
| 7 — ARP adversary-in-the-middle | T0830 | Zeek — ARP poisoning | **DETECTED** |
| 8 — Tag manipulation | T0831 | Zeek + Wazuh + historian | **DETECTED** |

981 Wazuh alerts generated across the kill chain window. 5 MITRE ATT&CK tactic
families detected. Phases 7 and 8 triggered simultaneous alerts from both the
network layer (Zeek) and the host layer (Wazuh) — independent dual confirmation.

---

## Dashboards

After running the full stack, three Grafana dashboards are available at
**http://localhost:3000**:

| Dashboard | Purpose |
|---|---|
| SOC Honeypot Detection | Kill chain timeline, ML session predictions, Wazuh alert feed, session intent panel |
| OPC UA Process Telemetry | Live tag values and anomaly markers from the physics simulation |
| Wazuh Events | Raw alert stream with MITRE ATT&CK tactic mapping |

---

## Adversarial Validation

An AI agent (Claude Opus) was given one credential pair and no other information.

**Task:** find every accessible asset and reach the deepest level of access possible.

| What the agent did | What the honeynet caught |
|---|---|
| Found all 4 Level 3 assets independently | SSH logon — Wazuh |
| Retrieved credentials from SMB (no password) | Network scan — Zeek (45 s latency) |
| Authenticated to historian with found credentials | SMB file read — Zeek (file level) |
| Enumerated all 15 OPC UA process tags | Historian login + API queries — Zeek |
| Executed tag manipulation payload | OPC UA write frames — Zeek |
| Identified the false OPC UA document | Historian ingest anomaly — historian app |

Every action was detected. The deception layer held under fully unscripted
adversarial pressure.

---

## Operations Reference

```bash
# Validate Zeek capture and relay pipeline
bash scripts/check_zeek_pipeline.sh

# Inject a smoke marker and verify end-to-end Loki/Wazuh flow
bash scripts/smoke_zeek_wazuh_loki.sh

# Run a labeled live replay and write a ground-truth manifest
bash scripts/replay_attack_scenario.sh

# Full replay + alert verification for host, app, and OT coverage
bash scripts/validate_honeypot_readiness.sh

# Quick pass/fail check for demo readiness (Zeek, Wazuh, Loki)
bash scripts/demo_green_check.sh

# Snapshot Zeek, Wazuh, and historian logs into an archive
bash scripts/archive_telemetry_bundle.sh <scenario-id>

# Collect a benign capture baseline
bash scripts/capture_benign_baseline.sh <duration-seconds> [scenario-id]

# Clean demo residue and stop MITM tooling
bash scripts/reset_lab_state.sh
```

---

## Thesis Context

**Title:** Building a Decoy System in an Industrial Setting —
Modelling Purdue Level 3 for an Industrial Deception System  
**Institution:** German University in Cairo (GUC)  
**Year:** 2026  
**Supervisor:** Dr. Amr Mohamed Saber

The thesis covers five identified literature gaps (no prior Level 3 focus, no
cross-layer telemetry correlation, no analyst-ready ML output, fixed
non-modular architectures, no realistic open-source OPC UA simulation) and
addresses each directly. This repository is the complete, reproducible
implementation artefact.

---

## License

MIT
