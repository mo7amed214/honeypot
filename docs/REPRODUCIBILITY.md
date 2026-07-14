# Reproducibility Guide

This document lists the exact steps to reproduce every quantitative artefact in
the paper, the pinned toolchain, and the seeds used. Everything runs from the
repository with Docker; no proprietary hardware is required.

## Toolchain (pinned)

| Component | Version | Where |
|---|---|---|
| Python (host, harness) | 3.11+ (stdlib only) | `redteam/` |
| PyTorch (ML) | 2.5.1 (CPU) | `ml/lstm_session/Dockerfile` |
| NumPy | 2.1.1 | `ml/lstm_session/requirements.txt` |
| scikit-learn | 1.5.2 | `ml/lstm_session/requirements.txt` |
| Zeek | 6.0 | `zeek/zeek:latest` (compose) |
| Wazuh | 4.14.4 | single-node compose |
| Grafana / Loki / Promtail | pinned in `compose/*.yml` | monitoring profile |

Random seed for all ML runs: **1337** (overridable via `--seed`). The seed is
threaded through `torch.manual_seed`, `random.seed`, the grouped split, and
k-fold assignment, so a given seed reproduces a given split and initialisation.

## 1. Environment (system + detection)

```bash
# core Level 3 honeynet + monitoring (lean or full)
bash scripts/run_level3_monitoring.sh          # resolves the ot-net bridge for Zeek
# verify
bash scripts/validate_honeypot_readiness.sh
```

## 2. Training corpus

```bash
# curated scenario corpus (deterministic; seed baked into the generator)
python ml/lstm_session/generate_curated_sessions.py
# -> artifacts/scenario-runs/*/ground_truth.jsonl
```

## 3. Headline model + k-fold (Table: ML classification)

```bash
docker compose -f compose/docker-compose.ml.yml run --rm lstm-session-runtime \
  python -m ml.lstm_session.train \
    --scenario-root artifacts/scenario-runs \
    --output-dir ml/runs/latest --kfold 5 --seed 1337
# metrics -> ml/runs/latest/metrics.json
```

## 4. Ablation + seed robustness (Table: ablation)

```bash
docker compose -f compose/docker-compose.ml.yml run --rm lstm-session-runtime \
  python -m ml.lstm_session.ablation \
    --scenario-root artifacts/scenario-runs --out ml/runs/ablation --kfold 0
# report -> ml/runs/ablation/ablation/ablation_report.md
```

## 5. Strong baselines (Table: baseline comparison)

```bash
docker compose -f compose/docker-compose.ml.yml run --rm lstm-session-runtime \
  python -m ml.lstm_session.baselines \
    --scenario-root artifacts/scenario-runs --out ml/runs/baselines
# report -> ml/runs/baselines/baselines_report.md
```

## 6. Robustness under perturbation (Table: robustness)

```bash
docker compose -f compose/docker-compose.ml.yml run --rm lstm-session-runtime \
  python -m ml.lstm_session.robustness \
    --model ml/runs/latest/model.pt \
    --scenario-root artifacts/scenario-runs --out ml/runs/robustness
# report -> ml/runs/robustness/robustness_report.md
```

## 7. Autonomous LLM red-team battery (Tables 1-6, adversarial validation)

Offline validation (no keys, no VM — proves the pipeline):
```bash
python -m redteam.run_experiments --models mock \
  --objectives explore credential_theft process_manipulation \
               data_exfiltration persistence \
  --repeats 2 --target mock --no-reset
python -m redteam.aggregate
```

Live (needs the running honeynet + at least one model key in `redteam/.env`):
```bash
python -m redteam.run_experiments \
  --models claude-opus gpt gemini llama-local \
  --objectives explore credential_theft process_manipulation \
               data_exfiltration persistence \
  --repeats 5
python -m redteam.aggregate
# tables -> artifacts/redteam-report/table{1..6}.md
```

## 8. Public dataset + datasheet

```bash
python scripts/build_public_dataset.py
# -> dataset/level3_sessions.{full,subset}.jsonl, DATASHEET.md, SCHEMA.md, stats.json
```

## Determinism notes

- ML runs are seeded but CPU BLAS kernels can introduce tiny (<1e-3) float
  variation across machines; k-fold mean/std is reported to absorb this.
- The curated corpus generator is fully deterministic for a given code version.
- LLM red-team runs are inherently stochastic (model sampling); this is exactly
  why the battery reports repeated-trial distributions rather than a single run.
