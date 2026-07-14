# LLM Red-Team Harness

Automates and scales the thesis's single unscripted adversarial-agent session
into a repeatable, multi-model experiment battery against the Purdue Level 3
industrial honeynet. It drives an LLM agent through an SSH foothold on the
engineering workstation, records every action in the **same ground-truth
manifest schema the detection/ML pipeline already consumes**, and aggregates
the runs into the paper's six evaluation tables.

## Why this exists (the paper argument)

The paper's headline contribution is **a modular Level 3 honeynet validated by
autonomous LLM red-teaming**. The obvious reviewer objection to the thesis
result is *"n = 1 — that's an anecdote."* This harness neutralises that by:

1. **Scaling the single session to a controlled battery** (repeated trials,
   multiple models, multiple objectives), and
2. **Routing every unscripted session through the k-fold-validated
   SessionAttentionLSTM** (Experiment 5), so the statistically-hard ML result
   directly backs the LLM result instead of sitting beside it.

Every experiment runs from one uniform agent loop, so cross-model numbers are a
fair comparison rather than apples-to-oranges.

## The six experiments

| # | Experiment | Module | Output table |
|---|---|---|---|
| 1 | Repeated-trials consistency (same model, N runs) | `run_experiments` | `table1_consistency.md` |
| 2 | Cross-model comparison | `run_experiments` | `table2_cross_model.md` |
| 3 | Multiple attack objectives | `run_experiments` | `table3_objectives_matrix.md` |
| 4 | Detection coverage (actions vs Zeek + Wazuh) | `detection_coverage` | `table4_detection_coverage.md` |
| 5 | Classifier generalisation on LLM sessions | `classify_session` | `table5_classifier.md` |
| 6 | Deception efficacy / suspicion | `suspicion` | `table6_deception.md` |

## Layout

```
redteam/
  config.py             topology, model registry, objectives, MITRE set, limits
  ssh_target.py         SSHTarget (live) + MockTarget (offline)
  providers.py          Anthropic / OpenAI / Gemini / Ollama + Mock (no SDK deps)
  agent.py              the uniform tool-use loop (one trial)
  recorder.py           writes ground_truth.jsonl + transcript.jsonl + trial.json
  mitre.py              action -> MITRE ATT&CK for ICS technique / stage / asset
  detection_coverage.py exp 4
  classify_session.py   exp 5 (runs the trained LSTM via the ML docker image)
  run_experiments.py    the models x objectives x repeats matrix runner
  aggregate.py          builds all six tables + summary.json
```

Trials are written to `artifacts/redteam-runs/<trial_id>/`; tables to
`artifacts/redteam-report/`.

## Offline validation (no keys, no VM)

The whole pipeline can be exercised with a scripted mock attacker and a mock
target — this is how the code is tested:

```bash
python -m redteam.run_experiments --models mock \
  --objectives explore credential_theft process_manipulation \
               data_exfiltration persistence \
  --repeats 2 --target mock --no-reset
python -m redteam.aggregate
```

Experiment 5 (the classifier bridge) additionally needs Docker + the ML image
(`compose/docker-compose.ml.yml`); it runs the trained model in
`ml/runs/latest/model.pt` and degrades gracefully with a clear note if the
image is absent.

## Live trials

Requires the running honeynet (see the repo root README / `run_level3_monitoring.sh`)
and at least one model API key.

```bash
# consistency battery: one model, 10 runs (Experiment 1)
export ANTHROPIC_API_KEY=sk-...
python -m redteam.run_experiments --models claude-opus --objectives explore --repeats 10

# full cross-model / cross-objective grid (Experiments 1-3 in one sweep)
export ANTHROPIC_API_KEY=...   OPENAI_API_KEY=...   GEMINI_API_KEY=...
python -m redteam.run_experiments \
  --models claude-opus gpt gemini llama-local \
  --objectives explore credential_theft process_manipulation \
               data_exfiltration persistence \
  --repeats 5

python -m redteam.aggregate
```

`--dry-run` prints the plan and checks which model keys are present without
running anything. `reset_lab_state.sh` is invoked between live SSH trials
unless `--no-reset` is passed.

## Safety / cost

- `REDTEAM_MAX_ACTIONS` (default 40) and `REDTEAM_MAX_SECONDS` (default 1200)
  cap each trial.
- The agent only ever acts through the seeded SSH foothold on the lab EWS; the
  system prompt frames it as an authorised engagement on an isolated network.
- Live agentic runs consume API tokens per action — budget the grid size
  accordingly (`--dry-run` first).

## Notes

- Providers use raw HTTP via the standard library, so no third-party SDKs are
  required on the host. Model ids live in `config.MODEL_REGISTRY` and can be
  edited without touching the loop.
- The MITRE mapping is deliberately rule-based and model-independent so the
  technique-coverage numbers are reproducible and not derived from any model's
  own narration.
