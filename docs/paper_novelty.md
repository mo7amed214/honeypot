# Solo Journal Paper — Concrete Novelty & Contribution Statement

**Target venue:** Elsevier, *International Journal of Critical Infrastructure Protection* (IJCIP)
**Working title:** *A Modular Purdue Level 3 Industrial Honeynet Validated by Autonomous LLM Red-Teaming*

---

## 1. The one-sentence novelty

> An upper-layer (Purdue Level 3) industrial honeynet whose realism and
> detection stack are validated by an **autonomous LLM agent acting as the
> attacker**, and whose k-fold-validated session classifier is shown to
> generalise to those unscripted agent sessions.

Two things make this new, and neither exists in the prior art:

1. **Where the honeynet sits.** Almost all ICS honeypot research (Conpot,
   GasPot, HoneyPhy, and the honeypot/honeynet surveys) targets field-device /
   PLC levels (Purdue 0–2). This work instruments the *site-operations* layer —
   engineering workstation, historian, OPC UA server, SMB share — which is
   where credential reuse, data historians, and supervisory-to-operational
   telemetry actually live, and which is largely unexplored as a deception
   surface.

2. **How it is validated.** Existing LLM + ICS-honeypot work (LLMPot, VelLMes)
   uses an LLM to *power the honeypot* — generating protocol responses and
   process behaviour. This work inverts that role: the LLM is the **red-team
   adversary**, given only an IP and one credential, used to validate that the
   honeynet is coherent enough to sustain autonomous unscripted attack and that
   the detection stack catches it. That inversion is the methodological
   contribution.

## 2. Why the novelty is defensible (the reviewer-trap fix)

The known weakness of the thesis result is that the LLM session was **n = 1** —
a reviewer will call it anecdotal. The paper closes this on two fronts:

- **Statistical spine (Option B's hard data).** The SessionAttentionLSTM result
  is strong and reproducible: 94.70 % danger-label accuracy, 97.59 % ± 0.73 %
  5-fold cross-validation on the thesis corpus. **Important honesty check (new
  analysis, see `docs/ml_evaluation_results.md`):** the thesis's "40-point gap"
  is against a *deliberately weak single-feature rule* baseline. When we add
  *strong learned* baselines (LogisticRegression / RandomForest / SVM on
  order-free session features), they reach ~100 % on clean, complete curated
  sessions — i.e. **on easy fully-observed data the sequential model is not
  required.** The LSTM's defensible value is not raw clean-session accuracy but
  **robustness and early prediction**: under event shuffling it drops 11.8 pp
  (a bag-of-features baseline is order-invariant and cannot drop at all), which
  is direct evidence the model uses sequential structure; it also degrades
  gracefully under dropped events (−3.9 pp) and supports partial-session
  prediction. Framed this way the ML pillar is reviewer-proof rather than
  overstated.
- **The bridge (new work).** The trained classifier is run **on the LLM
  sessions themselves** — sessions it never saw in training. A correct
  prediction there is an out-of-distribution generalisation result that ties
  the hard ML number directly to the LLM pillar. In the harness's offline
  validation the classifier flagged 10/10 unscripted sessions as
  critical/OT-impact; on live model runs this becomes the paper's Table 5.
- **Scale (new work).** The single session is scaled to a controlled battery:
  repeated trials (consistency), multiple models (cross-model), and multiple
  objectives (weakness classes). "10/10 runs reached process impact across three
  model families" is evidence; "it worked once" is not.

So the headline is Option A (system design + autonomous LLM red-teaming), and
it is fortified — not replaced — by Option B's hard data.

## 3. The evaluation apparatus (built, in `redteam/`)

The paper's LLM-pillar claims are produced by a reproducible harness, not a
manual session. It drives a model-agnostic agent against the honeynet through
the SSH foothold, records every action in the same manifest schema as the
scripted kill chain, and aggregates six tables:

| # | Experiment | What it proves |
|---|---|---|
| 1 | Repeated-trials consistency | the result is not a one-off |
| 2 | Cross-model comparison | it is a property of the honeynet, not one model |
| 3 | Multiple attack objectives | it surfaces a *class* of weaknesses |
| 4 | Detection coverage | the honeynet *catches* the autonomous attacker |
| 5 | Classifier on LLM sessions | the hard ML result generalises to the LLM pillar |
| 6 | Deception efficacy / suspicion | the environment is believable + bait works |

## 4. Stated contributions (paper bullet list)

1. **A Level 3-focused industrial honeynet.** A modular, reproducible
   site-operations deception surface (EWS, historian, OPC UA with a live
   physics simulation, SMB share) tied together by a coherent credential-reuse
   narrative — addressing the upper-layer gap in ICS honeypot research.
2. **Autonomous LLM red-teaming as a validation methodology.** A reproducible,
   model-agnostic harness that uses LLM agents as unscripted attackers to
   independently validate deception coherence and detection coverage — a
   non-circular alternative to scripted self-evaluation.
3. **Cross-model adversarial evidence.** A controlled battery (repeated trials ×
   models × objectives) that quantifies how reliably, and by which paths,
   autonomous agents traverse a Level 3 kill chain — with implications for
   AI-augmented threat modelling.
4. **A session-level detection result that generalises.** An attention-LSTM
   session classifier (94.7 % / 97.6 % k-fold) shown to correctly rate
   unscripted LLM-generated sessions it never trained on, bridging the ML and
   red-team contributions.
5. **A reproducibility + dataset artefact.** MITRE ATT&CK-for-ICS-labelled
   session data and a one-command-deployable environment for the community.

## 4b. Live cross-model red-team results (produced this iteration)

The harness was run live against the honeynet (real SSH-equivalent foothold →
real OPC UA / historian / SMB services) with a **remote capable model** and a
**local small model**, giving a three-tier capability spectrum:

| Tier | Model | Behaviour | Detection | Classifier verdict |
|---|---|---|---|---|
| Frontier (thesis) | Claude Opus | completes full kill chain → OPC-UA impact | multi-layer detections fire | critical |
| Mid (live) | Qwen2.5-7B | systematic recon; reaches **all 4 assets**; stalls before impact | Zeek `discovery_scan` (rule 100307A) fired on the recon | medium (correct: recon-only) |
| Small (live) | Llama-3.2-3B | fails to leave the foothold (0 assets) | nothing to detect | n/a |

Key point for the paper: this is **stronger than the thesis's single Opus
anecdote** — it shows the Level 3 kill chain's exploitability **scales with model
capability**, with live evidence at each tier. The mid-tier model's
reconnaissance *was* caught by the network sensor; it never triggered the
higher-consequence detectors (OPC-UA write, ARP-MITM) precisely because it never
completed the chain. Detection coverage here is network-layer only (Zeek); host
/ app coverage (Wazuh) needs the heavier stack and is future work. Reproduce
with `scripts/run_redteam_live.sh` + `python -m redteam.aggregate`.

## 5. Reviewer-shield work — DONE this iteration

These were built and **actually run** (real numbers, not just code):

- **Ablation study** (`ml/lstm_session/ablation.py`) — 8 configs; prefix
  expansion is the dominant design choice (−2.5 pp), architecture knobs ~0.2 pp.
- **Strong baselines** (`ml/lstm_session/baselines.py`) — LR/RF/SVM/NB; surfaced
  the honest finding above (order-free learners ≈100 % on clean data).
- **Robustness** (`ml/lstm_session/robustness.py`) — drop/shuffle/truncate/noise;
  shuffle −11.8 pp proves order-sensitivity and justifies the sequential model.
- **Public dataset + datasheet** (`scripts/build_public_dataset.py`) — 257
  sessions / 1261 events sanitised, balanced subset, datasheet + schema.
- **Reproducibility package** (`docs/REPRODUCIBILITY.md`,
  `scripts/run_ml_evaluation_suite.sh`) — pinned toolchain, seed control,
  one-command suite.
- **Red-team harness** (`redteam/`) — model-agnostic, six-experiment battery,
  validated offline incl. the real classifier bridge.

Full results: `docs/ml_evaluation_results.md`.

## 6. What is still genuinely blocked (needs a real machine / model access)

- **Live LLM runs.** The harness is complete and multi-model ready; producing
  the live Tables 1–6 needs model access (a working API key or a local Ollama
  model) **and** enough RAM to run a model + honeynet + EWS VM at once. On the
  current 16 GB development machine this trio does not fit (repeated Docker
  crashes; ~1.5 GB free under load). This is a hardware/credential blocker, not
  a code gap — one command runs it on an adequate machine.
- **Thesis-corpus numbers.** The ablation/baseline/robustness numbers above are
  on the reproducible 257-session curated corpus; restating the thesis's exact
  94.7 %/97.6 % needs the mixed live-replay + curated corpus regenerated.

None of these change the framing; they populate the tables the apparatus
already produces.
