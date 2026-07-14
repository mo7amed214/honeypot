"""Autonomous LLM red-team harness for the Purdue Level 3 industrial honeynet.

This package automates and scales the single unscripted adversarial-agent
session described in the thesis into a repeatable, multi-model experiment
battery. It drives an LLM agent against the live honeynet through an SSH
foothold, records every action in the same ground-truth manifest schema the
detection/ML pipeline already consumes, and post-processes the runs into the
paper's evaluation tables:

  1. Repeated-trials consistency  (same model, N runs)
  2. Cross-model comparison       (Claude / GPT / Gemini / open-source)
  3. Multiple attack objectives   (recon / manipulation / exfil / persistence)
  4. Detection coverage           (actions vs. Zeek + Wazuh alerts)
  5. Classifier generalisation    (SessionAttentionLSTM on unscripted sessions)
  6. Deception efficacy           (suspicion + bait-interaction analysis)

The core (agent loop, recorder, MITRE mapping, coverage, suspicion,
aggregation) is pure standard-library Python so it runs anywhere. Live trials
need model API keys and the running lab; the classifier bridge reuses the
existing Docker ML image. A built-in mock provider + mock target let the whole
pipeline be validated offline with no keys and no VM.
"""

__all__ = ["config"]
