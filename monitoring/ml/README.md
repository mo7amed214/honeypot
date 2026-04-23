# ML Monitoring Feed

This directory is used for generated JSONL exports that Promtail scrapes into Loki.

Expected runtime files:

- `model_summary.jsonl`
- `session_predictions.jsonl`
- `evaluation_predictions.jsonl`

The files are generated locally by:

```bash
bash scripts/run_ml_pipeline.sh
```
