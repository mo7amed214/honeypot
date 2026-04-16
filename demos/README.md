# Streamlit Attack Demo

This app provides a guided live demo flow for your thesis:

- Environment and pipeline readiness checks
- Attacker storyline actions (recon, SMB access, OPC UA path touch)
- MITRE-mapped rule evidence counters from Loki
- Links to Grafana, Wazuh, and Historian pages

## Install

From repository root:

pip install -r demos/requirements.txt

## Run

From repository root:

bash scripts/run_streamlit_demo.sh

Then open:

http://localhost:8501

## Tips for presentation

- Keep dashboard time window aligned with your narrative section.
- Run one action at a time, then refresh evidence counters.
- Keep one Grafana tab open to avoid query pressure.
- If an action requires adaptation for your lab, edit the command in the app before running.
