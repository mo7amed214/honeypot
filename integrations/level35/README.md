# Level 3.5 integration surface

This folder documents the minimal reproducible Level 3 contract exposed to the
Level 3.5 environment.

## Contract

- host: `172.30.70.10`
- port: `22`
- login: `john / Cisco`
- startup: `bash scripts/run_level35_ingress.sh`
- smoke test: `bash scripts/smoke_level35_ingress.sh`

## What this host represents

The ingress target represents the Level 3 `EWS` / operator workstation.

By default it is intentionally smaller than the full thesis lab:

- enough for Level 3.5 to pivot into a stable Level 3 host
- reproducible from repo code
- not dependent on the original `192.168.1.x` laptop-specific topology

For a full-OS EWS ingress, run the same contract with:

```bash
export HONEYPOT_EWS_MODE=windows
bash scripts/run_level35_ingress.sh
```

That requires the local Windows EWS Vagrant box to be registered first.

## Notes

- The integration surface uses the reproducible `integration` Vagrant profile.
- If you want the portable fallback ingress:
  - `export HONEYPOT_EWS_MODE=linux`
- If you want the real Windows EWS ingress and the box is already registered:
  - `export HONEYPOT_EWS_MODE=windows`
- This repo already supports the Windows box name `honeypot/ews-win11-local`
  when it has been registered locally.
