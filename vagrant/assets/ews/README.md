Drop optional Windows EWS artifacts here if you want the Vagrant EWS box to
look more like the live Windows machine.

Useful examples copied from the real EWS VM:

- `arpspoof.exe`
- `enable_ews_host_telemetry.ps1`
- `nmap-7.99-setup.exe`
- `python-3.11.9-amd64.exe`
- `wazuh-agent-4.14.4-1.msi`
- `Sysmon.zip`

The Windows EWS provisioner copies any files in this directory into:

- `C:\Users\john\Downloads`

If the following installer names are present, the provisioner also attempts
silent installation:

- `python-3.11*.exe`
- `nmap-*-setup.exe`
- `wazuh-agent-*.msi` when `HONEYPOT_EWS_WAZUH_MANAGER` is set

This keeps the Vagrant EWS closer to the real thesis workstation without
forcing those third-party binaries into the repo by default.
