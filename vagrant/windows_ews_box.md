# Windows EWS Box

The real thesis EWS is a Windows 11 VM, so the Linux fallback is only a
temporary stand-in.

To reproduce the actual OS, package the real `EWS-WIN11` VM from the Windows
VirtualBox host into a local VirtualBox-compatible Vagrant box, then register
that box on the Linux host.

## 1. Package the Windows VM on laptop1

On the Windows VirtualBox host, from the repo root:

```powershell
powershell -ExecutionPolicy Bypass -File .\scripts\windows\package_ews_vagrant_box.ps1
```

That uses `VBoxManage export` and creates:

- `vagrant\boxes\ews-win11.box`

If needed, you can override the VM name, output path, or VBoxManage path:

```powershell
powershell -ExecutionPolicy Bypass -File .\scripts\windows\package_ews_vagrant_box.ps1 -VmName "EWS-WIN11" -OutputPath ".\ews-win11.box"
```

## 2. Install the box on the Linux honeypot host

The `.box` file is large, so it is intentionally not committed to git.
Install it from whichever artifact source you use.

From the Windows laptop over SSH:

```bash
EWS_BOX_SOURCE='labssh@192.168.1.3:/C:/Users/labssh/Downloads/ews-win11.box' \
  bash scripts/install_ews_windows_box.sh
```

From a release/artifact URL:

```bash
EWS_BOX_URL='https://example.invalid/ews-win11.box' \
  bash scripts/install_ews_windows_box.sh
```

From a local file:

```bash
bash scripts/install_ews_windows_box.sh /path/to/ews-win11.box
```

The installer places the packaged file at:

- `vagrant/boxes/ews-win11.box`

and writes:

- `vagrant/boxes/ews-win11.box.sha256`

## 3. Register the box on Linux

The installer registers by default. To register manually from the repo root:

```bash
bash scripts/register_ews_windows_box.sh
```

This registers the box under:

- `honeypot/ews-win11-local`

## 4. Use the real Windows EWS

```bash
export HONEYPOT_VAGRANT_PROFILE=laptop1-safe
export HONEYPOT_EWS_MODE=windows
export HONEYPOT_EWS_BOX=honeypot/ews-win11-local
vagrant destroy -f ews
vagrant up ews
```

## Notes

- `laptop1-safe` keeps the EWS role on the safe host-only subnet by default.
- `laptop1-bridge` is closer to the live LAN layout, but use it only when you
  intentionally want a bridged replay.
- The Windows provisioner enables OpenSSH, creates `john / Cisco`, and copies
  optional artifacts from `vagrant/assets/ews/`.
- For a public repo, publish `ews-win11.box` as a GitHub release asset, Git LFS
  object, or private shared artifact. Do not commit the box directly to normal
  git history.
