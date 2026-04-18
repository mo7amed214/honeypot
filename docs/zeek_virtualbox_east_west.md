# Zeek Coverage For East-West VirtualBox Traffic

## Why the current laptop sensor misses some traffic

The monitoring laptop only sees packets that traverse its capture interface.
When `EWS -> historian` or `EWS -> SMB` happens directly between VMs on the other laptop, that traffic can stay inside the VirtualBox host path and never cross the monitoring laptop.

That is why:

- `Wazuh` can confirm the action on the endpoint.
- `historian logs` can confirm the action in the application.
- `Zeek` on the monitoring laptop can still miss the packet flow.

## Recommended topology for this lab

Because you are using:

- a `physical switch`
- `VirtualBox` on the other laptop
- the current laptop mainly for `Grafana / Wazuh / Streamlit / Loki`

the best design is:

1. Keep this laptop as the monitoring and dashboard node.
2. Run a second Zeek sensor on the `VirtualBox host laptop`.
3. Relay that remote sensor's `conn.log` into `/home/ceo/zeek_feed.log` on this monitoring laptop.
4. Keep the existing `Wazuh -> Loki -> Grafana` pipeline unchanged.

This is better than relying on switch mirroring alone, because same-host VM-to-VM traffic may never hit the physical switch.

## VirtualBox host setup

### 1. Install Zeek on the VirtualBox host

Install Zeek on the laptop that is actually running the VMs.

### 2. Identify the interface that sees VM traffic

Start with:

```bash
ip -br addr
sudo tcpdump -ni any host 192.168.1.5 or host 192.168.1.7 or host 192.168.1.10 or host 192.168.1.11
```

Then generate a test from one VM to another, for example:

- `EWS -> historian`
- `EWS -> SMB`

Use the interface that actually shows the packets.

Prefer:

- the bridged physical adapter used by VirtualBox
- or the host interface that carries the VM traffic

Avoid `any` as the final Zeek interface unless you have validated it carefully in this environment.

### 3. Point Zeek at that interface

Example `node.cfg`:

```ini
[zeek]
type=standalone
host=localhost
interface=enp3s0
```

Then deploy:

```bash
sudo /opt/zeek/bin/zeekctl deploy
```

### 4. Validate east-west visibility on the VirtualBox host

After a VM-to-VM test, confirm the remote Zeek sensor sees entries like:

- `192.168.1.5 -> 192.168.1.10:5000`
- `192.168.1.5 -> 192.168.1.7:445`
- `192.168.1.5 -> 192.168.1.11:4840`

Example:

```bash
sudo tail -n 50 /opt/zeek/spool/zeek/conn.log
sudo tail -n 50 /opt/zeek/spool/zeek/http.log
```

## Relay the remote Zeek sensor into this monitoring laptop

This repo includes:

- `scripts/zeek_remote_relay.sh`
- `monitoring/systemd/zeek-remote-relay.service`
- `monitoring/systemd/zeek-remote-relay.env.example`

### 1. Copy the env example

On the monitoring laptop:

```bash
sudo cp monitoring/systemd/zeek-remote-relay.env.example /etc/default/zeek-remote-relay
```

Edit the values for the VirtualBox host:

- `REMOTE_SENSOR_HOST`
- `REMOTE_SENSOR_USER`
- `REMOTE_SENSOR_KEY` or `REMOTE_SENSOR_PASSWORD`

### 2. Install the service

```bash
sudo cp monitoring/systemd/zeek-remote-relay.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now zeek-remote-relay.service
```

### 3. Check the relay

```bash
sudo systemctl status zeek-remote-relay.service
tail -n 20 /home/ceo/zeek_feed.log
```

Once the remote `conn.log` is appended into `zeek_feed.log`, the existing Wazuh rules and Grafana dashboards continue to work without major changes.

## What to expect after this change

With a Zeek sensor on the VirtualBox host, the SOC dashboard should finally show network evidence for traffic such as:

- `EWS -> historian`
- `EWS -> SMB`
- `EWS -> OPC UA`

That closes the current gap where host/application logs prove the action but the monitoring laptop Zeek sensor does not see the packet path.
