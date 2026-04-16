import json
import os
import threading
from datetime import datetime, timezone
from typing import Any, Dict

SERVICE_NAME = os.getenv("SERVICE_NAME", "historian_service")
EVENT_LOG_PATH = os.getenv("EVENT_LOG_PATH", "/var/log/historian/events.jsonl")
_LOCK = threading.Lock()


def _utc_now_iso() -> str:
    return datetime.now(tz=timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _safe(value: Any) -> Any:
    if value is None:
        return ""
    if isinstance(value, (str, int, float, bool)):
        return value
    return str(value)


def emit_event(
    event_type: str,
    src_ip: str = "",
    username: str = "",
    route: str = "",
    tag: str = "",
    status: str = "",
    user_agent: str = "",
    extra: Dict[str, Any] | None = None,
) -> None:
    record: Dict[str, Any] = {
        "timestamp": _utc_now_iso(),
        "service": SERVICE_NAME,
        "event_type": event_type,
        "src_ip": _safe(src_ip),
        "username": _safe(username),
        "route": _safe(route),
        "tag": _safe(tag),
        "status": _safe(status),
        "user_agent": _safe(user_agent),
    }

    if extra:
        for key, value in extra.items():
            record[str(key)] = _safe(value)

    line = json.dumps(record, ensure_ascii=True)
    print(line, flush=True)

    try:
        log_dir = os.path.dirname(EVENT_LOG_PATH)
        if log_dir:
            os.makedirs(log_dir, exist_ok=True)
        with _LOCK:
            with open(EVENT_LOG_PATH, "a", encoding="utf-8") as handle:
                handle.write(line + "\n")
    except Exception:
        pass
