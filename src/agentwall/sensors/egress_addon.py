from __future__ import annotations

import base64
import json
import os
import socket
import struct
import time

MAX_BODY = 1_048_576
_SKIP_DOMAINS = ("anthropic.com", "claude.ai", "claude.com")
_DEFAULT_SOCK = os.path.join(os.environ.get("XDG_RUNTIME_DIR", "/tmp"), "agentwall", "egress.sock")


def skip_host(host: str) -> bool:
    h = (host or "").lower()
    return any(h == d or h.endswith("." + d) for d in _SKIP_DOMAINS)


def build_record(*, host: str, method: str, path: str, scheme: str, ts: float,
                 body: bytes | None) -> dict:
    raw = body or b""
    size = len(raw)
    truncated = size > MAX_BODY
    body_b64 = None if (truncated or not raw) else base64.b64encode(raw).decode()
    return {"host": host, "method": method, "path": path, "scheme": scheme,
            "ts": ts, "size": size, "truncated": truncated, "body_b64": body_b64}


def send_record(socket_path: str, record: dict) -> None:
    data = json.dumps(record).encode()
    frame = struct.pack(">I", len(data)) + data
    try:
        s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        s.settimeout(0.5)
        s.connect(socket_path)
        s.sendall(frame)
        s.close()
    except OSError:
        return  # fail-safe: never block or raise on the egress path


class EgressAddon:
    def __init__(self, socket_path: str | None = None) -> None:
        self._sock = socket_path or os.environ.get("AGENTWALL_EGRESS_SOCK", _DEFAULT_SOCK)

    def request(self, flow) -> None:  # mitmproxy hook; flow is duck-typed
        req = flow.request
        host = getattr(req, "pretty_host", "") or getattr(req, "host", "")
        if skip_host(host):
            return
        body = req.raw_content if getattr(req, "raw_content", None) else b""
        rec = build_record(host=host, method=req.method, path=req.path,
                           scheme=req.scheme, ts=getattr(req, "timestamp_start", time.time()),
                           body=body)
        send_record(self._sock, rec)


addons = [EgressAddon()]
