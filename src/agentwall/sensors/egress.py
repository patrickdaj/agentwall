from __future__ import annotations

import asyncio
import base64
import json
import os
import struct
import subprocess
from pathlib import Path
from typing import Callable

from agentwall.events import SecurityEvent, new_event

_ADDON = str(Path(__file__).with_name("egress_addon.py"))


def default_socket_path() -> str:
    base = os.environ.get("XDG_RUNTIME_DIR", "/tmp")
    return os.path.join(base, "agentwall", "egress.sock")


def egress_event_from_record(rec: dict, session_id: str,
                             blob_put: Callable[[bytes], str]) -> SecurityEvent:
    payload_ref = None
    body_b64 = rec.get("body_b64")
    if body_b64:
        payload_ref = blob_put(base64.b64decode(body_b64))
    return new_event(event_type="network_upload", session_id=session_id, source="egress",
                     ts=float(rec.get("ts", 0.0)), payload_ref=payload_ref,
                     attrs={"destination": rec.get("host"), "method": rec.get("method"),
                            "path": rec.get("path"), "size": rec.get("size"),
                            "truncated": bool(rec.get("truncated", False))})


class EgressSensor:
    def __init__(self, socket_path: str, blob_put: Callable[[bytes], str], session_id: str,
                 dead_letter: Callable[[str, str], None], *, proxy_port: int = 8888,
                 spawn_proxy: bool = True) -> None:
        self._sock = socket_path
        self._blob_put = blob_put
        self._session = session_id
        self._dead_letter = dead_letter
        self._port = proxy_port
        self._spawn = spawn_proxy
        self._server: asyncio.AbstractServer | None = None
        self._proc: subprocess.Popen | None = None
        self._stop_event = asyncio.Event()  # 3.12: safe to create without a running loop
        self.degraded = False

    def _to_event(self, rec: dict) -> SecurityEvent:
        return egress_event_from_record(rec, self._session, self._blob_put)

    def _start_proxy(self) -> None:
        if _port_in_use(self._port):
            self.degraded = True
            raise RuntimeError(
                f"port {self._port} already in use — stop the conflicting proxy "
                f"(the daemon must own the addon-bearing mitmdump)")
        env = {**os.environ, "AGENTWALL_EGRESS_SOCK": self._sock}
        self._proc = subprocess.Popen(
            ["mitmdump", "-s", _ADDON, "-p", str(self._port), "--set", "stream_large_bodies=1m"],
            env=env, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

    async def run(self, bus) -> None:
        if self._spawn:
            self._start_proxy()
        try:
            os.makedirs(os.path.dirname(self._sock), exist_ok=True)
            if os.path.exists(self._sock):
                os.unlink(self._sock)
            self._server = await asyncio.start_unix_server(self._make_handler(bus), path=self._sock)
            async with self._server:
                await self._stop_event.wait()  # stop() sets this; exiting the context closes the server
        except Exception:  # socket setup failed after spawning the proxy — don't orphan it
            if self._proc is not None and self._proc.poll() is None:
                self._proc.terminate()
            raise

    def _make_handler(self, bus):
        async def handle(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
            raw = b""
            try:
                hdr = await reader.readexactly(4)
                (n,) = struct.unpack(">I", hdr)
                raw = await reader.readexactly(n)
                rec = json.loads(raw)
                await bus.publish(self._to_event(rec))
            except Exception as exc:  # fail-safe: dead-letter, keep serving
                self._dead_letter(raw.decode("utf-8", "replace"), repr(exc))
            finally:
                writer.close()
        return handle

    def stop(self) -> None:
        self._stop_event.set()  # unblocks run()'s wait; the async-with then closes the server
        if self._proc is not None and self._proc.poll() is None:
            self._proc.terminate()
            try:
                self._proc.wait(timeout=5)  # reap so a restarting daemon leaves no zombies
            except subprocess.TimeoutExpired:
                self._proc.kill()
                self._proc.wait()
        if os.path.exists(self._sock):
            try:
                os.unlink(self._sock)
            except OSError:
                pass


def _port_in_use(port: int) -> bool:
    import socket
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        s.bind(("127.0.0.1", port))
        return False
    except OSError:
        return True
    finally:
        s.close()
