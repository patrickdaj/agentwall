import base64
import socket
import struct

from agentwall.sensors.egress_addon import build_record, skip_host, send_record


def test_skip_host_matches_anthropic_and_subdomains():
    assert skip_host("api.anthropic.com")
    assert skip_host("anthropic.com")
    assert skip_host("claude.ai")
    assert skip_host("downloads.claude.ai")
    assert not skip_host("httpbin.org")
    assert not skip_host("evil-anthropic.com.attacker.net")


def test_build_record_captures_body():
    rec = build_record(host="httpbin.org", method="POST", path="/post",
                       scheme="https", ts=1.0, body=b"secret=abc")
    assert rec["host"] == "httpbin.org" and rec["method"] == "POST"
    assert rec["size"] == 10 and rec["truncated"] is False
    assert base64.b64decode(rec["body_b64"]) == b"secret=abc"


def test_build_record_truncates_oversize_body():
    big = b"x" * (1_048_576 + 1)
    rec = build_record(host="h", method="POST", path="/", scheme="https", ts=1.0, body=big)
    assert rec["truncated"] is True
    assert rec["body_b64"] is None
    assert rec["size"] == 1_048_577


def test_send_record_writes_length_prefixed_frame(tmp_path):
    sock_path = str(tmp_path / "e.sock")
    srv = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    srv.bind(sock_path)
    srv.listen(1)
    send_record(sock_path, {"host": "h", "method": "GET"})
    conn, _ = srv.accept()
    hdr = conn.recv(4)
    (n,) = struct.unpack(">I", hdr)
    body = conn.recv(n)
    conn.close()
    srv.close()
    import json
    assert json.loads(body)["host"] == "h"


def test_send_record_silent_when_socket_absent(tmp_path):
    send_record(str(tmp_path / "nope.sock"), {"host": "h"})  # must not raise
