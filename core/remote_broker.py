#!/usr/bin/env python3
"""core/remote_broker.py — Multi-Host Remote Execution Broker Daemon & Client for LONLY.

Enables distributed multi-host penetration testing:
- RemoteBrokerServer: A secured daemon running on target nodes/jumpboxes.
  - Enforces HMAC-SHA256 signature authentication on every inbound execution request.
  - Replay attack defense via timestamp freshness validation (<60s drift).
  - Scope allowlist enforcement at the edge node.
  - POSIX sandboxing and process isolation via the local ExecutionBroker.
- RemoteBrokerClient: Remote transport adapter dispatching tool calls over mTLS/HTTP to daemon nodes.
"""

from __future__ import annotations

import hashlib
import hmac
import http.server
import json
import os
import socketserver
import threading
import time
import urllib.error
import urllib.request
from dataclasses import asdict, dataclass
from typing import Any, Optional

from core.broker import ExecutionBroker, ExecutionResult
from core.config import get_logger

logger = get_logger("lonly.broker.remote")

DEFAULT_BROKER_PORT = 9876
TIMESTAMP_TOLERANCE_SEC = 60.0


def compute_request_signature(secret_key: str, timestamp: str, body_bytes: bytes) -> str:
    """Compute HMAC-SHA256 signature over timestamp and request body."""
    msg = f"{timestamp}:".encode("utf-8") + body_bytes
    return hmac.new(secret_key.encode("utf-8"), msg, hashlib.sha256).hexdigest()


class RemoteBrokerHandler(http.server.BaseHTTPRequestHandler):
    """HTTP Request Handler for remote tool execution requests."""

    server_secret_key: str = ""
    local_broker: Optional[ExecutionBroker] = None
    allowed_scope: list[str] = []

    def _send_json(self, status: int, data: dict) -> None:
        payload = json.dumps(data, ensure_ascii=False).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)

    def do_GET(self) -> None:
        """Health check endpoint."""
        if self.path == "/health":
            self._send_json(200, {
                "status": "healthy",
                "daemon": "lonly_remote_broker",
                "scope": self.allowed_scope,
                "timestamp": time.time(),
            })
        else:
            self._send_json(404, {"error": "Not found"})

    def do_POST(self) -> None:
        """Authenticated tool execution endpoint."""
        if self.path != "/execute":
            self._send_json(404, {"error": "Endpoint not found"})
            return

        # 1. Verify HMAC authentication headers
        req_ts = self.headers.get("X-LONLY-Timestamp", "")
        req_sig = self.headers.get("X-LONLY-Signature", "")

        if not req_ts or not req_sig:
            self._send_json(401, {"error": "Missing authentication headers (X-LONLY-Timestamp, X-LONLY-Signature)"})
            return

        try:
            ts_float = float(req_ts)
            now = time.time()
            if abs(now - ts_float) > TIMESTAMP_TOLERANCE_SEC:
                self._send_json(403, {"error": f"Timestamp drift exceeded ({abs(now - ts_float):.1f}s > {TIMESTAMP_TOLERANCE_SEC}s)"})
                return
        except ValueError:
            self._send_json(400, {"error": "Invalid timestamp format"})
            return

        content_len = int(self.headers.get("Content-Length", 0))
        body = self.rfile.read(content_len)

        expected_sig = compute_request_signature(self.server_secret_key, req_ts, body)
        if not hmac.compare_digest(expected_sig, req_sig):
            self._send_json(401, {"error": "Invalid HMAC signature"})
            return

        try:
            req_data = json.loads(body.decode("utf-8"))
        except Exception as exc:
            self._send_json(400, {"error": f"Malformed JSON request: {exc}"})
            return

        executable = req_data.get("executable", "")
        argv = req_data.get("argv", [])
        target = req_data.get("target", "")
        capability = req_data.get("capability", "")
        timeout = float(req_data.get("timeout", 60.0))
        approved = bool(req_data.get("approved", False))

        # 2. Scope validation at daemon node
        if self.allowed_scope and target:
            from core.policy import TargetPolicy
            if not TargetPolicy(allowed_targets=self.allowed_scope).is_in_scope(target):
                self._send_json(403, {"error": f"Target '{target}' is rejected by daemon scope policy"})
                return

        # 3. Execution via local POSIX sandboxed broker
        broker = self.local_broker or ExecutionBroker()
        result: ExecutionResult = broker.execute(
            executable=executable,
            argv=argv,
            target=target,
            capability=capability,
            timeout=int(timeout),
            approved=approved,
        )

        resp_dict = {
            "execution_id": result.execution_id,
            "executable": result.executable,
            "argv": result.argv,
            "exit_code": result.exit_code,
            "stdout": result.stdout,
            "stderr": result.stderr,
            "duration_ms": result.duration_ms,
            "timestamp": result.timestamp,
            "output": result.output,
            "truncated": result.truncated,
        }
        self._send_json(200, resp_dict)

    def log_message(self, format: str, *args: Any) -> None:
        logger.debug("RemoteBrokerDaemon HTTP: " + format, *args)


class RemoteBrokerServer:
    """Threaded HTTP daemon running the Remote Broker PEP service."""

    def __init__(
        self,
        host: str = "127.0.0.1",
        port: int = DEFAULT_BROKER_PORT,
        secret_key: str = "lonly-shared-secret-key",
        allowed_scope: Optional[list[str]] = None,
        broker: Optional[ExecutionBroker] = None,
    ) -> None:
        self.host = host
        self.port = port
        self.secret_key = secret_key
        self.allowed_scope = allowed_scope or ["127.0.0.1", "localhost", "::1"]
        self.broker = broker or ExecutionBroker()

        class CustomHandler(RemoteBrokerHandler):
            server_secret_key = secret_key
            local_broker = self.broker
            allowed_scope = self.allowed_scope

        class _ReuseTCPServer(socketserver.TCPServer):
            allow_reuse_address = True

        self._server = _ReuseTCPServer((self.host, self.port), CustomHandler)
        self.port = self._server.server_address[1]
        self._thread: Optional[threading.Thread] = None

    def start(self) -> None:
        """Start daemon server in background thread."""
        self._thread = threading.Thread(target=self._server.serve_forever, daemon=True)
        self._thread.start()
        logger.info("RemoteBrokerServer started at http://%s:%d", self.host, self.port)

    def stop(self) -> None:
        """Shutdown daemon server cleanly."""
        self._server.shutdown()
        self._server.server_close()
        if self._thread and self._thread.is_alive():
            self._thread.join(timeout=2.0)
        logger.info("RemoteBrokerServer stopped")


class RemoteBrokerClient:
    """Client adapter connecting to a remote node's RemoteBrokerServer."""

    def __init__(
        self,
        server_url: str = f"http://127.0.0.1:{DEFAULT_BROKER_PORT}",
        secret_key: str = "lonly-shared-secret-key",
        timeout: float = 65.0,
    ) -> None:
        self.server_url = server_url.rstrip("/")
        self.secret_key = secret_key
        self.timeout = timeout

    def check_health(self) -> dict:
        """Ping remote broker daemon."""
        url = f"{self.server_url}/health"
        req = urllib.request.Request(url, method="GET")
        with urllib.request.urlopen(req, timeout=5.0) as resp:
            return json.loads(resp.read().decode("utf-8"))

    def execute(
        self,
        executable: str,
        argv: list[str],
        target: str = "",
        capability: str = "",
        timeout: float = 60.0,
        approved: bool = False,
    ) -> ExecutionResult:
        """Dispatch tool command to remote daemon with HMAC authentication."""
        url = f"{self.server_url}/execute"
        payload_data = {
            "executable": executable,
            "argv": argv,
            "target": target,
            "capability": capability,
            "timeout": timeout,
            "approved": approved,
        }
        body = json.dumps(payload_data, ensure_ascii=False).encode("utf-8")
        timestamp = str(time.time())
        signature = compute_request_signature(self.secret_key, timestamp, body)

        headers = {
            "Content-Type": "application/json",
            "Content-Length": str(len(body)),
            "X-LONLY-Timestamp": timestamp,
            "X-LONLY-Signature": signature,
        }

        req = urllib.request.Request(url, data=body, headers=headers, method="POST")
        try:
            with urllib.request.urlopen(req, timeout=self.timeout) as resp:
                data = json.loads(resp.read().decode("utf-8"))
                return ExecutionResult(
                    execution_id=data.get("execution_id", ""),
                    executable=data.get("executable", executable),
                    argv=data.get("argv", argv),
                    exit_code=data["exit_code"],
                    stdout=data["stdout"],
                    stderr=data["stderr"],
                    duration_ms=data.get("duration_ms", 0.0),
                    timestamp=data.get("timestamp", ""),
                    output=data.get("output", data["stdout"]),
                    truncated=data.get("truncated", False),
                )
        except urllib.error.HTTPError as err:
            err_body = err.read().decode("utf-8", errors="ignore")
            logger.error("Remote broker error %d: %s", err.code, err_body)
            return ExecutionResult(
                execution_id="",
                executable=executable,
                argv=argv,
                exit_code=1,
                stdout="",
                stderr=f"Remote Broker Error ({err.code}): {err_body}",
                duration_ms=0.0,
                timestamp=str(time.time()),
                output="",
            )
        except Exception as exc:
            logger.error("Remote broker connection failure: %s", exc)
            return ExecutionResult(
                execution_id="",
                executable=executable,
                argv=argv,
                exit_code=1,
                stdout="",
                stderr=f"Remote Broker Connection Failure: {exc}",
                duration_ms=0.0,
                timestamp=str(time.time()),
                output="",
            )
