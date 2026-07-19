"""Loopback A2A relay for the Codex adapter.

The relay is deliberately local-only.  linkd (or a local bootstrap process)
hands it a short-lived ingress capability; the relay never exposes a Tailnet
or public listener and never produces an LLM response itself.
"""

from __future__ import annotations

import hashlib
import base64
import http.server
import hmac
import json
import queue
import secrets
import socket
import threading
import time
from collections import deque
from dataclasses import dataclass, field
from typing import Any, Mapping
from urllib.parse import parse_qs, unquote, urlsplit

from .service import AdapterService


class RelayError(ValueError):
    """A request failed relay validation or capability authorization."""


class IngressCapability:
    """In-memory short-lived ingress capabilities with nonce replay checks."""

    def __init__(self, *, clock=time.time) -> None:
        self._clock = clock
        self._lock = threading.RLock()
        self._values: dict[str, _Capability] = {}

    def issue(self, *, agent_id: str, ttl_seconds: int = 120) -> str:
        if not agent_id:
            raise ValueError("agent_id is required")
        if ttl_seconds <= 0:
            raise ValueError("ttl_seconds must be positive")
        token = secrets.token_urlsafe(32)
        key = _token_key(token)
        with self._lock:
            self._values[key] = _Capability(
                agent_id=agent_id,
                expires_at=int(self._clock()) + ttl_seconds,
            )
        return token

    def register(self, token: str, *, agent_id: str, ttl_seconds: int = 86400) -> None:
        """Register a linkd-issued local ingress token without logging it.

        The current Go gateway derives this value from the registration secret.
        It is accepted only on the loopback relay and can be replaced by a
        short-lived capability when the gateway issues per-request relay claims.
        """
        if not token or not agent_id:
            raise ValueError("token and agent_id are required")
        with self._lock:
            self._values[_token_key(token)] = _Capability(
                agent_id=agent_id,
                expires_at=int(self._clock()) + ttl_seconds,
            )

    def revoke(self, token: str) -> None:
        with self._lock:
            self._values.pop(_token_key(token), None)

    def verify(
        self,
        token: str,
        *,
        agent_id: str,
        nonce: str,
        message_id: str,
        fingerprint: str,
    ) -> bool:
        if not token or not nonce or not message_id:
            raise RelayError("ingress capability, nonce, and messageId are required")
        now = int(self._clock())
        with self._lock:
            capability = self._values.get(_token_key(token))
            if capability is None or capability.expires_at < now:
                if capability is not None:
                    self._values.pop(_token_key(token), None)
                raise RelayError("ingress capability is invalid or expired")
            if capability.agent_id != agent_id:
                raise RelayError("ingress capability is scoped to another Agent")
            previous = capability.nonces.get(nonce)
            if previous is not None:
                previous_message, previous_fingerprint = previous
                if previous_message != message_id or previous_fingerprint != fingerprint:
                    raise RelayError("ingress nonce replay has different message claims")
                return True
            capability.nonces[nonce] = (message_id, fingerprint)
            # Bound memory for a long-lived local process while keeping enough
            # replay history for the capability's short lifetime.
            if len(capability.nonces) > 4096:
                oldest = next(iter(capability.nonces))
                capability.nonces.pop(oldest, None)
            return False

    def check(self, token: str, *, agent_id: str) -> None:
        """Validate a capability for read-only relay operations."""
        if not token:
            raise RelayError("ingress capability is required")
        now = int(self._clock())
        with self._lock:
            capability = self._values.get(_token_key(token))
            if capability is None or capability.expires_at < now:
                if capability is not None:
                    self._values.pop(_token_key(token), None)
                raise RelayError("ingress capability is invalid or expired")
            if capability.agent_id != agent_id:
                raise RelayError("ingress capability is scoped to another Agent")


@dataclass
class _Capability:
    agent_id: str
    expires_at: int
    nonces: dict[str, tuple[str, str]] = field(default_factory=dict)


def _token_key(token: str) -> str:
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


class RelayServer:
    """Threaded HTTP relay bound to a loopback address."""

    def __init__(
        self,
        service: AdapterService,
        *,
        agent_id: str,
        capability: IngressCapability,
        host: str = "127.0.0.1",
        port: int = 0,
        default_cwd: str = "",
        max_body_bytes: int = 1024 * 1024,
        linkd_ingress_token: str = "",
    ) -> None:
        if host not in {"127.0.0.1", "localhost", "::1"}:
            raise ValueError("Codex A2A relay must bind to loopback")
        if not agent_id:
            raise ValueError("agent_id is required")
        self.service = service
        self.agent_id = agent_id
        self.capability = capability
        self.host = host
        self.port = port
        self.default_cwd = default_cwd
        self.max_body_bytes = max(1024, max_body_bytes)
        self.linkd_ingress_token = linkd_ingress_token
        if linkd_ingress_token:
            capability.register(linkd_ingress_token, agent_id=agent_id, ttl_seconds=24 * 60 * 60)
        self._events: deque[dict[str, Any]] = deque(maxlen=256)
        self._subscribers: set[queue.Queue[dict[str, Any]]] = set()
        self._events_lock = threading.RLock()
        self._httpd: http.server.ThreadingHTTPServer | None = None
        self._thread: threading.Thread | None = None

    @property
    def address(self) -> tuple[str, int]:
        if self._httpd is None:
            return self.host, self.port
        host, port = self._httpd.server_address[:2]
        return str(host), int(port)

    @property
    def base_url(self) -> str:
        host, port = self.address
        return f"http://{host}:{port}"

    def start(self) -> tuple[str, int]:
        if self._httpd is not None:
            return self.address
        relay = self

        handler_class = type("_RelayHandler", (_RelayRequestHandler,), {"relay": relay})
        server_class: type[http.server.ThreadingHTTPServer] = http.server.ThreadingHTTPServer
        if ":" in self.host:
            server_class = type(
                "_IPv6RelayHTTPServer",
                (http.server.ThreadingHTTPServer,),
                {"address_family": socket.AF_INET6},
            )
        self._httpd = server_class((self.host, self.port), handler_class)
        self._httpd.daemon_threads = True
        self._thread = threading.Thread(target=self._httpd.serve_forever, name="snw-codex-a2a-relay", daemon=True)
        self._thread.start()
        return self.address

    def serve_forever(self) -> None:
        if self._httpd is None:
            self.start()
        if self._thread is not None and self._thread is not threading.current_thread():
            self._thread.join()

    def shutdown(self) -> None:
        if self._httpd is None:
            return
        self._httpd.shutdown()
        self._httpd.server_close()
        if self._thread is not None and self._thread is not threading.current_thread():
            self._thread.join(timeout=2)
        self._httpd = None
        self._thread = None

    def health(self) -> dict[str, Any]:
        return {"ok": True, "agentId": self.agent_id, "loopbackOnly": True}

    def handle_inbound(
        self,
        payload: Mapping[str, Any],
        token: str,
        *,
        allow_missing_nonce: bool = False,
    ) -> dict[str, Any]:
        normalized = _normalize_payload(payload, self.agent_id, allow_missing_nonce=allow_missing_nonce)
        fingerprint = _payload_fingerprint(normalized)
        duplicate_nonce = self.capability.verify(
            token,
            agent_id=self.agent_id,
            nonce=normalized["nonce"],
            message_id=normalized["messageId"],
            fingerprint=fingerprint,
        )
        result = self.service.receive_message(
            agent_id=self.agent_id,
            remote_agent_id=normalized["sourceAgentId"],
            context_id=normalized["contextId"],
            message_id=normalized["messageId"],
            body=normalized["body"],
            cwd=self.default_cwd,
            task_id=normalized["taskId"],
            metadata=normalized["metadata"],
        )
        result = dict(result)
        result["duplicateNonce"] = duplicate_nonce
        self._publish({"type": "message.received", **result})
        return result

    def accepts_linkd_ingress(self, token: str) -> bool:
        if self.linkd_ingress_token and hmac.compare_digest(token, self.linkd_ingress_token):
            return True
        # A caller may register a linkd-derived token on IngressCapability;
        # this keeps compatibility with short-lived capability rotation.
        try:
            self.capability.check(token, agent_id=self.agent_id)
        except RelayError:
            return False
        return True

    def task_status(self, task_id: str) -> dict[str, Any]:
        return self.service.task_status(self.agent_id, task_id)

    def cancel_task(self, task_id: str) -> dict[str, Any]:
        result = self.service.cancel_task(self.agent_id, task_id)
        self._publish({"type": "task.updated", **result})
        return result

    def subscribe(self) -> queue.Queue[dict[str, Any]]:
        subscriber: queue.Queue[dict[str, Any]] = queue.Queue(maxsize=32)
        with self._events_lock:
            self._subscribers.add(subscriber)
        return subscriber

    def unsubscribe(self, subscriber: queue.Queue[dict[str, Any]]) -> None:
        with self._events_lock:
            self._subscribers.discard(subscriber)

    def _publish(self, event: dict[str, Any]) -> None:
        with self._events_lock:
            self._events.append(event)
            subscribers = list(self._subscribers)
        for subscriber in subscribers:
            try:
                subscriber.put_nowait(event)
            except queue.Full:
                # A slow SSE client must not block inbound delivery.
                pass


class _RelayRequestHandler(http.server.BaseHTTPRequestHandler):
    relay: RelayServer
    protocol_version = "HTTP/1.1"

    def log_message(self, format: str, *args: Any) -> None:
        # Message bodies and capability values must never reach stderr logs.
        return

    def do_GET(self) -> None:  # noqa: N802 - stdlib handler contract
        path = urlsplit(self.path)
        if path.path == "/a2a/health":
            self._json(200, self.relay.health())
            return
        if path.path == "/a2a/events":
            self._serve_sse(parse_qs(path.query))
            return
        task_prefix = ""
        if path.path.startswith("/a2a/tasks/"):
            task_prefix = "/a2a/tasks/"
        elif path.path.startswith("/a2a/rest/tasks/"):
            task_prefix = "/a2a/rest/tasks/"
        elif path.path.startswith("/v1/a2a/rest/tasks/"):
            task_prefix = "/v1/a2a/rest/tasks/"
        if task_prefix:
            task_id = unquote(path.path.removeprefix(task_prefix)).strip("/")
            try:
                self._authorize()
                task = self.relay.task_status(task_id)
                self._json(200, _task_response(task) if task_prefix.endswith("rest/tasks/") else task)
            except (RelayError, KeyError) as exc:
                self._error(exc)
            return
        self._json(404, {"error": "not_found"})

    def do_POST(self) -> None:  # noqa: N802 - stdlib handler contract
        path = urlsplit(self.path).path
        is_rest_message = (
            path.startswith("/a2a/rest") and not path.startswith("/a2a/rest/tasks/")
        ) or (
            path.startswith("/v1/a2a/rest") and not path.startswith("/v1/a2a/rest/tasks/")
        )
        if path in {"/a2a/inbound", "/v1/a2a/inbound"} or is_rest_message:
            try:
                token = self._authorize()
                payload = self._read_json()
                is_linkd = bool(self.headers.get("X-SNW-Linkd-Ingress", ""))
                result = self.relay.handle_inbound(
                    payload,
                    token,
                    allow_missing_nonce=is_linkd or "/a2a/rest" in path,
                )
                if is_rest_message:
                    self._json(200, _task_event_response(result))
                else:
                    self._json(200, result)
            except (RelayError, ValueError, KeyError, RuntimeError) as exc:
                self._error(exc)
            return
        cancel_prefix = None
        if path.startswith("/a2a/tasks/") and path.endswith("/cancel"):
            cancel_prefix = "/a2a/tasks/"
            task_id = unquote(path[len(cancel_prefix) : -len("/cancel")]).strip("/")
        elif path.startswith("/a2a/rest/tasks/") and path.endswith(":cancel"):
            cancel_prefix = "/a2a/rest/tasks/"
            task_id = unquote(path[len(cancel_prefix) : -len(":cancel")]).strip("/")
        if cancel_prefix is not None:
            try:
                self._authorize()
                result = self.relay.cancel_task(task_id)
                self._json(200, _task_response(result) if cancel_prefix.endswith("rest/tasks/") else result)
            except (RelayError, ValueError, KeyError, RuntimeError) as exc:
                self._error(exc)
            return
        if path in {"/a2a/rpc", "/a2a/jsonrpc", "/v1/a2a/jsonrpc"}:
            self._handle_rpc()
            return
        self._json(404, {"error": "not_found"})

    def _handle_rpc(self) -> None:
        request_id: Any = None
        try:
            token = self._authorize()
            request = self._read_json()
            request_id = request.get("id") if isinstance(request, dict) else None
            if not isinstance(request, dict) or request.get("jsonrpc") != "2.0":
                raise RelayError("JSON-RPC request must use jsonrpc=2.0")
            method = str(request.get("method", ""))
            params = request.get("params") if isinstance(request.get("params"), dict) else {}
            authenticated_source = getattr(self, "_source_agent_id", "")
            if authenticated_source and params.get("sourceAgentId") and params["sourceAgentId"] != authenticated_source:
                raise RelayError("sourceAgentId does not match the authenticated ingress identity")
            if authenticated_source:
                params = dict(params)
                params["sourceAgentId"] = authenticated_source
            if method in {"message.receive", "message/send", "message:send", "a2a.message.receive", "tasks.receive"}:
                result = self.relay.handle_inbound(
                    params,
                    token,
                    allow_missing_nonce=bool(self.headers.get("X-SNW-Linkd-Ingress", "")) or "/a2a/jsonrpc" in self.path,
                )
                result = _task_event_response(result)
            elif method in {"task.status", "tasks.status", "tasks/get"}:
                result = self.relay.task_status(str(params.get("taskId", "")))
            elif method in {"task.cancel", "tasks.cancel", "tasks/cancel"}:
                result = self.relay.cancel_task(str(params.get("taskId", "")))
            elif method in {"relay.health", "health"}:
                result = self.relay.health()
            else:
                self._json(200, _rpc_error(request_id, -32601, "method not found"))
                return
            self._json(200, {"jsonrpc": "2.0", "id": request_id, "result": result})
        except (RelayError, ValueError, KeyError, RuntimeError) as exc:
            self._json(400, _rpc_error(request_id, -32602, str(exc)))

    def _serve_sse(self, query: Mapping[str, list[str]]) -> None:
        try:
            self._authorize()
        except RelayError as exc:
            self._error(exc)
            return
        subscriber = self.relay.subscribe()
        self.send_response(200)
        self.send_header("Content-Type", "text/event-stream")
        self.send_header("Cache-Control", "no-cache")
        self.send_header("Connection", "keep-alive")
        self.end_headers()
        once = query.get("once", [""])[0].lower() in {"1", "true", "yes"}
        try:
            self.wfile.write(b"event: ready\ndata: {\"ok\":true}\n\n")
            self.wfile.flush()
            while True:
                try:
                    event = subscriber.get(timeout=15)
                except queue.Empty:
                    self.wfile.write(b": keepalive\n\n")
                    self.wfile.flush()
                    if once:
                        break
                    continue
                encoded = json.dumps(event, ensure_ascii=False, separators=(",", ":"))
                self.wfile.write(f"event: {event.get('type', 'message')}\ndata: {encoded}\n\n".encode("utf-8"))
                self.wfile.flush()
                if once:
                    break
        except (BrokenPipeError, ConnectionResetError, OSError):
            pass
        finally:
            self.relay.unsubscribe(subscriber)

    def _authorize(self) -> str:
        linkd_token = self.headers.get("X-SNW-Linkd-Ingress", "").strip()
        if linkd_token:
            if not self.relay.accepts_linkd_ingress(linkd_token):
                raise RelayError("linkd ingress capability is invalid")
            return linkd_token
        header = self.headers.get("Authorization", "")
        if header.lower().startswith("bearer "):
            token = header[7:].strip()
        else:
            token = self.headers.get("X-SNW-Ingress-Token", "").strip()
            if not token:
                token = self.headers.get("X-SNW-Linkd-Ingress", "").strip()
        self.relay.capability.check(token, agent_id=self.relay.agent_id)
        return token

    def _read_json(self) -> dict[str, Any]:
        try:
            length = int(self.headers.get("Content-Length", "0"))
        except ValueError as exc:
            raise RelayError("Content-Length must be an integer") from exc
        if length <= 0 or length > self.relay.max_body_bytes:
            raise RelayError("request body is empty or too large")
        raw = self.rfile.read(length)
        try:
            value = json.loads(raw)
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise RelayError("request body must be valid JSON") from exc
        if not isinstance(value, dict):
            raise RelayError("request body must be a JSON object")
        source_agent_id = self.headers.get("X-SNW-Agent-ID", "").strip()
        if source_agent_id:
            claimed_source = str(value.get("sourceAgentId") or value.get("source_agent_id") or "")
            if claimed_source and claimed_source != source_agent_id:
                raise RelayError("sourceAgentId does not match the authenticated ingress identity")
            value["sourceAgentId"] = source_agent_id
            self._source_agent_id = source_agent_id
        return value

    def _json(self, status: int, value: Mapping[str, Any]) -> None:
        encoded = json.dumps(value, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(encoded)))
        self.send_header("Connection", "close")
        self.end_headers()
        self.wfile.write(encoded)

    def _error(self, exc: Exception) -> None:
        message = str(exc).lower()
        # Nonce validation/replay failures are malformed or conflicting
        # requests, not authentication failures.  Only capability failures
        # should be reported as 401 so callers can distinguish retrying auth
        # from correcting the request claims.
        status = 401 if "capability" in message else 400
        if isinstance(exc, RuntimeError):
            status = 503
        if isinstance(exc, KeyError):
            status = 404
        self._json(status, {"error": str(exc)})


def _normalize_payload(
    payload: Mapping[str, Any],
    target_agent_id: str,
    *,
    allow_missing_nonce: bool = False,
) -> dict[str, Any]:
    message = payload.get("message") if isinstance(payload.get("message"), Mapping) else None
    params = payload.get("params") if isinstance(payload.get("params"), Mapping) else None
    if message is None and params is not None and isinstance(params.get("message"), Mapping):
        message = params.get("message")
    source = str(payload.get("sourceAgentId") or payload.get("source_agent_id") or (message or {}).get("sourceAgentId", ""))
    target = str(payload.get("targetAgentId") or payload.get("target_agent_id") or (message or {}).get("targetAgentId", "") or target_agent_id)
    message_id = str(payload.get("messageId") or payload.get("message_id") or (message or {}).get("messageId", ""))
    context = str(payload.get("contextId") or payload.get("context_id") or (message or {}).get("contextId", "") or message_id)
    task_id = str(payload.get("taskId") or payload.get("task_id") or message_id)
    nonce = str(payload.get("nonce") or "")
    metadata = payload.get("metadata") if isinstance(payload.get("metadata"), dict) else {}
    if not metadata and isinstance((message or {}).get("metadata"), dict):
        metadata = (message or {}).get("metadata", {})
    body = _extract_body(payload)
    if not source or not context or not message_id or not body:
        raise RelayError("sourceAgentId, contextId, messageId, and message body are required")
    if not nonce and not allow_missing_nonce:
        raise RelayError("nonce is required")
    if target != target_agent_id:
        raise RelayError("targetAgentId does not match the local Agent")
    return {
        "sourceAgentId": source,
        "targetAgentId": target,
        "contextId": context,
        "messageId": message_id,
        "taskId": task_id,
        "nonce": nonce or hashlib.sha256(f"snw-relay-nonce-v1\x00{source}\x00{context}\x00{message_id}".encode("utf-8")).hexdigest(),
        "body": body,
        "metadata": metadata,
    }


def _extract_body(payload: Mapping[str, Any]) -> str:
    direct = payload.get("body")
    if isinstance(direct, str):
        return direct.strip()
    message = payload.get("message")
    if isinstance(message, str):
        return message.strip()
    if isinstance(message, dict):
        parts = message.get("parts")
        if isinstance(parts, list):
            text = "\n".join(str(part.get("text", "")) for part in parts if isinstance(part, dict) and part.get("text"))
            if text.strip():
                return text.strip()
        for key in ("body", "text"):
            if isinstance(message.get(key), str) and message[key].strip():
                return message[key].strip()
        return json.dumps(message, ensure_ascii=False, sort_keys=True)
    nested = payload.get("payload")
    if isinstance(nested, dict):
        return _extract_body(nested)
    return ""


def _payload_fingerprint(payload: Mapping[str, Any]) -> str:
    value = {key: payload[key] for key in sorted(payload) if key != "nonce"}
    return hashlib.sha256(json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")).hexdigest()


def _derived_nonce(payload: Mapping[str, Any]) -> str:
    message_value = payload.get("message") if isinstance(payload.get("message"), Mapping) else None
    source = str(payload.get("sourceAgentId") or payload.get("source_agent_id") or (message_value or {}).get("sourceAgentId", ""))
    context = str(payload.get("contextId") or payload.get("context_id") or (message_value or {}).get("contextId", ""))
    message = str(payload.get("messageId") or payload.get("message_id") or (message_value or {}).get("messageId", ""))
    return hashlib.sha256(f"snw-relay-nonce-v1\x00{source}\x00{context}\x00{message}".encode("utf-8")).hexdigest()


def registration_ingress_token(registration_token: str) -> str:
    """Match the loopback token emitted by linkd's ingress round tripper."""
    digest = hashlib.sha256(registration_token.encode("utf-8")).digest()
    return base64.urlsafe_b64encode(digest).decode("ascii").rstrip("=")


def _rpc_error(request_id: Any, code: int, message: str) -> dict[str, Any]:
    return {"jsonrpc": "2.0", "id": request_id, "error": {"code": code, "message": message}}


def _task_response(result: Mapping[str, Any]) -> dict[str, Any]:
    state = str(result.get("state") or "received")
    status_state = {
        "received": "TASK_STATE_WORKING",
        "queued": "TASK_STATE_SUBMITTED",
        "pending": "TASK_STATE_SUBMITTED",
        "submitted": "TASK_STATE_SUBMITTED",
        "working": "TASK_STATE_WORKING",
        "completed": "TASK_STATE_COMPLETED",
        "failed": "TASK_STATE_FAILED",
        "rejected": "TASK_STATE_REJECTED",
        "input_required": "TASK_STATE_INPUT_REQUIRED",
        "auth_required": "TASK_STATE_AUTH_REQUIRED",
        "cancel_requested": "TASK_STATE_CANCELED",
        "cancelled": "TASK_STATE_CANCELED",
        "canceled": "TASK_STATE_CANCELED",
    }.get(state, "TASK_STATE_WORKING")
    return {
        "id": str(result.get("taskId") or result.get("messageId") or ""),
        "contextId": str(result.get("contextId") or ""),
        "status": {"state": status_state},
        "metadata": {"snw-agent-link": dict(result)},
    }


def _task_event_response(result: Mapping[str, Any]) -> dict[str, Any]:
    return {"task": _task_response(result)}
