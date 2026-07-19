"""Local linkd IPC client used by the Codex adapter."""

from __future__ import annotations

import base64
import hashlib
import json
import os
import socket
import subprocess
import uuid
from pathlib import Path
from typing import Any


class LinkIPCClient:
    def __init__(
        self,
        endpoint: str,
        *,
        registration_token: str = "",
        capability_session: str = "",
        cli_command: str = "snw-agent-link",
    ) -> None:
        self.endpoint = endpoint
        self.registration_token = registration_token
        self.capability_session = capability_session
        self.cli_command = cli_command

    @classmethod
    def from_env(cls) -> LinkIPCClient:
        link_data = Path(os.environ.get("SNW_AGENT_LINK_DATA_DIR", Path.home() / ".snw-agent-link"))
        endpoint = os.environ.get("SNW_AGENT_LINK_IPC", str(link_data / "snw-agent-link.sock"))
        return cls(
            endpoint,
            registration_token=os.environ.get("SNW_AGENT_LINK_REGISTRATION_TOKEN", ""),
            capability_session=os.environ.get("SNW_AGENT_LINK_CAPABILITY_SESSION", ""),
            cli_command=os.environ.get("SNW_AGENT_LINK_CLI", "snw-agent-link"),
        )

    def call(self, method: str, params: dict[str, Any]) -> Any:
        request_params = dict(params)
        if method.startswith(("message.", "mailbox.", "attachment.")):
            if self.capability_session:
                request_params.setdefault("capabilitySession", self.capability_session)
            elif self.registration_token:
                request_params.setdefault("registrationToken", self.registration_token)
        if os.name == "nt":
            process = subprocess.run(
                [self.cli_command, "--ipc", self.endpoint, method],
                input=json.dumps(request_params).encode("utf-8"),
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                check=False,
            )
            if process.returncode:
                raise RuntimeError(process.stderr.decode("utf-8", errors="replace").strip() or "snw-agent-link failed")
            return json.loads(process.stdout or b"null")
        request = {
            "version": "1.0",
            "requestId": str(uuid.uuid4()),
            "method": method,
            "params": request_params,
        }
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as connection:
            connection.settimeout(30)
            connection.connect(self.endpoint)
            connection.sendall((json.dumps(request, separators=(",", ":")) + "\n").encode("utf-8"))
            data = bytearray()
            while b"\n" not in data:
                chunk = connection.recv(65536)
                if not chunk:
                    break
                data.extend(chunk)
        if not data:
            raise RuntimeError("linkd IPC closed without a response")
        response = json.loads(bytes(data).splitlines()[0])
        if response.get("error"):
            raise RuntimeError(response["error"].get("message", "linkd IPC error"))
        return response.get("result")

    def upload_attachments(self, agent_id: str, paths: list[str], *, target_agent_id: str = "", context_id: str = "") -> list[dict[str, Any]]:
        if not target_agent_id or not context_id:
            raise ValueError("target_agent_id and context_id are required for attachment grants")
        uploaded: list[dict[str, Any]] = []
        for raw_path in paths:
            path = Path(raw_path).expanduser().resolve()
            if not path.is_file() or path.stat().st_size > 64 * 1024 * 1024:
                raise ValueError(f"attachment must be a regular file no larger than 64 MiB: {path.name}")
            digest = hashlib.sha256()
            with path.open("rb") as stream:
                for chunk in iter(lambda: stream.read(1024 * 1024), b""):
                    digest.update(chunk)
            initialized = self.call(
                "attachment.init",
                {
                    "agentId": agent_id,
                    "targetAgentId": target_agent_id,
                    "contextId": context_id,
                    "name": path.name,
                    "size": path.stat().st_size,
                    "sha256": digest.hexdigest(),
                },
            )
            metadata = initialized["attachment"]
            blob_id = metadata["blobId"]
            offset = 0
            with path.open("rb") as stream:
                while chunk := stream.read(4 * 1024 * 1024):
                    self.call(
                        "attachment.chunk",
                        {
                            "agentId": agent_id,
                            "blobId": blob_id,
                            "offset": offset,
                            "data": base64.b64encode(chunk).decode("ascii"),
                        },
                    )
                    offset += len(chunk)
            completed = self.call(
                "attachment.complete",
                {
                    "agentId": agent_id,
                    "blobId": blob_id,
                    "targetAgentId": target_agent_id,
                    "contextId": context_id,
                },
            )
            value = completed["attachment"]
            grant = self.call(
                "attachment.grant",
                {
                    "agentId": agent_id,
                    "blobId": blob_id,
                    "targetAgentId": target_agent_id,
                    "contextId": context_id,
                },
            )
            value = {**value, "grant": grant.get("grant", grant)}
            uploaded.append(value)
        return uploaded
