"""Codex lifecycle Hook runtime and executable entry."""

from __future__ import annotations

import json
import os
import sys
from pathlib import Path
from typing import Any, TextIO

from .storage import MailboxStore, SessionHandleSigner


def adapter_data_dir(env: dict[str, str] | None = None) -> Path:
    values = env or os.environ
    explicit = values.get("SNW_AGENT_LINK_ADAPTER_DATA_DIR")
    if explicit:
        root = Path(explicit).expanduser()
    elif values.get("PLUGIN_DATA"):
        root = Path(values["PLUGIN_DATA"]).expanduser()
    else:
        root = Path(values.get("SNW_AGENT_LINK_DATA_DIR", Path.home() / ".snw-agent-link")) / "codex"
    root.mkdir(mode=0o700, parents=True, exist_ok=True)
    os.chmod(root, 0o700)
    return root


class HookRuntime:
    def __init__(self, store: MailboxStore, signer: SessionHandleSigner, agent_id: str) -> None:
        self.store = store
        self.signer = signer
        self.agent_id = agent_id

    def session_start(self, payload: dict[str, Any]) -> dict[str, Any]:
        thread_id = _required(payload, "session_id")
        self.store.observe_thread(self.agent_id, thread_id, cwd=str(payload.get("cwd", "")), status="active")
        token = self.signer.issue(self.agent_id, thread_id)
        return {
            "continue": True,
            "hookSpecificOutput": {
                "hookEventName": "SessionStart",
                "additionalContext": (
                    f"snw-agent-link session_handle={token} "
                    "仅绑定当前 Codex thread；外部正文必须由用户显式调用 agent_inbox_attach。"
                ),
            },
        }

    def user_prompt_submit(self, payload: dict[str, Any]) -> dict[str, Any]:
        thread_id = _required(payload, "session_id")
        turn_id = str(payload.get("turn_id", ""))
        self.store.observe_thread(
            self.agent_id,
            thread_id,
            last_turn_id=turn_id,
            cwd=str(payload.get("cwd", "")),
            status="active",
        )
        token = self.signer.issue(self.agent_id, thread_id, turn_id=turn_id)
        count = self.store.unread_count(self.agent_id)
        return {
            "continue": True,
            "hookSpecificOutput": {
                "hookEventName": "UserPromptSubmit",
                "additionalContext": (
                    f"snw-agent-link session_handle={token}。当前有 {count} 条未读外部 Agent 消息；"
                    "只可使用 agent_inbox_list/read 查看，并由用户显式调用 agent_inbox_attach。"
                ),
            },
        }

    def stop(self, payload: dict[str, Any]) -> dict[str, Any]:
        thread_id = _required(payload, "session_id")
        self.store.observe_thread(
            self.agent_id,
            thread_id,
            last_turn_id=str(payload.get("turn_id", "")),
            status="stopped",
        )
        return {"continue": True}


def run_hook(event_name: str, stdin: TextIO = sys.stdin, stdout: TextIO = sys.stdout) -> None:
    payload = json.load(stdin)
    data_dir = adapter_data_dir()
    agent_id = os.environ.get("SNW_AGENT_LINK_AGENT_ID", "")
    if not agent_id:
        raise ValueError("SNW_AGENT_LINK_AGENT_ID is required")
    store = MailboxStore(data_dir)
    try:
        runtime = HookRuntime(store, SessionHandleSigner.from_data_dir(data_dir), agent_id)
        output = {
            "SessionStart": runtime.session_start,
            "UserPromptSubmit": runtime.user_prompt_submit,
            "Stop": runtime.stop,
        }[event_name](payload)
        stdout.write(json.dumps(output, ensure_ascii=False) + "\n")
    finally:
        store.close()


def _required(payload: dict[str, Any], name: str) -> str:
    value = str(payload.get(name, ""))
    if not value:
        raise ValueError(f"hook field is required: {name}")
    return value
