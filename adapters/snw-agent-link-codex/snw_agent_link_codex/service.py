"""Codex adapter orchestration for thread bindings and mailbox."""

from __future__ import annotations

import json
import threading
import uuid
from typing import Any

from .storage import MailboxStore, SessionHandleSigner


class AdapterService:
    def __init__(self, store: MailboxStore, signer: SessionHandleSigner, link_client: Any, app_server: Any = None) -> None:
        self.store = store
        self.signer = signer
        self.link = link_client
        self.app = app_server
        self._receive_lock = threading.RLock()

    def _thread(self, agent_id: str, session_handle: str):
        if self.app is None:
            raise RuntimeError("Codex app-server is required for thread operations")
        handle = self.signer.verify(session_handle, expected_agent_id=agent_id)
        snapshot = self.app.load_thread(handle.thread_id)
        self.store.observe_thread(agent_id, handle.thread_id, last_turn_id=handle.turn_id)
        return handle, snapshot

    def send_message(
        self,
        *,
        agent_id: str,
        target_agent_id: str,
        message: str,
        session_handle: str,
        context_id: str = "",
        attachments: list[Any] | None = None,
    ) -> dict[str, Any]:
        handle, snapshot = self._thread(agent_id, session_handle)
        resolved_context = context_id or handle.context_id or str(uuid.uuid4())
        previous_binding = _active_binding(self.store, agent_id, resolved_context, handle.thread_id)
        thread_sync = _thread_sync(snapshot, previous_binding)
        self.store.bind_context(agent_id, resolved_context, handle.thread_id, _last_turn(snapshot))
        message_id = str(uuid.uuid7()) if hasattr(uuid, "uuid7") else str(uuid.uuid4())
        attachment_values = list(attachments or [])
        if attachment_values and isinstance(attachment_values[0], str):
            uploader = getattr(self.link, "upload_attachments", None)
            if uploader is None:
                raise RuntimeError("link client does not support attachments")
            attachment_values = uploader(
                agent_id,
                attachment_values,
                target_agent_id=target_agent_id,
                context_id=resolved_context,
            )
        payload: dict[str, Any] = {
            "message": {
                "messageId": message_id,
                "role": "user",
                "contextId": resolved_context,
                "parts": [{"kind": "text", "text": message}],
                "metadata": {
                    "snw-agent-link/session": {
                        "threadId": handle.thread_id,
                        "turnId": handle.turn_id,
                        "contextId": resolved_context,
                    },
                    "snw-agent-link/threadSync": thread_sync,
                },
            }
        }
        if attachment_values:
            payload["message"]["metadata"]["snw-agent-link/attachments"] = attachment_values
        result = self.link.call(
            "message.send",
            {
                "sourceAgentId": agent_id,
                "targetAgentId": target_agent_id,
                "contextId": resolved_context,
                "messageId": message_id,
                "payload": payload,
            },
        )
        state = result.get("state", "sent") if isinstance(result, dict) else "sent"
        self.store.put_mailbox_item(
            agent_id=agent_id,
            message_id=message_id,
            context_id=resolved_context,
            remote_agent_id=target_agent_id,
            summary=" ".join(message.split())[:240],
            body=message,
            direction="outbound",
            state=state,
            task_id=str(result.get("messageId", message_id)) if isinstance(result, dict) else message_id,
            metadata={"attachments": attachment_values, "threadSync": thread_sync},
        )
        return result

    def attach_inbox(self, *, agent_id: str, message_ids: list[str], session_handle: str) -> dict[str, Any]:
        handle, snapshot = self._thread(agent_id, session_handle)
        items = [self.store.read_mailbox(agent_id, value, mark_read=False) for value in message_ids]
        if not items:
            raise ValueError("message_ids must not be empty")
        for item in items:
            self.app.attach_external_message(handle.thread_id, item.remote_agent_id, item.context_id, item.body)
            self.store.bind_context(agent_id, item.context_id, handle.thread_id, _last_turn(snapshot))
        self.store.mark_attached(agent_id, message_ids, handle.thread_id)
        return {
            "threadId": handle.thread_id,
            "messageIds": message_ids,
            "contextIds": list(dict.fromkeys(item.context_id for item in items)),
        }

    def sync_inbox(self, agent_id: str) -> int:
        result = self.link.call("mailbox.list", {"sourceAgentId": agent_id, "unreadOnly": False})
        values = result.get("items", []) if isinstance(result, dict) else result
        if not isinstance(values, list):
            return 0
        imported = 0
        for value in values:
            if not isinstance(value, dict):
                continue
            message_id = str(value.get("messageId") or value.get("id") or "")
            context_id = str(value.get("contextId") or "")
            remote_agent_id = str(value.get("sourceAgentId") or value.get("remoteAgentId") or "")
            if not message_id or not context_id or not remote_agent_id:
                continue
            raw_body = value.get("body", value.get("payload", value.get("message", "")))
            body = raw_body if isinstance(raw_body, str) else json.dumps(raw_body, ensure_ascii=False, sort_keys=True)
            message_value, extracted_body, extracted_metadata = _decode_a2a_message(body)
            if message_value is not None:
                body = extracted_body
                if extracted_metadata:
                    value_metadata = extracted_metadata
                else:
                    value_metadata = value.get("metadata") if isinstance(value.get("metadata"), dict) else {}
            else:
                value_metadata = value.get("metadata") if isinstance(value.get("metadata"), dict) else {}
            self.store.put_mailbox_item(
                agent_id=agent_id,
                message_id=message_id,
                context_id=context_id,
                remote_agent_id=remote_agent_id,
                summary=str(value.get("summary") or " ".join(body.split())[:240]),
                body=body,
                direction="inbound",
                state=str(value.get("state") or "unread"),
                task_id=str(value.get("taskId") or ""),
                received_at=value.get("receivedAt") if isinstance(value.get("receivedAt"), int) else None,
                metadata=value_metadata,
            )
            imported += 1
        return imported

    def list_inbox(self, agent_id: str, *, unread_only: bool = True, context_id: str = "", sync: bool = True) -> dict[str, Any]:
        if sync:
            try:
                self.sync_inbox(agent_id)
            except (OSError, RuntimeError):
                pass
        items = self.store.list_mailbox(agent_id, unread_only=unread_only, context_id=context_id)
        return {"items": [_mailbox_dict(item, include_body=False) for item in items], "unreadCount": self.store.unread_count(agent_id)}

    def read_inbox(self, agent_id: str, message_id: str) -> dict[str, Any]:
        try:
            item = self.store.read_mailbox(agent_id, message_id)
        except KeyError:
            self.sync_inbox(agent_id)
            item = self.store.read_mailbox(agent_id, message_id)
        return _mailbox_dict(item, include_body=True)

    def binding_status(self, agent_id: str, context_id: str) -> dict[str, Any]:
        try:
            active = self.store.active_binding(agent_id, context_id)
        except KeyError:
            return {"active": None, "history": []}
        return {"active": _binding_dict(active), "history": [_binding_dict(item) for item in self.store.binding_history(agent_id, context_id)]}

    def receive_message(
        self,
        *,
        agent_id: str,
        remote_agent_id: str,
        context_id: str,
        message_id: str,
        body: str,
        cwd: str = "",
        task_id: str = "",
        metadata: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        if not context_id or not message_id:
            raise ValueError("context_id and message_id are required")
        if not agent_id or not remote_agent_id:
            raise ValueError("agent_id and remote_agent_id are required")
        resolved_task_id = task_id or message_id
        inbound_metadata = dict(metadata or {})
        with self._receive_lock:
            existing = self.store.find_mailbox_item(agent_id, message_id)
            if existing is not None:
                if (
                    existing.context_id != context_id
                    or existing.remote_agent_id != remote_agent_id
                    or existing.body != body
                ):
                    raise ValueError("message_id is already associated with different inbound content")
                if existing.task_id and existing.task_id != resolved_task_id:
                    raise ValueError("message_id is already associated with a different task")
                try:
                    binding = self.store.active_binding(agent_id, context_id)
                except KeyError:
                    binding = None
                if binding is not None:
                    return _receive_result(existing, binding.thread_id, duplicate=True)

            existing_task = self.store.find_task(agent_id, resolved_task_id)
            if existing_task is not None and existing_task.message_id != message_id:
                raise ValueError("task_id is already associated with another message")

            # Persist the mailbox before talking to app-server. If Codex is down,
            # the message remains durable and a later relay retry can finish the
            # context/thread binding without losing the inbound task.
            self.store.put_mailbox_item(
                agent_id=agent_id,
                message_id=message_id,
                context_id=context_id,
                remote_agent_id=remote_agent_id,
                summary=" ".join(body.split())[:240],
                body=body,
                task_id=resolved_task_id,
                task_state="received",
                metadata=inbound_metadata,
            )

            try:
                binding = self.store.active_binding(agent_id, context_id)
            except KeyError:
                binding = None
            thread_id = binding.thread_id if binding is not None else ""
            attach_error = ""
            if not thread_id and self.app is not None:
                started = self.app.start_thread(cwd=cwd)
                thread = started.get("thread") if isinstance(started, dict) else None
                thread_id = str((thread or {}).get("id", ""))
                if not thread_id:
                    attach_error = "Codex app-server did not return a thread id"
                else:
                    self.store.bind_context(agent_id, context_id, thread_id)
            if thread_id and self.app is not None and hasattr(self.app, "attach_external_message"):
                try:
                    self.app.attach_external_message(thread_id, remote_agent_id, context_id, body)
                except Exception as exc:
                    # The mailbox and binding are still durable. Do not fabricate
                    # a model response; report the attach failure as task state.
                    attach_error = str(exc) or "Codex app-server rejected inbound user input"

            if thread_id or attach_error:
                updated_metadata = dict(inbound_metadata)
                updated_metadata["threadId"] = thread_id
                if attach_error:
                    updated_metadata["attachError"] = attach_error
                self.store.put_mailbox_item(
                    agent_id=agent_id,
                    message_id=message_id,
                    context_id=context_id,
                    remote_agent_id=remote_agent_id,
                    summary=" ".join(body.split())[:240],
                    body=body,
                    task_id=resolved_task_id,
                    task_state="received",
                    metadata=updated_metadata,
                )
            item = self.store.find_mailbox_item(agent_id, message_id)
            if item is None:
                raise RuntimeError("inbound mailbox item was not persisted")
            return _receive_result(item, thread_id, duplicate=False, attach_error=attach_error)

    def task_status(self, agent_id: str, task_id: str) -> dict[str, Any]:
        item = self.store.find_task(agent_id, task_id)
        if item is None:
            raise KeyError(f"task not found: {task_id}")
        return _task_dict(item)

    def cancel_task(self, agent_id: str, task_id: str) -> dict[str, Any]:
        item = self.store.find_task(agent_id, task_id)
        if item is None:
            raise KeyError(f"task not found: {task_id}")
        if item.task_state in {"received", "queued", "pending"}:
            item = self.store.update_task_state(agent_id, task_id, "cancel_requested")
        return _task_dict(item)


def _last_turn(snapshot: dict[str, Any]) -> str:
    thread = snapshot.get("thread") if isinstance(snapshot, dict) else None
    turns = thread.get("turns") if isinstance(thread, dict) else None
    return str(turns[-1].get("id", "")) if turns else ""


def _active_binding(store: Any, agent_id: str, context_id: str, thread_id: str) -> Any:
    try:
        binding = store.active_binding(agent_id, context_id)
    except KeyError:
        return None
    return binding if binding.thread_id == thread_id else None


def _thread_sync(snapshot: dict[str, Any], previous_binding: Any) -> dict[str, Any]:
    turns = _visible_turns(snapshot)
    previous_turn_id = str(getattr(previous_binding, "last_turn_id", "") or "")
    if not previous_turn_id:
        return {"mode": "snapshot", "baseTurnId": "", "turns": turns}
    matching_index = next((index for index, turn in enumerate(turns) if turn.get("id") == previous_turn_id), -1)
    if matching_index < 0:
        return {"mode": "snapshot", "baseTurnId": previous_turn_id, "turns": turns}
    # app-server may append visible items while retaining the turn id.
    return {"mode": "delta", "baseTurnId": previous_turn_id, "turns": turns[matching_index:]}


def _visible_turns(snapshot: dict[str, Any]) -> list[dict[str, Any]]:
    thread = snapshot.get("thread") if isinstance(snapshot, dict) else None
    raw_turns = thread.get("turns") if isinstance(thread, dict) else None
    if not isinstance(raw_turns, list):
        return []
    visible: list[dict[str, Any]] = []
    for raw_turn in raw_turns:
        if not isinstance(raw_turn, dict):
            continue
        turn = {
            key: value
            for key, value in raw_turn.items()
            if key not in {"reasoning", "hidden", "encryptedContent"}
        }
        raw_items = raw_turn.get("items")
        if isinstance(raw_items, list):
            items: list[dict[str, Any]] = []
            for raw_item in raw_items:
                if not isinstance(raw_item, dict):
                    continue
                item_type = str(raw_item.get("type", "")).lower()
                if "reason" in item_type or item_type in {"system", "systemmessage", "developermessage"}:
                    continue
                items.append(
                    {
                        key: value
                        for key, value in raw_item.items()
                        if key not in {"reasoning", "hidden", "encryptedContent"}
                    }
                )
            turn["items"] = items
        visible.append(turn)
    return visible


def _decode_a2a_message(body: str) -> tuple[dict[str, Any] | None, str, dict[str, Any]]:
    try:
        envelope = json.loads(body)
    except (TypeError, json.JSONDecodeError):
        return None, body, {}
    if not isinstance(envelope, dict):
        return None, body, {}
    message = envelope.get("message")
    if not isinstance(message, dict):
        params = envelope.get("params")
        message = params.get("message") if isinstance(params, dict) else None
    if not isinstance(message, dict):
        return None, body, {}
    parts = message.get("parts")
    text_parts = [str(part.get("text", "")) for part in parts if isinstance(part, dict) and part.get("kind") == "text"] if isinstance(parts, list) else []
    extracted_body = "\n".join(part for part in text_parts if part)
    if not extracted_body:
        extracted_body = json.dumps(message, ensure_ascii=False, sort_keys=True)
    metadata = message.get("metadata") if isinstance(message.get("metadata"), dict) else {}
    return message, extracted_body, metadata


def _mailbox_dict(item: Any, *, include_body: bool) -> dict[str, Any]:
    value = {
        "agentId": item.agent_id,
        "messageId": item.message_id,
        "contextId": item.context_id,
        "remoteAgentId": item.remote_agent_id,
        "direction": item.direction,
        "summary": item.summary,
        "state": item.state,
        "taskId": item.task_id,
        "taskState": item.task_state,
        "receivedAt": item.received_at,
        "attachedThreadId": item.attached_thread_id,
    }
    if include_body:
        value["body"] = item.body
        value["metadata"] = item.metadata
    return value


def _binding_dict(item: Any) -> dict[str, Any]:
    return {
        "agentId": item.agent_id,
        "contextId": item.context_id,
        "threadId": item.thread_id,
        "lastTurnId": item.last_turn_id,
        "active": item.active,
        "createdAt": item.created_at,
        "updatedAt": item.updated_at,
    }


def _task_dict(item: Any) -> dict[str, Any]:
    return {
        "taskId": item.task_id,
        "messageId": item.message_id,
        "contextId": item.context_id,
        "sourceAgentId": item.remote_agent_id,
        "state": item.task_state or item.state,
        "threadId": str(item.metadata.get("threadId", "")),
        "receivedAt": item.received_at,
    }


def _receive_result(item: Any, thread_id: str, *, duplicate: bool, attach_error: str = "") -> dict[str, Any]:
    result = {
        "threadId": thread_id,
        "contextId": item.context_id,
        "messageId": item.message_id,
        "taskId": item.task_id,
        "state": item.task_state or "received",
        "duplicate": duplicate,
    }
    if attach_error:
        result["attachError"] = attach_error
    return result
