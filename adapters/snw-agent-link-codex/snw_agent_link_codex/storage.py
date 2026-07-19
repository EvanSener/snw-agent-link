"""Persistent thread bindings, signed session handles, and encrypted mailbox."""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import os
import secrets
import shutil
import sqlite3
import subprocess
import threading
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any


@dataclass(frozen=True)
class Binding:
    agent_id: str
    context_id: str
    thread_id: str
    last_turn_id: str
    active: bool
    created_at: int
    updated_at: int


@dataclass(frozen=True)
class MailboxItem:
    agent_id: str
    message_id: str
    context_id: str
    remote_agent_id: str
    direction: str
    summary: str
    body: str
    state: str
    task_id: str
    task_state: str
    received_at: int
    attached_thread_id: str
    metadata: dict[str, Any]


@dataclass(frozen=True)
class ObservedThread:
    agent_id: str
    thread_id: str
    last_turn_id: str
    cwd: str
    status: str
    updated_at: int


@dataclass(frozen=True)
class SessionHandle:
    agent_id: str
    thread_id: str
    turn_id: str
    context_id: str
    issued_at: int
    expires_at: int


class _OpenSSLCipher:
    VERSION = b"\x01"

    def __init__(self, data_dir: Path) -> None:
        self.data_dir = data_dir
        self.openssl = os.environ.get("SNW_AGENT_LINK_OPENSSL") or shutil.which("openssl")
        if not self.openssl:
            raise RuntimeError("OpenSSL is required for encrypted Codex mailbox storage")
        key = _load_or_create_key(data_dir / "mailbox.key", 64)
        self.encryption_key = key[:32]
        self.authentication_key = key[32:]

    def encrypt(self, value: str) -> bytes:
        nonce = secrets.token_bytes(16)
        ciphertext = self._crypt(value.encode("utf-8"), nonce, decrypt=False)
        authenticated = self.VERSION + nonce + ciphertext
        tag = hmac.new(self.authentication_key, authenticated, hashlib.sha256).digest()
        return self.VERSION + nonce + tag + ciphertext

    def decrypt(self, value: bytes) -> str:
        if len(value) < 49 or value[:1] != self.VERSION:
            raise ValueError("unsupported encrypted mailbox value")
        nonce = value[1:17]
        tag = value[17:49]
        ciphertext = value[49:]
        expected = hmac.new(
            self.authentication_key,
            self.VERSION + nonce + ciphertext,
            hashlib.sha256,
        ).digest()
        if not hmac.compare_digest(tag, expected):
            raise ValueError("encrypted mailbox authentication failed")
        return self._crypt(ciphertext, nonce, decrypt=True).decode("utf-8")

    def _crypt(self, value: bytes, nonce: bytes, *, decrypt: bool) -> bytes:
        command = [
            self.openssl,
            "enc",
            "-aes-256-ctr",
            "-nosalt",
            "-K",
            self.encryption_key.hex(),
            "-iv",
            nonce.hex(),
        ]
        if decrypt:
            command.append("-d")
        process = subprocess.run(
            command,
            input=value,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
        )
        if process.returncode:
            raise RuntimeError(process.stderr.decode("utf-8", errors="replace").strip() or "OpenSSL mailbox encryption failed")
        return process.stdout


class SessionHandleSigner:
    def __init__(self, key: bytes) -> None:
        if len(key) != 32:
            raise ValueError("session handle key must be 32 bytes")
        self.key = key

    @classmethod
    def from_data_dir(cls, data_dir: Path | str) -> SessionHandleSigner:
        root = Path(data_dir)
        root.mkdir(mode=0o700, parents=True, exist_ok=True)
        os.chmod(root, 0o700)
        return cls(_load_or_create_key(root / "session-handle.key", 32))

    def issue(
        self,
        agent_id: str,
        thread_id: str,
        *,
        turn_id: str = "",
        context_id: str = "",
        ttl_seconds: int = 8 * 60 * 60,
        now: int | None = None,
    ) -> str:
        issued_at = int(time.time() if now is None else now)
        payload = {
            "v": 1,
            "aid": agent_id,
            "tid": thread_id,
            "turn": turn_id,
            "ctx": context_id,
            "iat": issued_at,
            "exp": issued_at + ttl_seconds,
            "nonce": secrets.token_urlsafe(16),
        }
        encoded = _b64url(json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8"))
        signature = _b64url(hmac.new(self.key, encoded.encode("ascii"), hashlib.sha256).digest())
        return encoded + "." + signature

    def verify(
        self,
        token: str,
        *,
        expected_agent_id: str = "",
        now: int | None = None,
    ) -> SessionHandle:
        try:
            encoded, provided_signature = token.split(".", 1)
            expected_signature = _b64url(hmac.new(self.key, encoded.encode("ascii"), hashlib.sha256).digest())
            if not hmac.compare_digest(provided_signature, expected_signature):
                raise ValueError("session_handle signature is invalid")
            payload = json.loads(_b64url_decode(encoded))
        except (ValueError, json.JSONDecodeError, UnicodeDecodeError) as exc:
            if isinstance(exc, ValueError) and str(exc).startswith("session_handle"):
                raise
            raise ValueError("session_handle is malformed") from exc
        current = int(time.time() if now is None else now)
        if payload.get("v") != 1 or not payload.get("aid") or not payload.get("tid"):
            raise ValueError("session_handle claims are incomplete")
        if int(payload.get("exp", 0)) < current:
            raise ValueError("session_handle has expired")
        if int(payload.get("iat", 0)) > current + 300:
            raise ValueError("session_handle issue time is invalid")
        if expected_agent_id and payload["aid"] != expected_agent_id:
            raise ValueError("session_handle belongs to another Agent")
        return SessionHandle(
            agent_id=str(payload["aid"]),
            thread_id=str(payload["tid"]),
            turn_id=str(payload.get("turn", "")),
            context_id=str(payload.get("ctx", "")),
            issued_at=int(payload["iat"]),
            expires_at=int(payload["exp"]),
        )


class MailboxStore:
    def __init__(self, data_dir: Path | str) -> None:
        self.data_dir = Path(data_dir)
        self.data_dir.mkdir(mode=0o700, parents=True, exist_ok=True)
        os.chmod(self.data_dir, 0o700)
        self.database_path = self.data_dir / "adapter.sqlite3"
        self._cipher = _OpenSSLCipher(self.data_dir)
        self._lock = threading.RLock()
        self._closed = False
        self._db = sqlite3.connect(self.database_path, check_same_thread=False)
        os.chmod(self.database_path, 0o600)
        self._db.row_factory = sqlite3.Row
        self._db.execute("PRAGMA journal_mode=WAL")
        self._db.execute("PRAGMA foreign_keys=ON")
        self._db.execute("PRAGMA secure_delete=ON")
        self._migrate()

    def _migrate(self) -> None:
        with self._db:
            self._db.executescript(
                """
                CREATE TABLE IF NOT EXISTS bindings (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    agent_id TEXT NOT NULL,
                    context_id TEXT NOT NULL,
                    thread_id TEXT NOT NULL,
                    last_turn_id TEXT NOT NULL DEFAULT '',
                    active INTEGER NOT NULL,
                    created_at INTEGER NOT NULL,
                    updated_at INTEGER NOT NULL,
                    UNIQUE(agent_id, context_id, thread_id)
                );
                CREATE UNIQUE INDEX IF NOT EXISTS bindings_one_active
                    ON bindings(agent_id, context_id) WHERE active = 1;
                CREATE TABLE IF NOT EXISTS observed_threads (
                    agent_id TEXT NOT NULL,
                    thread_id TEXT NOT NULL,
                    last_turn_id TEXT NOT NULL DEFAULT '',
                    cwd TEXT NOT NULL DEFAULT '',
                    status TEXT NOT NULL DEFAULT 'active',
                    updated_at INTEGER NOT NULL,
                    PRIMARY KEY(agent_id, thread_id)
                );
                CREATE TABLE IF NOT EXISTS mailbox_items (
                    agent_id TEXT NOT NULL,
                    message_id TEXT NOT NULL,
                    context_id TEXT NOT NULL,
                    remote_agent_id TEXT NOT NULL,
                    direction TEXT NOT NULL,
                    summary BLOB NOT NULL,
                    body BLOB NOT NULL,
                    metadata BLOB NOT NULL,
                    state TEXT NOT NULL,
                    task_id TEXT NOT NULL DEFAULT '',
                    task_state TEXT NOT NULL DEFAULT '',
                    received_at INTEGER NOT NULL,
                    read_at INTEGER,
                    attached_thread_id TEXT NOT NULL DEFAULT '',
                    attached_at INTEGER,
                    PRIMARY KEY(agent_id, message_id)
                );
                CREATE INDEX IF NOT EXISTS mailbox_unread
                    ON mailbox_items(agent_id, state, received_at DESC);
                CREATE INDEX IF NOT EXISTS mailbox_context
                    ON mailbox_items(agent_id, context_id, received_at DESC);
                """
            )
            columns = {
                str(row[1])
                for row in self._db.execute("PRAGMA table_info(mailbox_items)").fetchall()
            }
            if "task_state" not in columns:
                self._db.execute(
                    "ALTER TABLE mailbox_items ADD COLUMN task_state TEXT NOT NULL DEFAULT ''"
                )

    def bind_context(
        self,
        agent_id: str,
        context_id: str,
        thread_id: str,
        last_turn_id: str = "",
    ) -> Binding:
        if not agent_id or not context_id or not thread_id:
            raise ValueError("agent_id, context_id, and thread_id are required")
        now = int(time.time())
        with self._lock, self._db:
            self._db.execute(
                "UPDATE bindings SET active = 0, updated_at = ? WHERE agent_id = ? AND context_id = ? AND active = 1",
                (now, agent_id, context_id),
            )
            self._db.execute(
                """
                INSERT INTO bindings(agent_id, context_id, thread_id, last_turn_id, active, created_at, updated_at)
                VALUES (?, ?, ?, ?, 1, ?, ?)
                ON CONFLICT(agent_id, context_id, thread_id) DO UPDATE SET
                    last_turn_id = excluded.last_turn_id,
                    active = 1,
                    updated_at = excluded.updated_at
                """,
                (agent_id, context_id, thread_id, last_turn_id, now, now),
            )
        return self.active_binding(agent_id, context_id)

    def active_binding(self, agent_id: str, context_id: str) -> Binding:
        with self._lock:
            row = self._db.execute(
                "SELECT * FROM bindings WHERE agent_id = ? AND context_id = ? AND active = 1",
                (agent_id, context_id),
            ).fetchone()
        if row is None:
            raise KeyError(f"active binding not found: {agent_id}/{context_id}")
        return _binding(row)

    def binding_history(self, agent_id: str, context_id: str) -> list[Binding]:
        with self._lock:
            rows = self._db.execute(
                "SELECT * FROM bindings WHERE agent_id = ? AND context_id = ? ORDER BY id",
                (agent_id, context_id),
            ).fetchall()
        return [_binding(row) for row in rows]

    def detach_thread(self, agent_id: str, thread_id: str) -> int:
        now = int(time.time())
        with self._lock, self._db:
            result = self._db.execute(
                "UPDATE bindings SET active = 0, updated_at = ? WHERE agent_id = ? AND thread_id = ? AND active = 1",
                (now, agent_id, thread_id),
            )
            self.observe_thread(agent_id, thread_id, status="detached")
        return int(result.rowcount)

    def observe_thread(
        self,
        agent_id: str,
        thread_id: str,
        *,
        last_turn_id: str = "",
        cwd: str = "",
        status: str = "active",
    ) -> None:
        if not agent_id or not thread_id:
            return
        now = int(time.time())
        with self._lock, self._db:
            self._db.execute(
                """
                INSERT INTO observed_threads(agent_id, thread_id, last_turn_id, cwd, status, updated_at)
                VALUES (?, ?, ?, ?, ?, ?)
                ON CONFLICT(agent_id, thread_id) DO UPDATE SET
                    last_turn_id = CASE WHEN excluded.last_turn_id = '' THEN observed_threads.last_turn_id ELSE excluded.last_turn_id END,
                    cwd = CASE WHEN excluded.cwd = '' THEN observed_threads.cwd ELSE excluded.cwd END,
                    status = excluded.status,
                    updated_at = excluded.updated_at
                """,
                (agent_id, thread_id, last_turn_id, cwd, status, now),
            )

    def get_observed_thread(self, agent_id: str, thread_id: str) -> ObservedThread:
        with self._lock:
            row = self._db.execute(
                "SELECT * FROM observed_threads WHERE agent_id = ? AND thread_id = ?",
                (agent_id, thread_id),
            ).fetchone()
        if row is None:
            raise KeyError(f"observed thread not found: {agent_id}/{thread_id}")
        return ObservedThread(
            agent_id=row["agent_id"],
            thread_id=row["thread_id"],
            last_turn_id=row["last_turn_id"],
            cwd=row["cwd"],
            status=row["status"],
            updated_at=row["updated_at"],
        )

    def put_mailbox_item(
        self,
        *,
        agent_id: str,
        message_id: str,
        context_id: str,
        remote_agent_id: str,
        summary: str,
        body: str,
        direction: str = "inbound",
        state: str | None = None,
        task_id: str = "",
        task_state: str = "",
        received_at: int | None = None,
        metadata: dict[str, Any] | None = None,
    ) -> None:
        if not agent_id or not message_id or not context_id:
            raise ValueError("agent_id, message_id, and context_id are required")
        item_state = state or ("unread" if direction == "inbound" else "sent")
        item_task_state = task_state or ("received" if direction == "inbound" else item_state)
        timestamp = int(time.time() if received_at is None else received_at)
        encrypted_summary = self._cipher.encrypt(summary)
        encrypted_body = self._cipher.encrypt(body)
        encrypted_metadata = self._cipher.encrypt(json.dumps(metadata or {}, sort_keys=True, ensure_ascii=False))
        with self._lock, self._db:
            self._db.execute(
                """
                INSERT INTO mailbox_items(
                    agent_id, message_id, context_id, remote_agent_id, direction,
                    summary, body, metadata, state, task_id, task_state, received_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(agent_id, message_id) DO UPDATE SET
                    context_id = excluded.context_id,
                    remote_agent_id = excluded.remote_agent_id,
                    summary = excluded.summary,
                    body = excluded.body,
                    metadata = excluded.metadata,
                    task_id = CASE WHEN excluded.task_id = '' THEN mailbox_items.task_id ELSE excluded.task_id END,
                    task_state = CASE WHEN excluded.task_state = '' THEN mailbox_items.task_state ELSE excluded.task_state END
                """,
                (
                    agent_id,
                    message_id,
                    context_id,
                    remote_agent_id,
                    direction,
                    encrypted_summary,
                    encrypted_body,
                    encrypted_metadata,
                    item_state,
                    task_id,
                    item_task_state,
                    timestamp,
                ),
            )

    def find_mailbox_item(self, agent_id: str, message_id: str) -> MailboxItem | None:
        """Return a mailbox item without changing its read state."""
        with self._lock:
            row = self._db.execute(
                "SELECT * FROM mailbox_items WHERE agent_id = ? AND message_id = ?",
                (agent_id, message_id),
            ).fetchone()
        return self._mailbox_item(row) if row is not None else None

    def find_task(self, agent_id: str, task_id: str) -> MailboxItem | None:
        """Find the durable local task associated with a mailbox item."""
        if not task_id:
            return None
        with self._lock:
            row = self._db.execute(
                "SELECT * FROM mailbox_items WHERE agent_id = ? AND task_id = ? ORDER BY received_at DESC LIMIT 1",
                (agent_id, task_id),
            ).fetchone()
        return self._mailbox_item(row) if row is not None else None

    def update_task_state(self, agent_id: str, task_id: str, task_state: str) -> MailboxItem:
        if not task_id or not task_state:
            raise ValueError("task_id and task_state are required")
        with self._lock, self._db:
            result = self._db.execute(
                "UPDATE mailbox_items SET task_state = ? WHERE agent_id = ? AND task_id = ?",
                (task_state, agent_id, task_id),
            )
            if result.rowcount == 0:
                raise KeyError(f"task not found: {task_id}")
            row = self._db.execute(
                "SELECT * FROM mailbox_items WHERE agent_id = ? AND task_id = ? ORDER BY received_at DESC LIMIT 1",
                (agent_id, task_id),
            ).fetchone()
        return self._mailbox_item(row)

    def list_mailbox(
        self,
        agent_id: str,
        *,
        unread_only: bool = False,
        context_id: str = "",
        limit: int = 100,
    ) -> list[MailboxItem]:
        clauses = ["agent_id = ?"]
        params: list[Any] = [agent_id]
        if unread_only:
            clauses.append("state = 'unread'")
        if context_id:
            clauses.append("context_id = ?")
            params.append(context_id)
        params.append(max(1, min(limit, 500)))
        with self._lock:
            rows = self._db.execute(
                "SELECT * FROM mailbox_items WHERE " + " AND ".join(clauses) + " ORDER BY received_at DESC LIMIT ?",
                params,
            ).fetchall()
        return [self._mailbox_item(row) for row in rows]

    def read_mailbox(self, agent_id: str, message_id: str, *, mark_read: bool = True) -> MailboxItem:
        with self._lock, self._db:
            row = self._db.execute(
                "SELECT * FROM mailbox_items WHERE agent_id = ? AND message_id = ?",
                (agent_id, message_id),
            ).fetchone()
            if row is None:
                raise KeyError(f"mailbox item not found: {message_id}")
            if mark_read and row["state"] == "unread":
                self._db.execute(
                    "UPDATE mailbox_items SET state = 'read', read_at = ? WHERE agent_id = ? AND message_id = ?",
                    (int(time.time()), agent_id, message_id),
                )
                row = self._db.execute(
                    "SELECT * FROM mailbox_items WHERE agent_id = ? AND message_id = ?",
                    (agent_id, message_id),
                ).fetchone()
        return self._mailbox_item(row)

    def mark_attached(self, agent_id: str, message_ids: list[str], thread_id: str) -> None:
        if not message_ids:
            raise ValueError("at least one message_id is required")
        now = int(time.time())
        with self._lock, self._db:
            for message_id in message_ids:
                result = self._db.execute(
                    """
                    UPDATE mailbox_items
                    SET state = 'attached', read_at = COALESCE(read_at, ?), attached_thread_id = ?, attached_at = ?
                    WHERE agent_id = ? AND message_id = ?
                    """,
                    (now, thread_id, now, agent_id, message_id),
                )
                if result.rowcount != 1:
                    raise KeyError(f"mailbox item not found: {message_id}")

    def unread_count(self, agent_id: str) -> int:
        with self._lock:
            row = self._db.execute(
                "SELECT COUNT(*) AS total FROM mailbox_items WHERE agent_id = ? AND state = 'unread'",
                (agent_id,),
            ).fetchone()
        return int(row["total"])

    def checkpoint(self) -> None:
        with self._lock:
            self._db.commit()
            self._db.execute("PRAGMA wal_checkpoint(TRUNCATE)")

    def close(self) -> None:
        if self._closed:
            return
        self._closed = True
        with self._lock:
            self._db.close()

    def _mailbox_item(self, row: sqlite3.Row) -> MailboxItem:
        return MailboxItem(
            agent_id=row["agent_id"],
            message_id=row["message_id"],
            context_id=row["context_id"],
            remote_agent_id=row["remote_agent_id"],
            direction=row["direction"],
            summary=self._cipher.decrypt(row["summary"]),
            body=self._cipher.decrypt(row["body"]),
            state=row["state"],
            task_id=row["task_id"],
            task_state=row["task_state"] if "task_state" in row.keys() else "",
            received_at=row["received_at"],
            attached_thread_id=row["attached_thread_id"],
            metadata=json.loads(self._cipher.decrypt(row["metadata"])),
        )


def _binding(row: sqlite3.Row) -> Binding:
    return Binding(
        agent_id=row["agent_id"],
        context_id=row["context_id"],
        thread_id=row["thread_id"],
        last_turn_id=row["last_turn_id"],
        active=bool(row["active"]),
        created_at=row["created_at"],
        updated_at=row["updated_at"],
    )


def _load_or_create_key(path: Path, size: int) -> bytes:
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    if path.exists():
        value = path.read_bytes()
        if len(value) != size:
            raise RuntimeError(f"invalid key length for {path.name}; restore the original backup")
        os.chmod(path, 0o600)
        return value
    value = secrets.token_bytes(size)
    try:
        descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    except FileExistsError:
        return _load_or_create_key(path, size)
    with os.fdopen(descriptor, "wb") as stream:
        stream.write(value)
        stream.flush()
        os.fsync(stream.fileno())
    return value


def _b64url(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).rstrip(b"=").decode("ascii")


def _b64url_decode(value: str) -> bytes:
    return base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))
