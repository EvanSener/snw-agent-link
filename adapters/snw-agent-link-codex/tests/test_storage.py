import sqlite3
import tempfile
import unittest
from pathlib import Path


from snw_agent_link_codex.storage import MailboxStore, SessionHandleSigner


class StorageTest(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.root = Path(self.temp_dir.name)
        self.store = MailboxStore(self.root)

    def tearDown(self):
        self.store.close()
        self.temp_dir.cleanup()

    def test_rebinding_preserves_history_and_switches_active_thread(self):
        self.store.bind_context("agent-a", "context-1", "thread-old", "turn-old")
        self.store.bind_context("agent-a", "context-1", "thread-new", "turn-new")

        active = self.store.active_binding("agent-a", "context-1")
        history = self.store.binding_history("agent-a", "context-1")

        self.assertEqual(active.thread_id, "thread-new")
        self.assertEqual([item.thread_id for item in history], ["thread-old", "thread-new"])
        self.assertFalse(history[0].active)
        self.assertTrue(history[1].active)

    def test_binding_and_mailbox_survive_restart(self):
        self.store.bind_context("agent-a", "context-1", "thread-a", "turn-a")
        self.store.put_mailbox_item(
            agent_id="agent-a",
            message_id="message-1",
            context_id="context-1",
            remote_agent_id="agent-b",
            summary="unread summary",
            body="private mailbox body",
        )
        self.store.close()

        reopened = MailboxStore(self.root)
        try:
            self.assertEqual(reopened.active_binding("agent-a", "context-1").thread_id, "thread-a")
            item = reopened.read_mailbox("agent-a", "message-1", mark_read=False)
            self.assertEqual(item.body, "private mailbox body")
            self.assertEqual(item.state, "unread")
        finally:
            reopened.close()
        self.store = MailboxStore(self.root)

    def test_database_never_contains_plaintext_mailbox_content(self):
        self.store.put_mailbox_item(
            agent_id="agent-a",
            message_id="message-secret",
            context_id="context-secret",
            remote_agent_id="agent-b",
            summary="summary-plaintext-marker",
            body="body-plaintext-marker",
        )
        self.store.checkpoint()

        raw = (self.root / "adapter.sqlite3").read_bytes()
        self.assertNotIn(b"summary-plaintext-marker", raw)
        self.assertNotIn(b"body-plaintext-marker", raw)

    def test_read_and_attach_states_are_explicit(self):
        self.store.put_mailbox_item(
            agent_id="agent-a",
            message_id="message-1",
            context_id="context-1",
            remote_agent_id="agent-b",
            summary="hello",
            body="hello body",
        )

        self.assertEqual(self.store.unread_count("agent-a"), 1)
        self.assertEqual(self.store.read_mailbox("agent-a", "message-1").state, "read")
        self.store.mark_attached("agent-a", ["message-1"], "thread-new")
        attached = self.store.read_mailbox("agent-a", "message-1", mark_read=False)

        self.assertEqual(attached.state, "attached")
        self.assertEqual(attached.attached_thread_id, "thread-new")

    def test_signed_session_handle_binds_agent_and_thread(self):
        signer = SessionHandleSigner.from_data_dir(self.root)
        token = signer.issue("agent-a", "thread-a", ttl_seconds=60, now=1_000)

        payload = signer.verify(token, expected_agent_id="agent-a", now=1_010)

        self.assertEqual(payload.agent_id, "agent-a")
        self.assertEqual(payload.thread_id, "thread-a")
        with self.assertRaises(ValueError):
            signer.verify(token, expected_agent_id="agent-b", now=1_010)


if __name__ == "__main__":
    unittest.main()
