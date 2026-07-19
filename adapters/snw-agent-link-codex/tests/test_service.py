import tempfile
import unittest
from pathlib import Path


from snw_agent_link_codex.service import AdapterService
from snw_agent_link_codex.storage import MailboxStore, SessionHandleSigner


class FakeLinkClient:
    def __init__(self):
        self.calls = []
        self.upload_calls = []
        self.mailbox_items = []

    def call(self, method, params):
        self.calls.append((method, params))
        if method == "mailbox.list":
            return {"items": self.mailbox_items}
        if method == "message.send":
            return {"messageId": params["messageId"], "state": "pending"}
        return {}

    def upload_attachments(self, agent_id, paths, *, target_agent_id, context_id):
        self.upload_calls.append((agent_id, paths, target_agent_id, context_id))
        return [{"blobId": "blob-1", "grant": {"targetAgentId": target_agent_id, "contextId": context_id}}]


class FakeAppServer:
    def __init__(self):
        self.calls = []

    def load_thread(self, thread_id):
        self.calls.append(("load", thread_id, True))
        return {"thread": {"id": thread_id, "turns": [{"id": "turn-current", "items": []}]}}

    def attach_external_message(self, thread_id, remote_agent_id, context_id, body):
        self.calls.append(("attach", thread_id, remote_agent_id, context_id, body))
        return {"attached": True}

    def start_thread(self, *, cwd=""):
        self.calls.append(("start", cwd))
        return {"thread": {"id": "thread-inbound"}}


class AdapterServiceTest(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.root = Path(self.temp_dir.name)
        self.store = MailboxStore(self.root)
        self.signer = SessionHandleSigner.from_data_dir(self.root)
        self.link = FakeLinkClient()
        self.app = FakeAppServer()
        self.service = AdapterService(self.store, self.signer, self.link, self.app)

    def tearDown(self):
        self.store.close()
        self.temp_dir.cleanup()

    def handle(self, agent_id, thread_id):
        return self.signer.issue(agent_id, thread_id, ttl_seconds=600)

    def test_send_uses_verified_thread_and_persists_context_binding(self):
        result = self.service.send_message(
            agent_id="agent-a",
            target_agent_id="agent-b",
            message="please inspect",
            session_handle=self.handle("agent-a", "thread-a"),
            context_id="context-1",
        )

        self.assertEqual(result["state"], "pending")
        self.assertEqual(self.app.calls[0], ("load", "thread-a", True))
        self.assertEqual(self.store.active_binding("agent-a", "context-1").thread_id, "thread-a")
        self.assertEqual(self.link.calls[0][0], "message.send")
        sync = self.link.calls[0][1]["payload"]["message"]["metadata"]["snw-agent-link/threadSync"]
        self.assertEqual(sync["mode"], "snapshot")
        self.assertEqual(sync["turns"][0]["id"], "turn-current")

    def test_subsequent_send_uses_delta_from_last_synced_turn(self):
        handle = self.handle("agent-a", "thread-a")
        self.service.send_message(
            agent_id="agent-a",
            target_agent_id="agent-b",
            message="first",
            session_handle=handle,
            context_id="context-1",
        )
        self.service.send_message(
            agent_id="agent-a",
            target_agent_id="agent-b",
            message="second",
            session_handle=handle,
            context_id="context-1",
        )
        sync = self.link.calls[1][1]["payload"]["message"]["metadata"]["snw-agent-link/threadSync"]
        self.assertEqual(sync["mode"], "delta")
        self.assertEqual(sync["baseTurnId"], "turn-current")

    def test_explicit_attach_reads_target_thread_and_marks_mailbox(self):
        self.store.put_mailbox_item(
            agent_id="agent-a",
            message_id="message-1",
            context_id="context-1",
            remote_agent_id="agent-b",
            summary="progress",
            body="finished the task",
        )

        result = self.service.attach_inbox(
            agent_id="agent-a",
            message_ids=["message-1"],
            session_handle=self.handle("agent-a", "thread-new"),
        )

        self.assertEqual(result["threadId"], "thread-new")
        self.assertEqual(self.app.calls[0], ("load", "thread-new", True))
        self.assertEqual(self.app.calls[1][0], "attach")
        item = self.store.read_mailbox("agent-a", "message-1", mark_read=False)
        self.assertEqual(item.state, "attached")
        self.assertEqual(self.store.active_binding("agent-a", "context-1").thread_id, "thread-new")

    def test_sync_inbox_extracts_a2a_text_and_thread_metadata(self):
        self.link.mailbox_items = [
            {
                "messageId": "message-in",
                "contextId": "context-in",
                "sourceAgentId": "agent-b",
                "body": '{"message":{"messageId":"message-in","contextId":"context-in","parts":[{"kind":"text","text":"hello from b"}],"metadata":{"snw-agent-link/threadSync":{"mode":"snapshot"}}}}',
            }
        ]

        self.assertEqual(self.service.sync_inbox("agent-a"), 1)
        item = self.store.read_mailbox("agent-a", "message-in", mark_read=False)
        self.assertEqual(item.body, "hello from b")
        self.assertEqual(item.metadata["snw-agent-link/threadSync"]["mode"], "snapshot")

    def test_two_session_handles_never_share_context_bindings(self):
        self.service.send_message(
            agent_id="agent-a",
            target_agent_id="agent-b",
            message="from one",
            session_handle=self.handle("agent-a", "thread-one"),
            context_id="context-one",
        )
        self.service.send_message(
            agent_id="agent-a",
            target_agent_id="agent-b",
            message="from two",
            session_handle=self.handle("agent-a", "thread-two"),
            context_id="context-two",
        )

        self.assertEqual(self.store.active_binding("agent-a", "context-one").thread_id, "thread-one")
        self.assertEqual(self.store.active_binding("agent-a", "context-two").thread_id, "thread-two")

    def test_attachment_upload_uses_resolved_target_and_context_grant(self):
        self.service.send_message(
            agent_id="agent-a",
            target_agent_id="agent-b",
            message="see attachment",
            session_handle=self.handle("agent-a", "thread-a"),
            attachments=["/tmp/report.txt"],
        )

        send_params = self.link.calls[0][1]
        resolved_context = send_params["contextId"]
        self.assertTrue(resolved_context)
        self.assertEqual(
            self.link.upload_calls,
            [("agent-a", ["/tmp/report.txt"], "agent-b", resolved_context)],
        )
        self.assertEqual(
            send_params["payload"]["message"]["metadata"]["snw-agent-link/attachments"][0]["grant"]["contextId"],
            resolved_context,
        )

    def test_receive_is_idempotent_and_binds_context_to_one_thread(self):
        first = self.service.receive_message(
            agent_id="agent-a",
            remote_agent_id="agent-b",
            context_id="context-in",
            message_id="message-in",
            task_id="task-in",
            body="untrusted inbound",
        )
        second = self.service.receive_message(
            agent_id="agent-a",
            remote_agent_id="agent-b",
            context_id="context-in",
            message_id="message-in",
            task_id="task-in",
            body="untrusted inbound",
        )

        self.assertFalse(first["duplicate"])
        self.assertTrue(second["duplicate"])
        self.assertEqual(first["threadId"], "thread-inbound")
        self.assertEqual(second["threadId"], "thread-inbound")
        self.assertEqual(self.store.active_binding("agent-a", "context-in").thread_id, "thread-inbound")
        self.assertEqual([call[0] for call in self.app.calls].count("start"), 1)
        self.assertEqual([call[0] for call in self.app.calls].count("attach"), 1)
        task = self.service.task_status("agent-a", "task-in")
        self.assertEqual(task["state"], "received")
        self.assertEqual(self.service.cancel_task("agent-a", "task-in")["state"], "cancel_requested")


if __name__ == "__main__":
    unittest.main()
