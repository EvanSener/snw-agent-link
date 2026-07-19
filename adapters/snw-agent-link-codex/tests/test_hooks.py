import tempfile
import unittest
from pathlib import Path


from snw_agent_link_codex.hooks import HookRuntime
from snw_agent_link_codex.storage import MailboxStore, SessionHandleSigner


class HookRuntimeTest(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.root = Path(self.temp_dir.name)
        self.store = MailboxStore(self.root)
        self.signer = SessionHandleSigner.from_data_dir(self.root)
        self.runtime = HookRuntime(self.store, self.signer, "agent-a")

    def tearDown(self):
        self.store.close()
        self.temp_dir.cleanup()

    def test_session_start_emits_signed_handle_for_exact_thread(self):
        output = self.runtime.session_start({"session_id": "thread-a", "source": "startup", "cwd": "/repo"})

        context = output["hookSpecificOutput"]["additionalContext"]
        token = context.split("session_handle=", 1)[1].split()[0]
        payload = self.signer.verify(token, expected_agent_id="agent-a")
        self.assertEqual(payload.thread_id, "thread-a")

    def test_user_prompt_submit_reports_count_without_remote_content(self):
        self.store.put_mailbox_item(
            agent_id="agent-a",
            message_id="message-1",
            context_id="context-1",
            remote_agent_id="agent-b",
            summary="do not expose summary",
            body="do not expose body",
        )

        output = self.runtime.user_prompt_submit({"session_id": "thread-a", "turn_id": "turn-a", "prompt": "hello", "cwd": "/repo"})
        serialized = str(output)

        self.assertIn("1 条未读", serialized)
        self.assertNotIn("do not expose summary", serialized)
        self.assertNotIn("do not expose body", serialized)

    def test_stop_records_last_turn_without_forcing_continuation(self):
        output = self.runtime.stop({"session_id": "thread-a", "turn_id": "turn-a", "last_assistant_message": "done"})

        observed = self.store.get_observed_thread("agent-a", "thread-a")
        self.assertEqual(observed.last_turn_id, "turn-a")
        self.assertTrue(output["continue"])


if __name__ == "__main__":
    unittest.main()
