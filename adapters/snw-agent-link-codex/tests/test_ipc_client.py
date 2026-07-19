import tempfile
import unittest
from pathlib import Path


from snw_agent_link_codex.ipc_client import LinkIPCClient


class RecordingLinkIPCClient(LinkIPCClient):
    def __init__(self):
        super().__init__("unused")
        self.calls = []

    def call(self, method, params):
        self.calls.append((method, params))
        if method == "attachment.init":
            return {"attachment": {"blobId": "blob-1"}}
        if method == "attachment.complete":
            return {"attachment": {"blobId": "blob-1", "sha256": "digest"}}
        if method == "attachment.grant":
            return {"grant": {"grantId": "grant-1", "targetAgentId": params["targetAgentId"], "contextId": params["contextId"]}}
        return {"attachment": {"blobId": "blob-1"}}


class LinkIPCClientTest(unittest.TestCase):
    def test_upload_scopes_init_complete_and_grant_to_target_context(self):
        client = RecordingLinkIPCClient()
        with tempfile.TemporaryDirectory() as data_dir:
            attachment = Path(data_dir) / "report.txt"
            attachment.write_text("content", encoding="utf-8")

            uploaded = client.upload_attachments(
                "agent-a",
                [str(attachment)],
                target_agent_id="agent-b",
                context_id="context-1",
            )

        calls = {method: params for method, params in client.calls if method != "attachment.chunk"}
        self.assertEqual(calls["attachment.init"]["agentId"], "agent-a")
        self.assertEqual(calls["attachment.init"]["targetAgentId"], "agent-b")
        self.assertEqual(calls["attachment.init"]["contextId"], "context-1")
        self.assertEqual(calls["attachment.complete"]["agentId"], "agent-a")
        self.assertEqual(calls["attachment.complete"]["targetAgentId"], "agent-b")
        self.assertEqual(calls["attachment.complete"]["contextId"], "context-1")
        self.assertEqual(calls["attachment.grant"]["agentId"], "agent-a")
        self.assertEqual(uploaded[0]["grant"]["grantId"], "grant-1")

    def test_upload_rejects_unscoped_attachment(self):
        client = RecordingLinkIPCClient()

        with self.assertRaises(ValueError):
            client.upload_attachments("agent-a", ["unused"], target_agent_id="", context_id="")


if __name__ == "__main__":
    unittest.main()
