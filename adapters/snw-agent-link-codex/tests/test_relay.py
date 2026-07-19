import json
import tempfile
import threading
import time
import unittest
from http.client import HTTPConnection
from pathlib import Path

from snw_agent_link_codex.relay import IngressCapability, RelayServer, registration_ingress_token
from snw_agent_link_codex.service import AdapterService
from snw_agent_link_codex.storage import MailboxStore, SessionHandleSigner


class FakeApp:
    def __init__(self):
        self.started = []
        self.attached = []

    def start_thread(self, *, cwd=""):
        thread_id = f"thread-{len(self.started) + 1}"
        self.started.append((thread_id, cwd))
        return {"thread": {"id": thread_id}}

    def attach_external_message(self, thread_id, remote_agent_id, context_id, body):
        self.attached.append((thread_id, remote_agent_id, context_id, body))
        return {"ok": True}


class RelayTest(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.store = MailboxStore(Path(self.temp.name))
        self.app = FakeApp()
        self.service = AdapterService(
            self.store,
            SessionHandleSigner.from_data_dir(Path(self.temp.name)),
            object(),
            self.app,
        )
        self.capability = IngressCapability()
        self.token = self.capability.issue(agent_id="agent-a", ttl_seconds=60)
        self.relay = RelayServer(
            self.service,
            agent_id="agent-a",
            capability=self.capability,
        )
        self.relay.start()

    def tearDown(self):
        self.relay.shutdown()
        self.store.close()
        self.temp.cleanup()

    def request(self, method, path, payload=None, token=None):
        host, port = self.relay.address
        connection = HTTPConnection(host, port, timeout=3)
        body = json.dumps(payload).encode() if payload is not None else None
        headers = {
            "Authorization": f"Bearer {token or self.token}",
            "X-SNW-Agent-ID": "agent-b",
        }
        if body is not None:
            headers["Content-Type"] = "application/json"
        connection.request(method, path, body=body, headers=headers)
        response = connection.getresponse()
        raw = response.read()
        connection.close()
        return response.status, json.loads(raw or b"{}")

    def inbound(self, message_id="m-1", context_id="ctx-1", nonce="n-1", body="hello"):
        return self.request(
            "POST",
            "/a2a/inbound",
            {
                "sourceAgentId": "agent-b",
                "targetAgentId": "agent-a",
                "contextId": context_id,
                "messageId": message_id,
                "taskId": f"task-{message_id}",
                "nonce": nonce,
                "body": body,
            },
        )

    def test_inbound_creates_thread_mailbox_and_context_binding(self):
        status, result = self.inbound()
        self.assertEqual(status, 200)
        self.assertEqual(result["threadId"], "thread-1")
        self.assertEqual(self.store.active_binding("agent-a", "ctx-1").thread_id, "thread-1")
        item = self.store.read_mailbox("agent-a", "m-1", mark_read=False)
        self.assertEqual(item.body, "hello")
        self.assertEqual(item.task_state, "received")
        self.assertEqual(self.app.attached[0][-1], "hello")

    def test_duplicate_message_and_nonce_are_idempotent(self):
        first_status, first = self.inbound()
        second_status, second = self.inbound()
        self.assertEqual((first_status, second_status), (200, 200))
        self.assertEqual(first["threadId"], second["threadId"])
        self.assertTrue(second["duplicate"])
        self.assertEqual(len(self.app.started), 1)
        self.assertEqual(len(self.app.attached), 1)

    def test_replay_nonce_with_different_body_is_rejected(self):
        self.inbound()
        status, result = self.inbound(body="tampered")
        self.assertEqual(status, 400)
        self.assertIn("replay", result["error"])

    def test_task_status_and_cancel_are_durable(self):
        self.inbound()
        status, result = self.request("GET", "/a2a/tasks/task-m-1")
        self.assertEqual(status, 200)
        self.assertEqual(result["state"], "received")
        status, result = self.request("POST", "/a2a/tasks/task-m-1/cancel", {})
        self.assertEqual(status, 200)
        self.assertEqual(result["state"], "cancel_requested")
        status, result = self.request("GET", "/a2a/tasks/task-m-1")
        self.assertEqual(result["state"], "cancel_requested")

    def test_wrong_target_and_missing_capability_fail_closed(self):
        payload = {
            "sourceAgentId": "agent-b",
            "targetAgentId": "agent-c",
            "contextId": "ctx-1",
            "messageId": "m-1",
            "nonce": "n-1",
            "body": "hello",
        }
        status, _ = self.request("POST", "/a2a/inbound", payload, token="bad")
        self.assertEqual(status, 401)
        status, result = self.request("POST", "/a2a/inbound", payload)
        self.assertEqual(status, 400)
        self.assertIn("targetAgentId", result["error"])

    def test_authenticated_source_header_cannot_be_overridden_by_body(self):
        status, result = self.request(
            "POST",
            "/a2a/inbound",
            {
                "sourceAgentId": "agent-forged",
                "targetAgentId": "agent-a",
                "contextId": "ctx-forged",
                "messageId": "m-forged",
                "nonce": "n-forged",
                "body": "forged source",
            },
        )
        self.assertEqual(status, 400)
        self.assertIn("sourceAgentId", result["error"])

    def test_json_rpc_and_health(self):
        status, result = self.request("GET", "/a2a/health", token="bad")
        self.assertEqual(status, 200)
        self.assertTrue(result["loopbackOnly"])
        status, result = self.request(
            "POST",
            "/a2a/rpc",
            {
                "jsonrpc": "2.0",
                "id": "rpc-1",
                "method": "message.receive",
                "params": {
                    "sourceAgentId": "agent-b",
                    "targetAgentId": "agent-a",
                    "contextId": "ctx-rpc",
                    "messageId": "m-rpc",
                    "nonce": "n-rpc",
                    "body": "rpc hello",
                },
            },
        )
        self.assertEqual(status, 200)
        self.assertEqual(result["id"], "rpc-1")
        self.assertEqual(result["result"]["task"]["contextId"], "ctx-rpc")

    def test_standard_a2a_rest_returns_task_shape_without_custom_nonce(self):
        status, result = self.request(
            "POST",
            "/a2a/rest",
            {
                "message": {
                    "messageId": "m-rest",
                    "contextId": "ctx-rest",
                    "role": "user",
                    "parts": [{"kind": "text", "text": "rest hello"}],
                }
            },
        )
        self.assertEqual(status, 200)
        self.assertEqual(result["task"]["id"], "m-rest")
        self.assertEqual(result["task"]["contextId"], "ctx-rest")
        self.assertEqual(result["task"]["status"]["state"], "TASK_STATE_WORKING")
        self.assertNotIn("messageId", result["task"])

    def test_sse_receives_inbound_event(self):
        host, port = self.relay.address
        connection = HTTPConnection(host, port, timeout=5)
        connection.request("GET", "/a2a/events", headers={"Authorization": f"Bearer {self.token}"})
        response = connection.getresponse()
        self.assertEqual(response.status, 200)
        ready = response.readline()
        self.assertIn(b"event: ready", ready)
        response.readline()
        response.readline()
        threading.Thread(target=self.inbound, daemon=True).start()
        lines = []
        deadline = time.time() + 3
        while time.time() < deadline and not any(b"message.received" in line for line in lines):
            line = response.readline()
            if line:
                lines.append(line)
        connection.close()
        self.assertTrue(any(b"message.received" in line for line in lines))

    def test_linkd_registration_hash_is_accepted_without_custom_nonce(self):
        registration_token = "registration-secret"
        ingress = registration_ingress_token(registration_token)
        capability = IngressCapability()
        capability.register(ingress, agent_id="agent-a")
        relay = RelayServer(self.service, agent_id="agent-a", capability=capability, linkd_ingress_token=ingress)
        result = relay.handle_inbound(
            {
                "sourceAgentId": "agent-b",
                "targetAgentId": "agent-a",
                "contextId": "ctx-linkd",
                "messageId": "m-linkd",
                "message": {"parts": [{"kind": "text", "text": "from linkd"}]},
            },
            ingress,
            allow_missing_nonce=True,
        )
        self.assertEqual(result["contextId"], "ctx-linkd")


if __name__ == "__main__":
    unittest.main()
