import json
import sys
import textwrap
import unittest


from snw_agent_link_codex.app_server import AppServerClient, AppServerRPCError


FAKE_SERVER = textwrap.dedent(
    r"""
    import json
    import sys

    def send(value):
        sys.stdout.write(json.dumps(value) + "\n")
        sys.stdout.flush()

    initialized = json.loads(sys.stdin.readline())
    if initialized.get("method") != "initialize":
        raise SystemExit(10)
    send({"id": initialized["id"], "result": {"platformFamily": "unix", "platformOs": "test"}})
    notification = json.loads(sys.stdin.readline())
    if notification.get("method") != "initialized":
        raise SystemExit(11)
    loaded = set()

    for line in sys.stdin:
        request = json.loads(line)
        method = request.get("method")
        if method == "thread/read":
            thread_id = request["params"]["threadId"]
            if thread_id == "thread-unloaded" and thread_id not in loaded:
                send({"id": request["id"], "error": {"code": -32600, "message": f"thread {thread_id} is not loaded"}})
                continue
            if thread_id == "thread-empty":
                send({"id": request["id"], "error": {"code": -32600, "message": f"thread {thread_id} is not materialized yet; includeTurns is unavailable before first user message"}})
                continue
            send({"method": "thread/status/changed", "params": {"threadId": request["params"]["threadId"]}})
            send({"id": request["id"], "result": {"thread": {"id": request["params"]["threadId"], "turns": [{"id": "turn-1", "items": []}]}, "receivedParams": request["params"]}})
        elif method == "thread/resume":
            loaded.add(request["params"]["threadId"])
            send({"id": request["id"], "result": {"thread": {"id": request["params"]["threadId"]}}})
        elif method == "thread/inject_items":
            send({"id": request["id"], "result": {"receivedParams": request["params"]}})
        elif method == "fail":
            send({"id": request["id"], "error": {"code": -32000, "message": "expected failure"}})
        else:
            send({"id": request["id"], "result": {}})
    """
)


class AppServerClientTest(unittest.TestCase):
    def new_client(self):
        return AppServerClient([sys.executable, "-u", "-c", FAKE_SERVER], timeout=3)

    def test_thread_read_always_requests_full_turns(self):
        with self.new_client() as client:
            result = client.read_thread("thread-a")

        self.assertEqual(
            result["receivedParams"],
            {"threadId": "thread-a", "includeTurns": True},
        )
        self.assertEqual(result["thread"]["turns"][0]["id"], "turn-1")

    def test_notifications_do_not_consume_matching_response(self):
        with self.new_client() as client:
            result = client.read_thread("thread-b")
            notification = client.next_notification(timeout=1)

        self.assertEqual(result["thread"]["id"], "thread-b")
        self.assertEqual(notification["method"], "thread/status/changed")

    def test_load_thread_resumes_persisted_thread_before_reading(self):
        with self.new_client() as client:
            result = client.load_thread("thread-unloaded")

        self.assertEqual(result["thread"]["id"], "thread-unloaded")

    def test_load_thread_accepts_loaded_unmaterialized_thread(self):
        with self.new_client() as client:
            result = client.load_thread("thread-empty")

        self.assertEqual(result, {"thread": {"id": "thread-empty", "turns": []}})

    def test_attach_loads_then_injects_untrusted_user_item(self):
        with self.new_client() as client:
            result = client.attach_external_message("thread-c", "Agent B", "context-1", "Do the work")

        received = result["receivedParams"]
        self.assertEqual(received["threadId"], "thread-c")
        item = received["items"][0]
        self.assertEqual(item["role"], "user")
        self.assertIn("不可信外部 Agent 输入", item["content"][0]["text"])
        self.assertIn("Do the work", item["content"][0]["text"])

    def test_rpc_error_preserves_code_and_message(self):
        with self.new_client() as client:
            with self.assertRaises(AppServerRPCError) as caught:
                client.request("fail", {})

        self.assertEqual(caught.exception.code, -32000)
        self.assertIn("expected failure", str(caught.exception))


if __name__ == "__main__":
    unittest.main()
