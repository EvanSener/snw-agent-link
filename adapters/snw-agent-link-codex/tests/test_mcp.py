import unittest


from snw_agent_link_codex.mcp import MCPProtocol


class FakeRuntime:
    def __init__(self):
        self.calls = []

    def call_tool(self, name, arguments):
        self.calls.append((name, arguments))
        if name == "explode":
            raise ValueError("expected tool failure")
        return {"ok": True, "name": name}


class MCPProtocolTest(unittest.TestCase):
    def setUp(self):
        self.runtime = FakeRuntime()
        self.protocol = MCPProtocol(self.runtime)

    def test_tools_list_exposes_persistent_inbox_workflow(self):
        response = self.protocol.handle({"jsonrpc": "2.0", "id": 1, "method": "tools/list", "params": {}})
        names = {tool["name"] for tool in response["result"]["tools"]}

        self.assertTrue({"agent_contact", "agent_inbox_list", "agent_inbox_read", "agent_inbox_attach"}.issubset(names))

    def test_tool_call_returns_structured_content(self):
        response = self.protocol.handle(
            {
                "jsonrpc": "2.0",
                "id": 2,
                "method": "tools/call",
                "params": {"name": "agent_inbox_list", "arguments": {"unread_only": True}},
            }
        )

        self.assertFalse(response["result"]["isError"])
        self.assertEqual(response["result"]["structuredContent"]["name"], "agent_inbox_list")

    def test_tool_failure_stays_inside_mcp_tool_result(self):
        response = self.protocol.handle(
            {
                "jsonrpc": "2.0",
                "id": 3,
                "method": "tools/call",
                "params": {"name": "explode", "arguments": {}},
            }
        )

        self.assertTrue(response["result"]["isError"])
        self.assertIn("expected tool failure", response["result"]["content"][0]["text"])

    def test_initialized_notification_has_no_response(self):
        self.assertIsNone(self.protocol.handle({"jsonrpc": "2.0", "method": "notifications/initialized", "params": {}}))


if __name__ == "__main__":
    unittest.main()
