import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


class PluginEntrypointTest(unittest.TestCase):
    def test_official_plugin_manifest_points_to_mcp_hooks_and_skills(self):
        manifest = json.loads((ROOT / ".codex-plugin" / "plugin.json").read_text(encoding="utf-8"))

        self.assertEqual(manifest["mcpServers"], "./.mcp.json")
        self.assertEqual(manifest["hooks"], "./hooks/hooks.json")
        self.assertEqual(manifest["skills"], "./skills/")

        mcp = json.loads((ROOT / ".mcp.json").read_text(encoding="utf-8"))
        self.assertEqual(mcp["snw-agent-link"]["command"], "python3")
        self.assertEqual(mcp["snw-agent-link"]["args"], ["${PLUGIN_ROOT}/mcp_server.py"])

        hook_config = json.loads((ROOT / "hooks" / "hooks.json").read_text(encoding="utf-8"))["hooks"]
        for event_name, script_name in {
            "SessionStart": "session-start.py",
            "UserPromptSubmit": "user-prompt-submit.py",
            "Stop": "stop.py",
        }.items():
            command = hook_config[event_name][0]["hooks"][0]
            self.assertEqual(command["type"], "command")
            self.assertEqual(command["command"], f"python3 ${{PLUGIN_ROOT}}/hooks/{script_name}")

        self.assertTrue((ROOT / "skills" / "snw-agent-link-codex" / "SKILL.md").is_file())

    def test_mcp_server_executable_handles_initialize_and_tools_list(self):
        with tempfile.TemporaryDirectory() as data_dir:
            env = dict(os.environ)
            env.update({"SNW_AGENT_LINK_AGENT_ID": "agent-a", "SNW_AGENT_LINK_ADAPTER_DATA_DIR": data_dir})
            requests = "\n".join(
                [
                    json.dumps({"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {}}),
                    json.dumps({"jsonrpc": "2.0", "method": "notifications/initialized", "params": {}}),
                    json.dumps({"jsonrpc": "2.0", "id": 2, "method": "tools/list", "params": {}}),
                ]
            ) + "\n"
            process = subprocess.run(
                [sys.executable, str(ROOT / "mcp_server.py")],
                input=requests,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                env=env,
                check=False,
            )

        self.assertEqual(process.returncode, 0, process.stderr)
        responses = [json.loads(line) for line in process.stdout.splitlines()]
        self.assertEqual([response["id"] for response in responses], [1, 2])
        self.assertIn("agent_inbox_attach", {tool["name"] for tool in responses[1]["result"]["tools"]})

    def test_session_start_hook_reads_official_stdin_shape(self):
        with tempfile.TemporaryDirectory() as data_dir:
            env = dict(os.environ)
            env.update({"SNW_AGENT_LINK_AGENT_ID": "agent-a", "SNW_AGENT_LINK_ADAPTER_DATA_DIR": data_dir})
            process = subprocess.run(
                [sys.executable, str(ROOT / "hooks" / "session-start.py")],
                input=json.dumps({"session_id": "thread-a", "source": "startup", "cwd": "/repo"}),
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                env=env,
                check=False,
            )

        self.assertEqual(process.returncode, 0, process.stderr)
        output = json.loads(process.stdout)
        self.assertIn("session_handle=", output["hookSpecificOutput"]["additionalContext"])


if __name__ == "__main__":
    unittest.main()
