import tempfile
import unittest
from pathlib import Path

from snw_agent_link_codex.installer import install_codex


class InstallerTest(unittest.TestCase):
    def test_install_copies_plugin_and_generates_non_secret_runtime_config(self):
        root = Path(__file__).resolve().parents[1]
        with tempfile.TemporaryDirectory() as temp:
            home = Path(temp) / "codex-home"
            data = Path(temp) / "data"
            result = install_codex(
                source_root=root,
                codex_home=home,
                data_dir=data,
                register_mcp=False,
            )

            destination = Path(result["pluginDir"])
            config = Path(result["configPath"])
            self.assertTrue(result["ok"])
            self.assertTrue((destination / ".codex-plugin" / "plugin.json").is_file())
            self.assertTrue((destination / "hooks" / "hooks.json").is_file())
            self.assertTrue(config.is_file())
            self.assertIn("SNW_AGENT_LINK_IPC", config.read_text(encoding="utf-8"))
            self.assertNotIn("TOKEN", config.read_text(encoding="utf-8").upper())

            rerun = install_codex(
                source_root=root,
                codex_home=home,
                data_dir=data,
                register_mcp=False,
            )
            self.assertFalse(rerun["configCreated"])
            self.assertTrue(rerun["ok"])


if __name__ == "__main__":
    unittest.main()
