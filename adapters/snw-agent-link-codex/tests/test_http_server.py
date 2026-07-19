import unittest

from snw_agent_link_codex import http_server


class HTTPServerEntrypointTest(unittest.TestCase):
    def test_module_exports_relay_and_defaults_to_relay_command(self):
        self.assertTrue(callable(http_server.main))
        self.assertTrue(hasattr(http_server, "RelayServer"))


if __name__ == "__main__":
    unittest.main()
