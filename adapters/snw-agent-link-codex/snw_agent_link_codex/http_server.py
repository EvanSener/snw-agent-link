"""Compatibility entry point for the loopback Codex A2A HTTP relay."""

from __future__ import annotations

import os
import sys

from .relay import IngressCapability, RelayError, RelayServer, registration_ingress_token

__all__ = ["IngressCapability", "RelayError", "RelayServer", "main", "serve"]


def main(argv: list[str] | None = None) -> int:
    """Run the loopback relay while preserving module command-line flags."""
    from .cli import main as cli_main

    registration_token = os.environ.get("SNW_AGENT_LINK_REGISTRATION_TOKEN", "")
    if registration_token:
        os.environ["SNW_AGENT_LINK_RELAY_LEGACY_TOKEN"] = registration_ingress_token(registration_token)
    arguments = list(sys.argv[1:] if argv is None else argv)
    if not arguments or arguments[0] != "relay":
        arguments.insert(0, "relay")
    return cli_main(arguments)


serve = main


if __name__ == "__main__":
    raise SystemExit(main())
