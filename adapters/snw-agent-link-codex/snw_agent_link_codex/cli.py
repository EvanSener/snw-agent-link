"""Human-facing install, doctor, relay, and chat smoke commands."""

from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path
from typing import Any

from .app_server import AppServerClient
from .doctor import run_doctor
from .hooks import adapter_data_dir
from .installer import install_codex
from .ipc_client import LinkIPCClient
from .relay import IngressCapability, RelayServer, registration_ingress_token
from .service import AdapterService
from .storage import MailboxStore, SessionHandleSigner


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="snw-agent-link-codex", description="snw-agent-link Codex adapter")
    subparsers = parser.add_subparsers(dest="command", required=True)
    install = subparsers.add_parser("install", help="install the Codex plugin and MCP server")
    install.add_argument("target", choices=["codex"])
    install.add_argument("--codex-home")
    install.add_argument("--plugin-dir")
    install.add_argument("--data-dir")
    install.add_argument("--no-mcp", action="store_true")
    subparsers.add_parser("doctor", help="check Codex, linkd, relay, and cc-switch")
    relay = subparsers.add_parser("relay", help="start the loopback A2A relay")
    relay.add_argument("--host", default="127.0.0.1")
    relay.add_argument("--port", type=int, default=int(os.environ.get("SNW_AGENT_LINK_RELAY_PORT", "15722")))
    relay.add_argument("--without-app-server", action="store_true", help="start mailbox relay without Codex app-server")
    relay.add_argument("--ingress-token-file")
    smoke = subparsers.add_parser("chat-smoke", help="install, start a local relay, and print agent_contact usage")
    smoke.add_argument("--no-mcp", action="store_true")
    smoke.add_argument("--without-app-server", action="store_true")
    args = parser.parse_args(argv)

    try:
        if args.command == "install":
            result = install_codex(
                codex_home=args.codex_home,
                plugin_dir=args.plugin_dir,
                data_dir=args.data_dir,
                register_mcp=not args.no_mcp,
            )
            _print_json(result)
            return 0 if result["ok"] else 1
        if args.command == "doctor":
            data_dir = adapter_data_dir()
            store = MailboxStore(data_dir)
            try:
                result = run_doctor(data_dir=data_dir, link_client=LinkIPCClient.from_env())
            finally:
                store.close()
            _print_json(result)
            return 0 if result["ok"] else 1
        if args.command == "relay":
            return _run_relay(args)
        if args.command == "chat-smoke":
            return _run_smoke(args)
    except (OSError, RuntimeError, ValueError) as exc:
        print(f"snw-agent-link-codex: {exc}", file=sys.stderr)
        return 1
    return 1


def _run_relay(args: argparse.Namespace) -> int:
    data_dir = adapter_data_dir()
    agent_id = os.environ.get("SNW_AGENT_LINK_AGENT_ID", "")
    if not agent_id:
        raise ValueError("SNW_AGENT_LINK_AGENT_ID is required; register an Agent first")
    store = MailboxStore(data_dir)
    app: Any = None
    if not args.without_app_server:
        app = AppServerClient()
        app.start()
    service = AdapterService(store, SessionHandleSigner.from_data_dir(data_dir), LinkIPCClient.from_env(), app)
    capability = IngressCapability()
    token = capability.issue(agent_id=agent_id)
    legacy_token = os.environ.get("SNW_AGENT_LINK_RELAY_LEGACY_TOKEN", "")
    if not legacy_token:
        registration_token = os.environ.get("SNW_AGENT_LINK_REGISTRATION_TOKEN", "")
        if registration_token:
            legacy_token = registration_ingress_token(registration_token)
    if legacy_token:
        capability.register(legacy_token, agent_id=agent_id)
    token_path = Path(args.ingress_token_file or os.environ.get("SNW_AGENT_LINK_RELAY_TOKEN_FILE", data_dir / "relay.ingress.token"))
    token_path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    token_path.write_text(token + "\n", encoding="utf-8")
    os.chmod(token_path, 0o600)
    relay = RelayServer(
        service,
        agent_id=agent_id,
        capability=capability,
        host=args.host,
        port=args.port,
        linkd_ingress_token=legacy_token,
    )
    relay.start()
    print(_usage(relay, token_path), flush=True)
    try:
        relay.serve_forever()
    except KeyboardInterrupt:
        return 0
    finally:
        relay.shutdown()
        if app is not None:
            app.close()
        store.close()
    return 0


def _run_smoke(args: argparse.Namespace) -> int:
    install_result = install_codex(register_mcp=not args.no_mcp)
    if not install_result["ok"]:
        _print_json(install_result)
        return 1
    agent_id = os.environ.get("SNW_AGENT_LINK_AGENT_ID", "")
    if not agent_id:
        print(json.dumps({"install": install_result, "relay": {"ok": False, "message": "设置 SNW_AGENT_LINK_AGENT_ID 后重跑 chat-smoke"}}, ensure_ascii=False, indent=2))
        return 1
    data_dir = adapter_data_dir()
    store = MailboxStore(data_dir)
    app = None
    if not args.without_app_server:
        app = AppServerClient()
        app.start()
    relay = RelayServer(
        AdapterService(store, SessionHandleSigner.from_data_dir(data_dir), LinkIPCClient.from_env(), app),
        agent_id=agent_id,
        capability=IngressCapability(),
    )
    relay.start()
    print(json.dumps({"install": install_result, "relay": relay.health(), "relayUrl": relay.base_url, "usage": _usage(relay, None)}, ensure_ascii=False, indent=2))
    relay.shutdown()
    if app is not None:
        app.close()
    store.close()
    return 0


def _usage(relay: RelayServer, token_path: Path | None) -> str:
    token_hint = f"ingress capability file: {token_path}" if token_path else "ingress capability is held by linkd"
    return (
        f"Codex A2A relay ready at {relay.base_url} (loopback-only); {token_hint}\n"
        "在 Codex thread 中使用 agent_contact：target_agent=<paired Agent ID>，"
        "message=<消息>，session_handle=<当前 Hook 注入的句柄>，context_id=<可选上下文>。\n"
        "外部消息仅写入加密 mailbox；使用 agent_inbox_list/read，再由用户显式 agent_inbox_attach。"
    )


def _print_json(value: Any) -> None:
    print(json.dumps(value, ensure_ascii=False, indent=2, sort_keys=True))


if __name__ == "__main__":
    raise SystemExit(main())
