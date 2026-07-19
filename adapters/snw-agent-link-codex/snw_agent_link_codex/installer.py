"""Idempotent local installer for the snw-agent-link Codex adapter."""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import tempfile
from pathlib import Path
from typing import Any


def install_codex(
    *,
    source_root: Path | str | None = None,
    codex_home: Path | str | None = None,
    plugin_dir: Path | str | None = None,
    data_dir: Path | str | None = None,
    register_mcp: bool = True,
) -> dict[str, Any]:
    """Install the plugin and register its MCP server without secrets.

    Existing plugin files are replaced from the checked-in source, while the
    runtime data directory and user Codex config are left untouched. Re-running
    this function is safe and converges to the same plugin contents.
    """
    source = Path(source_root).expanduser() if source_root else Path(__file__).resolve().parents[1]
    if not (source / ".codex-plugin" / "plugin.json").is_file():
        raise FileNotFoundError(f"Codex plugin manifest not found: {source}")
    home = Path(codex_home).expanduser() if codex_home else Path(os.environ.get("CODEX_HOME", Path.home() / ".codex")).expanduser()
    destination = Path(plugin_dir).expanduser() if plugin_dir else home / "plugins" / "snw-agent-link-codex"
    runtime_data = Path(data_dir).expanduser() if data_dir else Path.home() / ".snw-agent-link"
    runtime_data.mkdir(mode=0o700, parents=True, exist_ok=True)
    os.chmod(runtime_data, 0o700)
    destination.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    _copy_plugin(source, destination)
    config_path = runtime_data / "codex.env"
    config_created = _write_runtime_config(config_path, runtime_data)
    mcp = {"registered": False, "message": "未执行 Codex MCP 注册"}
    if register_mcp:
        mcp = _register_mcp(destination, home)
    return {
        "ok": bool(mcp.get("ok", True)),
        "pluginDir": str(destination),
        "runtimeDataDir": str(runtime_data),
        "configPath": str(config_path),
        "configCreated": config_created,
        "mcp": mcp,
        "next": [
            "source codex.env (仅包含本地路径，不含 token)",
            "snw-agent-link agent register，然后设置 SNW_AGENT_LINK_AGENT_ID 与 SNW_AGENT_LINK_REGISTRATION_TOKEN",
            "在 Codex 中打开已安装的 snw-agent-link-codex 插件后调用 agent_contacts_list/agent_contact",
        ],
    }


def _copy_plugin(source: Path, destination: Path) -> None:
    staging: Path | None = Path(tempfile.mkdtemp(prefix=f".{destination.name}.staging-", dir=str(destination.parent)))
    try:
        shutil.copytree(
            source,
            staging,
            dirs_exist_ok=True,
            ignore=shutil.ignore_patterns("__pycache__", "*.pyc", ".DS_Store"),
        )
        if destination.exists():
            # Preserve no generated runtime files in the plugin tree. The
            # adapter mailbox is intentionally under runtimeDataDir instead.
            shutil.rmtree(destination)
        staging.rename(destination)
        staging = None
    finally:
        if staging is not None and staging.exists():
            shutil.rmtree(staging, ignore_errors=True)


def _write_runtime_config(path: Path, data_dir: Path) -> bool:
    if path.exists():
        return False
    ipc = data_dir / "snw-agent-link.sock"
    adapter_data = data_dir / "codex"
    path.write_text(
        "# snw-agent-link Codex adapter local paths; do not put credentials here.\n"
        f"export SNW_AGENT_LINK_DATA_DIR={_shell_value(data_dir)}\n"
        f"export SNW_AGENT_LINK_ADAPTER_DATA_DIR={_shell_value(adapter_data)}\n"
        f"export SNW_AGENT_LINK_IPC={_shell_value(ipc)}\n",
        encoding="utf-8",
    )
    os.chmod(path, 0o600)
    return True


def _register_mcp(plugin_dir: Path, codex_home: Path) -> dict[str, Any]:
    codex = shutil.which(os.environ.get("SNW_CODEX_BIN", "codex"))
    if not codex:
        return {"ok": False, "registered": False, "message": "找不到 codex；插件已复制，请安装 Codex 后重跑 install codex"}
    env = dict(os.environ)
    env["CODEX_HOME"] = str(codex_home)
    get = subprocess.run(
        [codex, "mcp", "get", "snw-agent-link"],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        env=env,
        check=False,
    )
    if get.returncode == 0:
        return {"ok": True, "registered": True, "message": "Codex MCP snw-agent-link 已存在，保持原配置"}
    command = [
        codex,
        "mcp",
        "add",
        "snw-agent-link",
        "--",
        "python3",
        str(plugin_dir / "mcp_server.py"),
    ]
    added = subprocess.run(
        command,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        env=env,
        check=False,
    )
    if added.returncode:
        message = (added.stderr.strip() or added.stdout.strip() or "Codex MCP 注册失败")[-2000:]
        return {"ok": False, "registered": False, "message": message}
    return {"ok": True, "registered": True, "message": "Codex MCP snw-agent-link 已注册"}


def _shell_value(path: Path) -> str:
    return "'" + str(path).replace("'", "'\\''") + "'"


def load_plugin_manifest(plugin_dir: Path | str) -> dict[str, Any]:
    path = Path(plugin_dir) / ".codex-plugin" / "plugin.json"
    return json.loads(path.read_text(encoding="utf-8"))
