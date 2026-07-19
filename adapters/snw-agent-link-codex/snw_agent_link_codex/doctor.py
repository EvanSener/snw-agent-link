"""Actionable Codex adapter diagnostics without fabricating runtime health."""

from __future__ import annotations

import os
import shutil
import subprocess
import urllib.error
import urllib.request
from pathlib import Path
from typing import Any


def run_doctor(
    *,
    data_dir: Path | str,
    link_client: Any | None = None,
    plugin_root: Path | str | None = None,
    relay_url: str | None = None,
    cc_switch_url: str | None = None,
) -> dict[str, Any]:
    root = Path(data_dir).expanduser()
    checks: list[dict[str, Any]] = []
    codex = shutil.which(os.environ.get("SNW_CODEX_BIN", "codex"))
    if codex:
        version = _run([codex, "--version"])
        checks.append({"name": "codex", "ok": version["ok"], "message": version["message"]})
        app_server = _run([codex, "app-server", "--help"])
        checks.append({"name": "codex_app_server", "ok": app_server["ok"], "message": app_server["message"]})
    else:
        checks.append({"name": "codex", "ok": False, "message": "找不到 Codex CLI；运行 snw-agent-link-codex install codex"})
    checks.append(
        {
            "name": "openssl",
            "ok": shutil.which("openssl") is not None,
            "message": "mailbox 需要 OpenSSL AES-CTR/HMAC",
        }
    )
    checks.append(
        {
            "name": "adapter_store",
            "ok": root.is_dir() and (root / "adapter.sqlite3").exists(),
            "message": str(root),
        }
    )
    plugin = Path(plugin_root).expanduser() if plugin_root else Path(__file__).resolve().parents[1]
    plugin_ok = all(
        (plugin / path).exists()
        for path in (".codex-plugin/plugin.json", ".mcp.json", "hooks/hooks.json", "mcp_server.py")
    )
    checks.append(
        {
            "name": "adapter_plugin",
            "ok": plugin_ok,
            "message": str(plugin),
        }
    )
    if link_client is not None:
        try:
            status = link_client.call("status", {})
            checks.append({"name": "linkd_ipc", "ok": True, "message": _safe_message(status)})
        except (OSError, RuntimeError, ValueError) as exc:
            checks.append({"name": "linkd_ipc", "ok": False, "message": _safe_message(exc)})
    else:
        checks.append({"name": "linkd_ipc", "ok": False, "message": "未提供 linkd IPC client"})

    relay_target = relay_url or os.environ.get("SNW_AGENT_LINK_RELAY_URL", "")
    if relay_target:
        checks.append(_http_check("relay", _join_url(relay_target, "/a2a/health")))
    else:
        checks.append({"name": "relay", "ok": True, "status": "skipped", "message": "未配置 SNW_AGENT_LINK_RELAY_URL"})

    cc_target = cc_switch_url or os.environ.get("SNW_AGENT_LINK_CC_SWITCH_URL", "")
    if cc_target:
        checks.append(_http_check("cc_switch", _join_url(cc_target, "/models"), bearer="PROXY_MANAGED"))
    else:
        checks.append(
            {
                "name": "cc_switch",
                "ok": True,
                "status": "skipped",
                "message": "未配置 SNW_AGENT_LINK_CC_SWITCH_URL；Docker 默认使用 host.docker.internal:15721/v1",
            }
        )
    return {"ok": all(bool(check["ok"]) for check in checks), "checks": checks}


def _run(command: list[str]) -> dict[str, Any]:
    try:
        process = subprocess.run(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, check=False)
    except OSError as exc:
        return {"ok": False, "message": str(exc)}
    return {
        "ok": process.returncode == 0,
        "message": (process.stdout.strip() or process.stderr.strip())[-2000:],
    }


def _http_check(name: str, url: str, *, bearer: str = "") -> dict[str, Any]:
    request = urllib.request.Request(url, method="GET")
    if bearer:
        request.add_header("Authorization", f"Bearer {bearer}")
    try:
        with urllib.request.urlopen(request, timeout=3) as response:
            status = int(response.status)
            return {"name": name, "ok": 200 <= status < 500, "message": f"HTTP {status} {url}"}
    except urllib.error.HTTPError as exc:
        # A 401/403 proves the local route is reachable; credentials are
        # intentionally not requested or persisted by doctor.
        return {"name": name, "ok": 200 <= exc.code < 500, "message": f"HTTP {exc.code} {url}"}
    except (urllib.error.URLError, TimeoutError, OSError) as exc:
        return {"name": name, "ok": False, "message": f"{url} 不可达：{exc}"}


def _join_url(base: str, suffix: str) -> str:
    return base.rstrip("/") + "/" + suffix.lstrip("/")


def _safe_message(value: Any) -> str:
    text = str(value)
    for marker in ("token", "secret", "password", "credential"):
        text = text.replace(marker, "[redacted]")
    return text[:2000]
