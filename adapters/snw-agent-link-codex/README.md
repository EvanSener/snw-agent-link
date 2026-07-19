# snw-agent-link Codex CLI Adapter

这个适配器只面向 Codex CLI/app-server，不修改 Codex TUI，也不提供远程控制隧道。

## 一键安装

适配器目录内提供可执行入口，不需要手工复制 MCP 或 Hook：

```bash
./adapters/snw-agent-link-codex/snw-agent-link-codex install codex
# 或：PYTHONPATH=adapters/snw-agent-link-codex python3 -m snw_agent_link_codex install codex
```

命令会把官方插件目录复制到 `CODEX_HOME/plugins/snw-agent-link-codex`、生成不含密钥的
`~/.snw-agent-link/codex.env`，并幂等注册 `snw-agent-link` MCP。若 Codex 尚未安装，命令会
保留插件和配置并输出可修复的安装提示。

```bash
source ~/.snw-agent-link/codex.env
snw-agent-link agent register
export SNW_AGENT_LINK_AGENT_ID="<当前 Codex Agent ID>"
export SNW_AGENT_LINK_REGISTRATION_TOKEN="<agent.register 返回的 token>"
./adapters/snw-agent-link-codex/snw-agent-link-codex chat-smoke --without-app-server
```

`chat-smoke` 会启动并健康探测 loopback relay 后输出聊天用法，不伪造任何模型响应；需要
持续监听时运行 `snw-agent-link-codex relay`，接入真实 `codex app-server` 时去掉
`--without-app-server`。

## 手工运行

设置以下环境变量后，把 `mcp_server.py` 作为 MCP stdio server 注册：

```bash
export SNW_AGENT_LINK_DATA_DIR="$HOME/.snw-agent-link"
export SNW_AGENT_LINK_AGENT_ID="<当前 Codex Agent ID>"
export SNW_AGENT_LINK_REGISTRATION_TOKEN="<agent.register 返回的 token>"
python3 adapters/snw-agent-link-codex/mcp_server.py
```

`SNW_AGENT_LINK_IPC` 可直接指定 Unix Socket；未设置时由 `DATA_DIR` 推导。Windows 使用 CLI fallback，Named Pipe 路径通过 `SNW_AGENT_LINK_IPC` 指定。

## Loopback relay

`snw-agent-link-codex relay` 监听 `127.0.0.1`（默认端口 `15722`），支持：

- `POST /a2a/inbound`：Bearer 短期 ingress capability + nonce，入站消息持久化到加密 mailbox，并绑定 context/thread。
- linkd 回环转发使用 `X-SNW-Linkd-Ingress`（registration token hash 兼容值）和 `X-SNW-Agent-ID`；relay 只接受 loopback 请求。
- `POST /a2a/rpc` 或 `/a2a/jsonrpc`：`message.receive`、`tasks/get`、`tasks/cancel`、`relay.health`。
- `GET /a2a/events`：SSE 事件流；`GET /a2a/tasks/{taskId}` 与 `POST /a2a/tasks/{taskId}/cancel`。
- `GET /a2a/health`：仅报告本地 relay 存活，不代表 LLM 已完成。

重复 `messageId + nonce` 是幂等的；同一 nonce 携带不同消息会被拒绝。capability 只写入
`0600` 的本地 token 文件，不进入日志或 mailbox。

## MCP 工具

- `agent_contacts_list`：列出当前 Agent 的联系人和准入状态。
- `agent_contact`：把当前 Codex 会话的一条消息写入 outbox。
- `agent_inbox_list/read/attach`：列出、读取并由用户显式注入独立 Codex thread 的入站消息。
- `agent_binding_status`：查看 context 与 Codex thread 的当前及历史绑定。
- `agent_task_status`：读取 outbox 投递状态。
- `agent_task_wait`：轮询投递状态，适合在 Codex 中等待离线重试。
- `agent_task_cancel`：取消 queued 消息，已投递任务记录 `cancel_requested`。
- `agent_adapter_doctor`：检查 Codex CLI、app-server、OpenSSL、linkd IPC 和加密 mailbox。

适配器不读取其他 Codex thread，也不把远端内容提升为 system/developer 指令。附件参数只接受显式的路径列表；linkd 创建 target/context 绑定的 Blob grant，接收方通过 RFC 签名 Range 请求续传并校验 SHA-256。

## Hook

`hooks/session-start.py` 和 `hooks/user-prompt-submit.py` 使用官方 stdin JSON，生成绑定当前 thread/turn 的短期签名 `session_handle` 并只注入未读数量。Hook 只注入用户可见的外部消息，不注入隐藏推理。
