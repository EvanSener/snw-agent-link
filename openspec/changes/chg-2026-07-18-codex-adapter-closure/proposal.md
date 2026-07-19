# 为什么

Codex 适配器需要从一次性 MCP 脚本收敛为可恢复的 Codex CLI/app-server 集成，使 A2A context、Codex thread 与未读 mailbox 在 thread 关闭、删除或 Codex 重启后仍可追踪，并且由用户显式决定把外部消息附加到哪个 thread。

# 变更内容

- 新增 Codex app-server JSONL 客户端，完成初始化握手和 `thread/read(includeTurns=true)` 校验。
- 新增持久 A2A context ↔ Codex thread 绑定、加密 mailbox 和显式 attach 流程。
- 新增并发安全的短期签名 `session_handle`，避免多个 Codex thread 串线。
- 新增 MCP inbox/binding 工具、Codex 官方 Hook 配置和插件清单。
- 新增 adapter 单元测试和安装、恢复、并发使用说明。

# 能力范围

## 新增能力

- `codex-thread-bridge`: Codex app-server、thread 绑定、mailbox、MCP 与 Hook 的完整适配行为。

## 修改能力

None

# 影响范围

主要影响 `adapters/snw-agent-link-codex/`；不修改 Agent 无关的 Go 核心协议和守护进程职责。
