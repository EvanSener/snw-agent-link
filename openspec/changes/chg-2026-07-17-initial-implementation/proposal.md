# 为什么

需要一个不依赖中心消息服务、可在任意 Tailscale 节点之间双向通信的通用 A2A 链路，并通过 Agent 级双向白名单阻止同 Tailnet 或同主机上的未授权 Agent 冒充。

# 变更内容

- 新增跨平台守护进程、管理 CLI 和本地 IPC。
- 新增 Agent Ed25519 身份、registration capability、Tailscale `WhoIs` 节点上下文和双向准入。
- 新增邀请、接受、二次确认、撤销、封禁与主机迁移状态机。
- 新增 A2A Protocol 1.0 REST、JSON-RPC、SSE 网关。
- 新增 SQLite outbox、幂等、回执和断线恢复。
- 新增 Codex Plugin、Hook、MCP 和 app-server 适配器。
- 新增 M1 macOS/Linux 安装升级闭环、M4 Windows 服务定义、构建和发布流程。

# 能力范围

## 新增能力

- `agent-identity`
- `pairing`
- `a2a-gateway`
- `reliable-delivery`
- `codex-adapter`

## 修改能力

None

# 影响范围

新建项目全部源代码、协议接口、本地数据模型、服务定义、CI 和安全文档。
