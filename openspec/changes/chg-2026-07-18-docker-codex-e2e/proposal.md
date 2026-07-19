# 为什么

现有单元测试已经覆盖核心协议，但还没有可重复运行的真实三节点验证。需要在三台独立 Docker 节点中安装 Codex CLI、运行独立 tailscaled 与 linkd，通过 macOS 上的 cc-switch 路由完成 Codex 请求，并验证所有 Agent 对之间的双向 A2A。

# 变更内容

- 增加三节点 Docker Compose 与单镜像多进程启动脚本。
- 每个节点使用独立 Tailscale 状态、LocalAPI socket、Agent 身份和 adapter 数据；A2A 只走真实 Tailnet 地址。
- 增加 Codex adapter 的本地 A2A relay、context/thread 绑定和入站 mailbox 接入。
- 增加 Codex adapter 安装入口、cc-switch 配置模板和 doctor 诊断。
- 增加自动注册、三组双向配对、六方向 Codex→MCP→A2A 验收和负向安全测试。
- 成功与失败均输出脱敏的版本、Tailnet、WhoIs、消息、任务、回执和 mailbox 证据。

# 能力范围

## 新增能力

- `docker-codex-e2e`
- `codex-a2a-relay`
- `codex-adapter-install`

## 修改能力

- `tailscale-admission`
- `codex-thread-bridge`

# 明确边界

- 生产只支持自托管 Headscale + Tailscale OSS，不引入官方 Tailscale SaaS、OpenVPN、Cloudflare Tunnel 或 Docker bridge A2A 旁路。
- Docker E2E 的 bootstrap 注册和 Hook trust bypass 只在显式测试 profile 中启用，生产默认保持管理员确认。
- Headscale preauth key 由 runner 自动签发，只作为运行时 Docker secret 注入，不写入镜像、Compose 环境变量、日志或 artifacts。
