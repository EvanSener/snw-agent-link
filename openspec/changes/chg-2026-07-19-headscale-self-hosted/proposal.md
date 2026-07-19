## 背景

原首版依赖官方 Tailscale SaaS 控制面，无法满足“全部开源、自托管、不注册第三方账号”的硬性要求。

## 目标

- 使用 Headscale v0.29.2 作为自托管 Tailnet 控制面。
- 节点继续使用开源 `tailscale`/`tailscaled` 作为 WireGuard 数据面。
- 三节点 Docker 一键部署不再要求外部 Tailscale auth key。
- 一键脚本自动启动 Headscale、创建用户和一次性 preauth keys，再注册三个节点。
- 禁止回退到官方 Tailscale 控制面或官方 DERP map。
- 保留生产外部 `HEADSCALE_URL` 配置面，明确跨公网部署需要用户自有公网主机、域名和 TLS。

## 非目标

- 不把 Headscale、DERP 或 Agent 数据面部署到 Cloudflare Workers。
- 不使用 Headscale 替代 Agent 级双向白名单。
- 不允许 Docker bridge 承载 Agent A2A 业务流量。

## 验收

- 本地 Compose 由一个 Headscale 控制面和三个独立 Agent 节点组成。
- 三个节点通过 `--login-server` 注册到自建 Headscale。
- 三节点获得真实 `100.64.0.0/10` 地址并通过 `tailscale ping`。
- 六方向 A2A、Codex 路由、准入负测继续通过。
- Headscale 数据、节点数据和 Agent 身份均持久化。
