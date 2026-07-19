## ADDED Requirements

### Requirement: 自托管开源控制面

系统 MUST 使用 Headscale 作为 Tailnet 控制面，并禁止依赖官方 Tailscale SaaS 登录服务。

#### Scenario: 一键部署

- **WHEN** 用户执行三节点部署
- **THEN** runner MUST 先启动 Headscale，再创建用户和节点 preauth keys
- **AND** 节点 MUST 使用自建 `login-server` 注册

### Requirement: 禁止官方中继依赖

系统 MUST 禁用官方 Tailscale DERP map 和 logtail。

#### Scenario: 本地 E2E

- **WHEN** 三个节点运行在同一 Docker 主机
- **THEN** 节点 MUST 优先建立直接 WireGuard 连接
- **AND** 不得向官方 Tailscale 控制面或日志服务发送请求

### Requirement: 生产公网边界

跨主机生产部署 MUST 使用用户自有公网 HTTPS Headscale 地址。

#### Scenario: 一键部署公网控制面

- **WHEN** 用户配置域名与 ACME 邮箱并执行控制面部署
- **THEN** 系统 MUST 启动 Headscale、embedded DERP 和 STUN
- **AND** 只要求公网开放 80/TCP、443/TCP 与 3478/UDP
- **AND** 官方 DERP map、更新检查和 logtail MUST 保持禁用

#### Scenario: 无公网控制面

- **WHEN** 不同互联网网络中的节点无法访问 Headscale
- **THEN** 安装程序 MUST 明确失败
- **AND** 不得回退到官方 Tailscale SaaS、Cloudflare Tunnel 或 Docker bridge
