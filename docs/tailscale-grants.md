# Headscale Grants

Tailnet 控制面由自托管 Headscale 提供。节点使用 Tailscale 开源客户端建立 WireGuard 数据面；无法直连时使用同一 Headscale 的内置 DERP。DERP 不解密、不保存 A2A 业务消息。

生产模板 `deploy/self-hosted-control-plane/policy.hujson` 只允许 Tailnet 节点访问 TCP 7443：

```json
{
  "grants": [
    {
      "src": ["*"],
      "dst": ["*"],
      "ip": ["tcp:7443"]
    }
  ]
}
```

网络层允许访问 7443 不代表 Agent 获得通信权限。`snw-agent-linkd` 仍依次验证：

1. Tailscale Local API `WhoIs` 与 Stable Node ID。
2. Agent Ed25519 请求签名与防重放 nonce。
3. 目标 Agent 本机联系人状态必须为 `active`。

## 配置原则

- Headscale 用户、tag 或组只做节点范围划分。
- 只开放 `snw-agent-linkd` 的 TCP 7443，不开放管理 IPC。
- 不配置官方 DERP map、官方登录服务或 logtail。
- 不用 Cloudflare Tunnel、反向代理或公网端口暴露 Agent A2A。
- Headscale 公网 443 是控制面和 DERP，不是 Agent 业务 HTTP 入口。
