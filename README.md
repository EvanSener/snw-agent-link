# snw-agent-link

`snw-agent-link` 是完全开源、自托管的 Agent-to-Agent 通信系统：

```text
Headscale 控制面
  + Tailscale OSS 客户端 / WireGuard 数据面
  + 自托管 DERP / STUN
  + snw-agent-linkd
  + A2A Protocol 1.0
  + 可选 Codex Adapter
```

不需要官方 Tailscale 账号，不使用官方登录服务、官方 DERP map、Cloudflare Tunnel、中心消息邮箱或公网裸 A2A。

## 产品原则

- 所有 Agent 完全对等，不区分本地端、远端、客户端或服务端。
- 笔记本、本机多 Agent、服务器之间都通过同一 Tailnet 双向通信。
- Headscale/Tailscale 负责节点入网、可达性、WireGuard 加密和网络策略。
- `snw-agent-linkd` 负责 Agent 身份、双方白名单、A2A 路由、幂等、离线 outbox 和附件。
- 双方分别确认并进入 `active` 后才能投递正式消息。
- 白名单只控制消息准入，不替接收 Agent 决定工具、文件、Shell、联网或审批权限。
- 外部 Agent 内容始终作为不可信用户级输入，不能覆盖本地 system/developer 指令。
- Codex 是首个适配器，核心不依赖 Codex。

## 已实现

- 每 Agent 独立 Ed25519 身份、capability、签名和白名单。
- 双向邀请、接受、二次确认、撤销、封禁和主机迁移校验。
- Tailscale Local API `WhoIs` 与 Stable Node ID fail-closed 准入。
- A2A REST、JSON-RPC、SSE、Task、Message、Agent Card 和标准 Task 状态。
- RFC 9421/9530 请求/响应签名与 SSE cursor/hash 链。
- SQLite AES-256-GCM outbox、幂等、回执、重启恢复和 mailbox。
- Blob grant、Range 下载、SHA-256 校验、分块和跨节点断点续传。
- Codex app-server `thread/read`/`thread/resume`、签名 session handle、独立 Thread、Hook、MCP 和加密 mailbox。
- macOS LaunchAgent、Linux systemd user service、Windows Service 与交叉构建。
- Headscale v0.29.2 + Tailscale v1.98.9 + 三 Codex 节点六方向 Docker E2E。

## 本机三节点一键验收

前置：Docker Desktop、`/dev/net/tun`、`jq`、`curl`，以及 macOS cc-switch
`http://127.0.0.1:15721/v1`。

```bash
cp docker/e2e/.env.example docker/e2e/.env
scripts/deploy-e2e.sh deploy
```

runner 自动完成：

1. 启动自建 Headscale 与私有 DERP。
2. 创建 Headscale 用户和三份一次性节点 key。
3. 启动三个包含 Tailscale OSS、linkd、Codex 和 Adapter 的独立容器。
4. 注册三个独立 Agent 并完成三组双向白名单。
5. 验证六方向 Codex → MCP → A2A → mailbox → Codex Thread。
6. 验证未配对和身份错配请求被拒绝。

不需要填写 Tailscale 账号或外部 auth key。详见 `docker/e2e/README.md`。

## 生产控制面一键部署

跨互联网节点需要一台有公网 IP 的 Linux 主机和一个直接解析到该主机的域名：

```bash
cd deploy/self-hosted-control-plane
cp .env.example .env
$EDITOR .env
./deploy.sh up
./deploy.sh issue-key laptop-a
```

该部署只开放：

- `80/TCP`：ACME HTTP-01。
- `443/TCP`：Headscale 控制面与内置 DERP。
- `3478/UDP`：STUN。

节点加入：

```bash
scripts/join-self-hosted-tailnet.sh \
  --login-server https://headscale.example.com \
  --auth-key-file /secure/path/laptop-a.key \
  --hostname laptop-a
```

控制面部署细节见 `deploy/self-hosted-control-plane/README.md`。域名可以由任意 DNS 服务商解析，但必须直连公网主机；不经过 HTTP Tunnel 或 CDN 代理。

## 安装 Agent 节点

加入自建 Tailnet 后，构建并安装 linkd：

```bash
go build -o bin/snw-agent-link ./cmd/snw-agent-link
go build -o bin/snw-agent-linkd ./cmd/snw-agent-linkd

# macOS
packaging/macos/install.sh

# Linux
packaging/linux/install.sh
```

Windows 使用 `packaging/windows/install.ps1`。Codex Adapter：

```bash
./adapters/snw-agent-link-codex/snw-agent-link-codex install codex
```

完整注册、配对、故障处理和备份流程见 `docs/operations.md`。

## 开发验证

```bash
node scripts/openspec-ci-check.mjs
go test ./...
go test -race ./...
go vet ./...
go build ./cmd/...
PYTHONPATH=adapters/snw-agent-link-codex \
  python3 -m unittest discover -s adapters/snw-agent-link-codex/tests -p 'test_*.py'
```

## 开源基线

- Headscale v0.29.2
- Tailscale OSS 客户端与 DERP v1.98.9
- A2A Protocol 1.0 / `a2a-go/v2`
- OpenAI Codex CLI / app-server
- SQLite

项目使用 Apache-2.0 License。
