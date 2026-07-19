# 运维手册

## 安装清单

### 公网控制面主机

- Linux、Docker Engine、Docker Compose v2、`jq`。
- 一个直接解析到主机公网 IP 的域名。
- 放行 `80/TCP`、`443/TCP`、`3478/UDP`。
- 部署 `deploy/self-hosted-control-plane/`。

### 每个 Agent 节点

- Tailscale 开源客户端与 `tailscaled`。
- `snw-agent-link`、`snw-agent-linkd`。
- 目标 Agent 自身；Codex 节点额外安装 Codex CLI 与 Codex Adapter。
- 不需要官方 Tailscale 账号、主机证书、客户端 CA 或公网 A2A 端口。

## 控制面

```bash
cd deploy/self-hosted-control-plane
cp .env.example .env
$EDITOR .env
./deploy.sh up
./deploy.sh issue-key laptop-a
./deploy.sh status
```

Headscale 数据、Noise key、DERP key 和 ACME 资料保存在
`snw-agent-link-control_headscale-data`。备份时保护整个 volume；不得只复制 SQLite 而丢失控制面私钥。

## 节点入网

```bash
scripts/join-self-hosted-tailnet.sh \
  --login-server https://headscale.example.com \
  --auth-key-file /secure/path/laptop-a.key \
  --hostname laptop-a
```

每个节点使用独立、单次、短时 preauth key。脚本拒绝官方 Tailscale 登录地址、Cloudflare Tunnel、HTTP 控制面、空 key 和非 `100.x` 入网结果。

## linkd 安装

```bash
go build -o bin/snw-agent-link ./cmd/snw-agent-link
go build -o bin/snw-agent-linkd ./cmd/snw-agent-linkd
```

- macOS：`packaging/macos/install.sh`。
- Linux：`packaging/linux/install.sh`。
- Windows：管理员 PowerShell 执行 `packaging/windows/install.ps1`。

守护进程只绑定 `tailscale ip -4` 返回的地址和 TCP 7443；管理面只使用 Unix Socket 或 Windows Named Pipe。

## Agent 注册

原生 A2A 或 Adapter Endpoint 必须只监听 loopback。Codex 示例：

```bash
cat >agent-registration.json <<'JSON'
{
  "displayName": "My Codex Agent",
  "localEndpoint": "http://127.0.0.1:15722/a2a/rest",
  "agentCard": {
    "name": "My Codex Agent",
    "version": "1.0.0"
  }
}
JSON

snw-agent-link agent ensure --params agent-registration.json
./adapters/snw-agent-link-codex/snw-agent-link-codex install codex
```

保存返回的 `agentId` 和 `registrationToken` 到本机 `0600` 凭据文件，供 Adapter 启动。不得写入 Git、日志或聊天。

## 配对与通信

双方必须完成：

```text
pair invite → pair accept → pair approve → pair confirm → pair activate
```

任何一方未完成时都不能发送正式消息。撤销在本机立即生效；`block` 额外拒绝后续配对。

CLI 使用完整 IPC 方法名，参数通过 `--params file.json` 或标准输入传入：

```bash
snw-agent-link status
snw-agent-link agent list
snw-agent-link contact list --params contact-list.json
snw-agent-link doctor
```

## 故障排查

- 控制面无法连接：检查域名是否直连公网 IP、443/TCP 与证书，禁止回退 SaaS。
- 节点只能中继：检查 3478/UDP 和 NAT；DERP 负责转发加密包，不保存消息。
- `TAILSCALE_OFFLINE`：检查 `tailscaled`、自建 login-server 和 Local API。
- `agent pairing is required`：双方联系人未同时进入 `active`。
- `contact identity fingerprint conflict`：撤销旧身份并重新配对，不能静默替换公钥。
- 消息 pending：检查发送方 SQLite outbox、对方在线状态、Tailnet 地址和接收 Endpoint。
- Codex `thread not loaded`：Adapter 会执行 `thread/read → thread/resume → thread/read`；无 rollout 或已删除 Thread 必须重新创建会话。
- 附件 uploading：按 `received/size` 从确认 offset 继续分块，完成后校验 SHA-256。

## 备份

节点备份包含：

- `agent-link.sqlite3` 及 WAL。
- `outbox.key`。
- `identities/`。
- Codex Adapter SQLite 与 mailbox key。
- 系统密钥库中的相关材料。

恢复必须保持数据库与密钥同一版本。日志、审计和 artifacts 不得包含正文、附件、私钥、配对秘密或 preauth key。
