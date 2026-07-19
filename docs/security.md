# 安全基线

## 分层准入

Headscale Grants 限制“哪些 Tailnet 节点可以访问 `snw-agent-linkd` 端口”；Tailscale Local API `WhoIs` 固定来源节点；Agent 双向白名单限制“哪些 Agent 可以互相投递消息”。三层都通过后，链路才允许进入 A2A 处理器。

白名单不代表执行授权。接收 Agent 仍使用自己的模型、工具、文件、网络、审批和沙箱配置。

## 身份与密钥

- 主机层不自建 mTLS、CA、客户端证书或主机指纹；自托管 Headscale、Tailnet WireGuard、Grants 和 Tailscale `WhoIs` 提供节点层信任。配对数据中的旧 host fingerprint 字段仅为迁移兼容，不是准入前置条件。
- 每个 Agent 使用独立 Ed25519 密钥，不能复用同机其他 Agent 的身份。
- Agent ID 由版本化公钥摘要派生；每 Agent 另有独立 capability keypair，challenge 后换取短期 session capability。
- A2A 请求和最终响应使用 RFC 9421 detached signature 与 RFC 9530 `Content-Digest`；SSE 使用每事件 Ed25519 签名及 cursor/hash 链。旧 SignedEnvelope 仅保留在配对控制面兼容，不作为 A2A 业务准入。
- 为保证无人值守、自托管和跨平台恢复，Agent 身份、capability 与 outbox key 统一存放在本机 data directory，不依赖 Keychain、Credential Manager、Secret Service 或外部 KMS。
- macOS/Linux 的 data directory 与身份目录强制为 `0700`，密钥文件强制为 `0600`；权限不符时 daemon fail closed。
- Windows 安装器关闭 data directory 的 ACL 继承，只允许 LocalSystem 与本机 Administrators 完全控制；管理 Named Pipe 使用同一主体边界。
- daemon 使用 data directory 下的 `outbox.key` 派生 AES-256-GCM，SQLite outbox payload 在落盘时加密；丢失该密钥时必须走备份恢复，不能静默生成新 key 解密旧消息。
- 日志、错误和审计记录不得写入私钥、配对秘密、消息正文或附件正文。

## 输入安全

- 外部 Agent 内容始终按不可信用户输入处理。
- 不得覆盖本地 system/developer 指令，也不得继承发送方权限。
- 限制请求头、JSON、附件、并发任务和单 Agent 速率。
- 对附件执行大小、分块、路径和磁盘配额校验。
- linkd 只向注册时校验为 loopback 的 Endpoint 转发，并注入短期 relay ingress 标记；真实 Agent SDK 需要校验该标记，裸 loopback 调用不能作为对外通信路径。
- A2A `AUTH_REQUIRED`、`INPUT_REQUIRED` 和 `REJECTED` 原样传递，不在链路层自动批准。

## 撤销与恢复

撤销在本机立即生效，不等待对方确认；queued 消息取消、running 任务仅发送 CancelTask、未下载 Blob 授权失效。主机迁移或公钥变化按 Node context/新身份重新确认处理。重连使用 source+target+epoch+message ID、幂等键和任务索引避免重复执行。

## 威胁承诺

Standard profile 防止没有目标 Agent capability 的正常 Agent 通过协议冒充；同一 OS 用户下已完全恶意的代码不在承诺范围。需要抵抗该威胁时，使用 Strong profile 为每 Agent 配置独立 OS 用户、容器和密钥库。
