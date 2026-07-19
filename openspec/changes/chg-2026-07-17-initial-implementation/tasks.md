## 1. 项目与协议基线

- [x] 1.1 初始化独立 Git、OpenSpec 和治理 CI
- [x] 1.2 锁定 Go、A2A、Tailscale 与 SQLite 依赖

## 2. 身份与配对

- [x] 2.1 以测试驱动实现 Agent Ed25519 身份与签名
- [x] 2.2 实现双向配对、撤销、封禁状态机
- [x] 2.3 实现多 Agent 注册和独立联系人
- [x] 2.4 实现 Stable Node ID、RFC 9421/9530 Agent 准入、capability challenge 和持久 nonce 防重放

## 3. 持久化与可靠性

- [x] 3.1 实现 SQLite schema、迁移和加密字段接口
- [x] 3.2 接入 AES-GCM outbox、source+target+epoch 幂等、任务恢复和重试调度

## 4. 守护进程与协议

- [x] 4.1 实现本地 IPC 和管理 CLI
- [x] 4.2 实现 Tailscale Local API 与 WhoIs 校验
- [x] 4.3 M0 冻结 RFC 9421/9530、A2A binding、TaskState 和签名测试向量
- [x] 4.4 实现 Agent capability challenge、Node context 和双向 Contact admission
- [x] 4.5 实现 linkd 专属 Unix Socket/Named Pipe 或 ingress token 本地 relay
- [x] 4.6 实现入站请求到本地 Agent Endpoint 的真实转发
- [x] 4.7 实现出站签名 A2A 客户端和双方对等调用
- [x] 4.8 实现 response/error 签名与 SSE 事件签名、cursor/hash 恢复

## 5. Codex 适配器

- [x] 5.1 冻结 Codex CLI/app-server 支持版本并由 doctor 检测
- [x] 5.2 实现签名 session_handle、CodexThreadBinding 和加密 mailbox
- [x] 5.3 实现 MCP 工具、inbox list/read/attach 与 app-server 客户端
- [x] 5.4 实现 Hook 脚本和官方 Plugin/Skill 安装入口

## 6. 可靠消息与附件

- [x] 6.1 将正式 SendMessage 接入 SQLite outbox 和后台重试
- [x] 6.2 实现 messageId 幂等回执与官方 TaskState 索引恢复
- [x] 6.3 实现 `send --file`/MCP 附件选择、进度、Blob 分块、校验和与断点续传
- [x] 6.4 实现附件 status/cancel、保留期、GC、配额和受限保存路径

## 7. 交付与验证

- [x] 7.1 M1-User 增加 macOS 签名包/LaunchAgent 和 Linux 签名包/systemd、自启动、升级备份与回滚
- [x] 7.2 M4 增加 Windows 服务定义和交叉构建 CI
- [x] 7.2 完成安全、运维、威胁模型和 Grants 文档
- [x] 7.3 完成 M1-User 安装、配对、离线、重启、撤销、附件和 Codex 端到端验收矩阵
- [x] 7.4 运行 `go test -race ./...`、`go vet ./...`、`go build ./cmd/...`
