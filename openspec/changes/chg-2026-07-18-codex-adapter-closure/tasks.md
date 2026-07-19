## 1. 协议与持久化

- [x] 1.1 先写 app-server JSONL 握手、通知交错和 `thread/read(includeTurns=true)` 失败测试
- [x] 1.2 实现 app-server 客户端和 thread attach 边界
- [x] 1.3 先写绑定历史、并发隔离、加密 mailbox 与重启恢复失败测试
- [x] 1.4 实现 binding、session handle 与 mailbox 存储
- [x] 1.5 使用 `thread/read(includeTurns=true)` 发送可见历史快照和后续增量

## 2. MCP 与 Hook

- [x] 2.1 先写 contact、inbox list/read/attach 和并发 thread 失败测试
- [x] 2.2 实现 MCP service 与 stdio server
- [x] 2.3 先写 SessionStart、UserPromptSubmit、Stop Hook 失败测试
- [x] 2.4 实现官方 Hook stdin/stdout 契约和插件清单
- [x] 2.5 接入 linkd 加密入站 mailbox 与 capability 保护的 list/read IPC

## 3. 文档与验证

- [x] 3.1 更新安装、恢复、删除 thread、并发和故障排查说明
- [x] 3.2 运行 adapter 单测、Python 编译和 OpenSpec 检查
