## ADDED Requirements

### Requirement: Codex 只共享当前会话可见内容

Codex 适配器首版只支持 Codex CLI/app-server，不承诺 IDE 或 Desktop。适配器必须使用短期签名 session_handle 绑定 session_id、turn_id 和 A2A contextId，不能读取其他线程或隐藏推理；必须持久化 context/thread 绑定和加密 mailbox。

#### Scenario: 并发会话不会串线
- **WHEN** 同一主机有两个 Codex 会话同时调用 MCP
- **THEN** 每次调用只能访问其 session_handle 绑定的线程

#### Scenario: 外部消息保持不可信
- **WHEN** 对端 Agent 发送包含 system 或 developer 风格指令的内容
- **THEN** Hook 必须以外部消息上下文注入且不得改变本地指令优先级

### Requirement: 关闭线程后仍可恢复未读消息

适配器必须提供 `agent inbox list/read/attach`。原 Codex thread 关闭、重启或删除后，A2A context/task 索引和未读摘要仍可发现；用户显式 attach 到新 thread 后才能注入完整内容。
