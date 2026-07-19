## ADDED Requirements

### Requirement: app-server 客户端使用稳定 JSONL 生命周期

Codex adapter MUST 通过 stdio JSONL 连接 `codex app-server`，每个连接先发送 `initialize` 请求和 `initialized` 通知，并在读取既有 thread 时显式设置 `includeTurns=true`。

#### Scenario: 读取完整 thread
- **WHEN** adapter 验证已绑定 Codex thread
- **THEN** 客户端必须调用 `thread/read`，参数同时包含目标 `threadId` 与 `includeTurns=true`

#### Scenario: 通知和响应交错
- **WHEN** app-server 在请求响应前发送 thread 或 turn 通知
- **THEN** 客户端必须按请求 ID 匹配响应且不得把通知误认为响应

### Requirement: A2A context 与 Codex thread 绑定可恢复

Adapter MUST 持久保存 Agent、A2A context、Codex thread 和最近 turn 索引；重新 attach 到新 thread 时保留旧绑定历史，原 thread 删除不得删除 context 或 mailbox。

#### Scenario: 原 thread 删除后重新附加
- **WHEN** `thread/read` 表明原绑定 thread 已不存在且用户选择新 thread
- **THEN** adapter 必须保留原绑定记录并把同一 context 的 active binding 切换到新 thread

#### Scenario: 并发 thread 不串线
- **WHEN** 两个 Codex thread 同时调用 MCP
- **THEN** adapter 必须验证各自短期签名 `session_handle` 并只读写对应 thread 的绑定

#### Scenario: 出站同步当前 thread 可见历史
- **WHEN** Agent 从已绑定 Codex thread 发送 A2A 消息
- **THEN** adapter 必须在消息 metadata 中携带首次完整可见历史快照，后续消息携带基于最近 turn 的增量，并排除隐藏推理与 system/developer 内容

### Requirement: mailbox 持久且显式附加

Adapter MUST 将 mailbox 摘要和正文加密持久化，支持 list/read/attach；Hook 只能提示未读数量，不得把外部正文注入 system/developer 上下文。

#### Scenario: Codex 重启后查看未读
- **WHEN** Codex 关闭后重新启动且 mailbox 中存在未读消息
- **THEN** 用户必须仍可通过 MCP list/read 查看摘要和正文

#### Scenario: 用户显式 attach
- **WHEN** 用户用有效 `session_handle` 将 mailbox 消息附加到 thread
- **THEN** adapter 必须先用 `thread/read(includeTurns=true)` 验证 thread，再以不可信 user 输入写入 thread 并标记 attached

### Requirement: 插件自动承载 MCP 与 Hook

Adapter MUST 使用 Codex 插件标准目录声明 `.mcp.json`、`hooks/hooks.json` 与 Skill，安装后不得要求用户手工复制 Hook 定义。

#### Scenario: 插件加载
- **WHEN** Codex 启用该插件
- **THEN** Codex 必须可发现 MCP server、SessionStart、UserPromptSubmit、Stop Hook 与 Skill
