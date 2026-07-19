## ADDED Requirements

### Requirement: 发送方持久化未确认消息

正式发送前必须生成稳定 messageId 和 `sourceAgentId+targetAgentId+agentKeyEpoch+messageId` 幂等键并写入本地加密 SQLite outbox，重启后继续投递。语义为 at-least-once。

#### Scenario: 重复投递只创建一次任务
- **WHEN** 同一 messageId 因超时被重复发送
- **THEN** 接收方必须返回既有 Message/Task 结果且不得重复创建 Task；本地 Endpoint 也必须持久化同一幂等键。

#### Scenario: 对方离线后恢复
- **WHEN** 对方离线期间消息进入 outbox 且随后重新上线
- **THEN** 发送方必须按退避策略继续投递直至确认或人工取消

### Requirement: 链路状态不冒充任务状态

必须分别记录 `queued`、`delivered`、`accepted`、`task-created`、`running`、`completed`、`rejected`，并映射官方 `submitted`、`working`、`input-required`、`auth-required`、`completed`、`failed`、`canceled`、`rejected`。
