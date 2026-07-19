## ADDED Requirements

### Requirement: 使用官方 A2A Protocol 1.0

网关必须复用官方 A2A 1.0 Task、Message、Artifact 和 Agent Card 模型，并分阶段支持 JSON-RPC、REST 与 SSE，内部不得把传输绑定到单一协议。

#### Scenario: 白名单外请求提前拒绝
- **WHEN** 未知或非 active Agent 请求正式 A2A 端点
- **THEN** 网关必须在向本地 Agent 路由完整消息体前拒绝

#### Scenario: 权限状态原样传递
- **WHEN** 接收 Agent 返回 AUTH_REQUIRED、INPUT_REQUIRED 或 REJECTED
- **THEN** 链路层必须原样传递且不得自行放宽权限

#### Scenario: Tailnet 内真实转发
- **WHEN** active 联系人通过 Tailscale Node context、Agent 签名和 capability 调用目标 Agent
- **THEN** 对端守护进程必须把官方 A2A 请求转发到仅接受 linkd relay 的目标 Endpoint，并原样返回结果或经验证的事件

#### Scenario: 签名绑定语义请求
- **WHEN** 对端守护进程收到 REST 或 JSON-RPC 请求
- **THEN** 必须验证 RFC 9421/9530 签名绑定方法、路径、目标 Agent、请求体摘要、时间窗和 nonce，不得只信任 Agent ID 请求头；响应必须覆盖 HTTP 状态和响应体摘要

#### Scenario: loopback 路由限制
- **WHEN** Agent 注册本机 A2A Endpoint
- **THEN** Endpoint 必须通过 linkd 专属 Unix Socket/Named Pipe，或验证 linkd-issued 短期 ingress token；裸 loopback 请求必须拒绝，且不得跟随重定向
