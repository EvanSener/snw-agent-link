## ADDED Requirements

### Requirement: 每个 Agent 拥有独立可验证身份

守护进程承载的每个 Agent 必须使用独立 Ed25519 身份密钥。Agent ID 固定为 `snw-agent:v1:<base32lower-no-pad(SHA-256("snw-agent-id-v1\\0" || raw-public-key))>`；另有独立 capability Ed25519 keypair，Agent SDK 以 capability 私钥完成 challenge，换取短期 session。签名内容必须绑定 Agent、目标、方法、路径、请求体摘要、时间戳和 nonce。

#### Scenario: 同机 Agent 不能冒充
- **WHEN** 同一主机上的 Agent B 使用自己的私钥发送声称来自 Agent A 的消息
- **THEN** 守护进程必须因签名公钥与 Agent A 联系人记录不匹配而拒绝

#### Scenario: 私钥轮换失败封闭
- **WHEN** 已配对 Agent 的公钥发生变化且没有重新配对
- **THEN** 新消息必须被拒绝并要求建立新身份关系

### Requirement: capability 生命周期可恢复

linkd 只保存 capability 公钥、代次、Agent/Endpoint/方法绑定和状态；私钥只在 Agent 的平台密钥库中保存。丢失 capability 必须轮换代次，丢失身份私钥必须生成新 Agent ID 并重新配对，不能静默替换。
