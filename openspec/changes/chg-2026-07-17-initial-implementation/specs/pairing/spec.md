## ADDED Requirements

### Requirement: 正式通信需要双向人工确认

一次性邀请只能启动配对，不能代表双方授权；双方分别确认对端指纹后关系才可进入 `active`。

邀请通过 `.snwpair` 文件、二维码或 URI 传递，包含高熵一次性秘密、inviteId、Agent 公钥摘要、Stable Node ID、路由地址和过期时间；短语只用于人工比对。未 active 的控制端点必须限流、限大小且不得枚举联系人存在性。邀请方离线时 acceptance/confirmation/receipt 进入配对 outbox，重新上线后继续。

#### Scenario: 单边接受不能通信
- **WHEN** 接收方已接受邀请但发起方尚未确认接收方身份
- **THEN** 双方正式消息都必须被拒绝

#### Scenario: 撤销立即生效
- **WHEN** 任意一方本地撤销联系人
- **THEN** 本机必须立即拒绝该联系人的新消息且不依赖远端确认

### Requirement: 撤销必须止损但不伪造远端终止

本机撤销立即拒绝新业务消息，queued outbox 标记 `cancelled` 且不再发送；运行中的远端任务发送 `CancelTask` 并显示 `cancel_requested`，不能承诺远端一定停止；SSE 订阅关闭，未下载 Blob 授权失效，已落盘副本不回收。撤销通知使用独立控制 outbox 有限重试。
