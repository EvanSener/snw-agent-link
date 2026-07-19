# 威胁模型

## 信任边界

1. 自托管 Headscale + Tailscale OSS：节点注册、WireGuard 可达性、Grants、DERP/STUN。
2. `snw-agent-linkd`：`WhoIs`、Stable Node ID、Agent 签名、capability、双方白名单、幂等和路由。
3. 接收 Agent：自行决定是否执行任务、调用工具、访问文件、联网或请求审批。

同一 Tailnet 中的节点并不自动成为可信 Agent。只有双方分别确认并写入本地白名单后，关系才进入 `active`。

## 主要攻击者

- 获得 Headscale 节点资格但未获 Agent 白名单授权的节点。
- 同一主机上没有目标 capability、试图冒充其他 Agent 的进程。
- 盗用 Agent 私钥、registration token、preauth key 或 capability 的本地恶意进程。
- 重放旧邀请、消息、响应、SSE cursor 或撤销通知的攻击者。
- 通过畸形 JSON、压缩炸弹、超大附件或并发请求耗尽资源的攻击者。
- 试图把外部 Agent 文本提升为 system/developer 指令的提示注入攻击者。
- 试图把节点回退到官方 SaaS、官方 DERP 或公网裸连接的配置攻击者。

## 核心假设

- Headscale、域名、ACME 账户、Docker 主机和备份由部署者控制。
- Tailscale OSS 客户端、Headscale 和操作系统未被完全攻陷。
- 公网仅开放 Headscale/DERP 所需 `80/TCP`、`443/TCP`、`3478/UDP`。
- Agent 身份和 capability 私钥保存在受 OS 权限保护的本机文件中：Unix 使用 `0700/0600`，Windows 使用 NTFS ACL。
- 接收 Agent 始终把外部消息作为不可信用户级输入。

## 非目标

- 不抵抗已完全取得控制面或 Agent 主机 root/管理员权限的攻击者。
- 不替 Agent 实现工具、文件、Shell、联网或沙箱授权。
- 不提供公网匿名接入、中心邮箱、远程桌面或远程 Codex TUI。
- Standard profile 不抵抗同一 OS 用户下的任意恶意代码；该场景使用独立 OS 用户或容器。
- 本地文件密钥不抵抗已获得同一 OS 主体权限或本机管理员权限的攻击者。

## 失效处理

- Stable Node ID、Agent 公钥或主机绑定变化时默认拒绝通信。
- 节点 preauth key 只使用一次；泄露时立即在 Headscale 撤销并重新签发。
- capability 泄露时轮换代次，使旧 session 失效。
- Agent 私钥疑似泄露时生成新身份并重新配对，不能静默换钥。
- 任意一方撤销后，本机立即拒绝新消息，不等待对方确认。
