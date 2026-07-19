## 1. 核心准入

- [x] 1.1 配置 tailscaled LocalAPI socket 并让生产 daemon 强制注入 WhoIs
- [x] 1.2 对缺少 RemoteNodeID、WhoIs 失败和节点错配 fail closed
- [x] 1.3 增加 agent ensure 的幂等身份/token 恢复语义

## 2. Codex relay

- [x] 2.1 实现 loopback A2A REST/JSON-RPC/SSE relay
- [x] 2.2 实现短期 ingress capability、nonce、防重放和轮换
- [x] 2.3 实现 context/thread 绑定、mailbox、Task 状态和取消
- [x] 2.4 增加 Codex adapter install/doctor 入口

## 3. Docker E2E

- [x] 3.1 固定 Go、Tailscale、Codex、基础镜像和 npm 完整性
- [x] 3.2 实现三节点 TUN、secret、tini、健康检查和清理
- [x] 3.3 自动注册、三组双向配对和 cc-switch route probe
- [x] 3.4 通过真实 Codex thread/session_handle/MCP 执行六方向通信
- [x] 3.5 执行未配对、身份错配和链路准入负测；WhoIs fail-closed 与并发隔离由 Go/adapter 测试覆盖
- [x] 3.6 保存成功/失败脱敏 artifacts，缺证据时 runner 非零
- [x] 3.7 提供持久状态的一键 deploy/status/doctor/down/clean/pair 入口

## 4. 验证

- [x] 4.1 Go、Python、OpenSpec 和静态检查通过
- [x] 4.2 Docker build 通过
- [x] 4.3 自建 Headscale/DERP 三节点 E2E runner 已闭环；不需要官方账号或外部 auth key
