# 三节点 Codex E2E

这套 E2E 在同一 Docker 主机上启动：

- 一个 Headscale v0.29.2 控制面。
- 一个从 Tailscale v1.98.9 源码构建的私有 `derper`。
- 三个独立节点；每个节点包含 `tailscaled`、`snw-agent-linkd`、Codex CLI 和 Codex Adapter。

不需要官方 Tailscale 账号或外部 auth key。runner 自动创建 Headscale 用户和三份一小时有效、不可复用的节点 preauth key。

## 前置条件

- macOS 已启动 Docker Desktop，并允许容器使用 `/dev/net/tun` 与 `NET_ADMIN`。
- cc-switch 监听 `127.0.0.1:15721` 并提供 `gpt-5.6-sol`。
- 已安装 `docker`、Docker Compose v2、`curl`、`jq` 和 `openssl`。

## 部署

```bash
cd /Users/sen/Downloads/code/snw-agent-link
cp docker/e2e/.env.example docker/e2e/.env
$EDITOR docker/e2e/.env
scripts/deploy-e2e.sh deploy
```

`.env` 只包含可选节点名、cc-switch 地址和模型：

```dotenv
E2E_NODE_A_NAME=snw-e2e-a
E2E_NODE_B_NAME=snw-e2e-b
E2E_NODE_C_NAME=snw-e2e-c
CC_SWITCH_BASE_URL=http://127.0.0.1:15721/v1
CODEX_MODEL=gpt-5.6-sol
```

`deploy` 会构建镜像、启动 Headscale/DERP、采集 Tailnet/WhoIs 证据、幂等注册 Agent、完成三组双向配对，并执行 Codex 路由、六方向消息和准入负测。成功后容器保持运行。

## 日常命令

```bash
scripts/deploy-e2e.sh status
scripts/deploy-e2e.sh doctor
scripts/deploy-e2e.sh pair
scripts/deploy-e2e.sh down
scripts/deploy-e2e.sh clean
```

`deploy`、`pair`、`status` 和 `doctor` 会复用已有 Headscale、节点、Agent 身份和联系人状态。`clean` 只删除本项目 E2E 容器、卷、`.state` 和 artifacts，下一次 `deploy` 会从零注册。

## 安全边界

- A2A 业务请求必须命中 `100.64.0.0/10` Tailnet 地址，不能走 Docker bridge。
- Headscale 禁用更新检查、logtail 和官方 DERP map。
- DERP 使用 runner 生成并 pin 的私有 TLS 证书，不连接官方中继。
- 节点必须显式使用 `--login-server=http://headscale:8080`。
- preauth key、Agent token、DERP 私钥和正文不会进入镜像、Compose 环境变量或 artifacts。
- cc-switch 仅承载 LLM API 流量，不参与 Agent 网络、身份或消息转发。

每次运行的脱敏证据位于 `docker/e2e/artifacts/<UTC-run-id>/`。任一真实组件缺失时 runner 必须非零退出，不允许使用 mock、伪造 `100.x` 地址或 Docker bridge 冒充成功。
