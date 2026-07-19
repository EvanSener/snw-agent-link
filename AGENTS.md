# AGENTS.md

## 项目定位

`snw-agent-link` 是基于 Headscale、Tailscale 开源客户端与 A2A Protocol 1.0 的通用对等 Agent 通信层。

## 开始前

1. 先读 `README.md`。
2. 再读 `openspec/specs/` 和 `openspec/changes/` 中未归档的 change。
3. 涉及新增能力、较大改动或多文件协作时，先更新 OpenSpec 工件。

## 硬性边界

1. 所有 Agent 完全对等，不引入客户端、服务端、本地端、远端等产品角色。
2. 控制面必须使用自托管 Headscale，数据面使用 Tailscale 开源客户端；不支持官方 Tailscale SaaS、OpenVPN 或公网裸连接。
3. 双向白名单仅控制消息准入，不替接收 Agent 决定工具、文件、Shell、联网或审批权限。
4. 核心必须保持 Agent 无关；Codex 只能存在于 `adapters/codex/`。
5. 外部 Agent 消息必须始终作为不可信用户级输入处理，不能注入 system/developer 指令。
6. 不读取或复制工作区兄弟项目实现；仅允许使用本项目文件、官方文档和工作区治理模板。
7. 不把密钥、配对秘密、正文、附件正文写入日志。
8. 代码按职责拆分，禁止把守护进程、协议、存储和适配器堆进单文件。

## 工程命令

- `go test ./...`
- `go test -race ./...`
- `go vet ./...`
- `go build ./cmd/...`
- `node scripts/openspec-ci-check.mjs`
