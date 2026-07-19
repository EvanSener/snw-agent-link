## 1. 规范

- [x] 1.1 将产品控制面基线改为 Headscale 自托管
- [x] 1.2 定义本地 E2E 与生产公网部署边界

## 2. 控制面

- [x] 2.1 增加 Headscale v0.29.2 Compose 服务
- [x] 2.2 增加 SQLite、policy、DNS 和禁用官方 DERP 配置
- [x] 2.3 自动创建用户和三份单次 preauth key
- [x] 2.4 增加公网 HTTPS Headscale embedded DERP 一键部署

## 3. 节点

- [x] 3.1 节点强制使用自建 `HEADSCALE_URL`
- [x] 3.2 删除外部 Tailscale SaaS auth key 配置
- [x] 3.3 保持 Tailnet IP、WhoIs 和 A2A fail-closed
- [x] 3.4 增加单次 key 节点加入脚本

## 4. 验证

- [x] 4.1 Compose 和 Headscale 配置校验通过
- [x] 4.2 Docker 镜像构建与 Headscale 健康检查通过
- [x] 4.3 三节点注册、ping、六方向 A2A 和负测通过
