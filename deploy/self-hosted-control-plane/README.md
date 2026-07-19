# 全开源控制面部署

本目录在一台有公网 IP 的 Linux 主机上部署：

- Headscale v0.29.2：自托管 Tailnet 控制面。
- Headscale Embedded DERP：自托管 TCP 中继。
- STUN：公网 UDP 3478，帮助节点建立直连。
- ACME TLS：Headscale 自行申请并续期证书。

不使用官方 Tailscale 登录服务、官方 DERP map、logtail、Cloudflare Tunnel 或公网裸 A2A。

## 前置条件

1. 域名 A/AAAA 直接解析到该主机公网 IP。
2. 防火墙和云安全组放行 `80/TCP`、`443/TCP`、`3478/UDP`。
3. 安装 Docker Engine、Docker Compose v2 和 `jq`。
4. 如果域名 DNS 托管在 Cloudflare，必须使用 DNS-only，不开启代理。

## 启动

```bash
cp .env.example .env
$EDITOR .env
./deploy.sh up
./deploy.sh issue-key laptop-a
./deploy.sh status
```

`issue-key` 生成一小时有效、不可复用、非临时节点 key，文件权限为 `0600`。把该文件通过安全通道传到目标节点，然后运行：

```bash
scripts/join-self-hosted-tailnet.sh \
  --login-server https://headscale.example.com \
  --auth-key-file /secure/path/laptop-a.key \
  --hostname laptop-a
```

Headscale SQLite、Noise key、DERP key 和 ACME 资料保存在 Docker volume
`snw-agent-link-control_headscale-data`。备份和迁移时必须整体保护该 volume。

## 生命周期

```bash
./deploy.sh status
./deploy.sh logs
./deploy.sh down
./deploy.sh up
```

`down` 保留数据卷。生产恢复前先验证域名仍直接指向当前公网 IP，并确保 443/TCP 与
3478/UDP 都可达；只有 443 而没有 UDP 时仍可中继，但直连成功率会下降。
