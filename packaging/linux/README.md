# Linux 安装

运行 `packaging/linux/install.sh` 会把 CLI 和 daemon 安装到 `~/.local/bin`，使用统一的 `~/.snw-agent-link` 数据目录，安装 user systemd service，并从 `tailscale ip -1` 获取绑定地址。服务器场景可将同一 service 复制到 `/etc/systemd/system` 后改为 system service。

升级使用 `packaging/upgrade.sh`，会备份 SQLite 和 identities；新进程无法启动时自动回滚二进制。

桌面节点使用 systemd user service；服务器节点可使用 system service。服务账号只应拥有数据目录、证书和本地 IPC 的必要权限。

```bash
systemctl --user daemon-reload
systemctl --user enable --now snw-agent-linkd.service
systemctl --user status snw-agent-linkd.service
```

Headless 主机可将服务安装到 `/etc/systemd/system`，并通过专用用户运行。密钥文件必须为 `0600`，数据库目录必须限制为服务账号。
