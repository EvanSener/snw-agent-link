# macOS 安装

使用 LaunchAgent 运行用户态 `snw-agent-linkd`。安装脚本同时把 CLI 和 daemon 安装到 `~/.local/bin`，使用 `~/.snw-agent-link` 数据目录和当前 Tailnet IP。

实际安装流程：

```bash
mkdir -p "$HOME/Library/LaunchAgents"
# 将项目提供的 launchd plist 按实际路径生成后放入该目录
launchctl bootstrap "gui/$(id -u)" "$HOME/Library/LaunchAgents/com.snw.agent-linkd.plist"
launchctl kickstart -k "gui/$(id -u)/com.snw.agent-linkd"
```

不要把服务绑定到公网网卡；`--tailscale-bind-ip` 必须是本机 Tailscale 地址。

运行 `packaging/macos/install.sh` 会自动读取 `tailscale ip -1`，生成 plist 并启动服务。升级使用 `packaging/upgrade.sh`，升级前会备份 SQLite 和 identities，启动失败自动恢复旧二进制。
