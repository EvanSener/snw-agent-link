#!/bin/sh
set -eu

DAEMON_BIN=${SNW_AGENT_LINKD_BIN:-"$(pwd)/bin/snw-agent-linkd"}
CLI_BIN=${SNW_AGENT_LINK_BIN:-"$(pwd)/bin/snw-agent-link"}
INSTALL_DIR=${SNW_AGENT_LINK_INSTALL_DIR:-"$HOME/.local/bin"}
DATA_DIR=${SNW_AGENT_LINK_DATA_DIR:-"$HOME/.snw-agent-link"}
TAILSCALE_IP=${TAILSCALE_BIND_IP:-"$(tailscale ip -1 2>/dev/null | head -n 1 || true)"}
if [ -z "$TAILSCALE_IP" ]; then
  echo "未检测到 Tailscale IPv4，请设置 TAILSCALE_BIND_IP" >&2
  exit 1
fi
if [ ! -x "$DAEMON_BIN" ] || [ ! -x "$CLI_BIN" ]; then
  echo "找不到 snw-agent-link/snw-agent-linkd 可执行文件" >&2
  exit 1
fi

mkdir -p "$HOME/Library/LaunchAgents" "$DATA_DIR" "$INSTALL_DIR"
install -m 0755 "$DAEMON_BIN" "$INSTALL_DIR/snw-agent-linkd"
install -m 0755 "$CLI_BIN" "$INSTALL_DIR/snw-agent-link"
PLIST="$HOME/Library/LaunchAgents/com.snw.agent-linkd.plist"
sed -e "s#__SNW_AGENT_LINKD_BIN__#$INSTALL_DIR/snw-agent-linkd#g" -e "s#__SNW_AGENT_LINK_DATA_DIR__#$DATA_DIR#g" -e "s#__TAILSCALE_BIND_IP__#$TAILSCALE_IP#g" \
  "$(dirname "$0")/com.snw.agent-linkd.plist.template" > "$PLIST"
chmod 600 "$PLIST"
launchctl bootout "gui/$(id -u)/com.snw.agent-linkd" 2>/dev/null || true
launchctl bootstrap "gui/$(id -u)" "$PLIST"
launchctl kickstart -k "gui/$(id -u)/com.snw.agent-linkd"
echo "snw-agent-link 与 snw-agent-linkd 已安装到 $INSTALL_DIR；服务已启动: $PLIST"
