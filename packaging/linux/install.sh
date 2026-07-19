#!/bin/sh
set -eu

DAEMON_BIN=${SNW_AGENT_LINKD_BIN:-"$(pwd)/bin/snw-agent-linkd"}
CLI_BIN=${SNW_AGENT_LINK_BIN:-"$(pwd)/bin/snw-agent-link"}
if [ ! -x "$DAEMON_BIN" ] || [ ! -x "$CLI_BIN" ]; then
  echo "找不到 snw-agent-link/snw-agent-linkd 可执行文件" >&2
  exit 1
fi
mkdir -p "$HOME/.local/bin" "$HOME/.snw-agent-link" "$HOME/.config/systemd/user"
chmod 0700 "$HOME/.snw-agent-link"
install -m 0755 "$DAEMON_BIN" "$HOME/.local/bin/snw-agent-linkd"
install -m 0755 "$CLI_BIN" "$HOME/.local/bin/snw-agent-link"
install -m 0755 "$(dirname "$0")/snw-agent-linkd-wrapper" "$HOME/.local/bin/snw-agent-linkd-wrapper"
install -m 0644 "$(dirname "$0")/snw-agent-linkd.service" "$HOME/.config/systemd/user/snw-agent-linkd.service"
systemctl --user daemon-reload
systemctl --user enable --now snw-agent-linkd.service
echo "snw-agent-link 与 snw-agent-linkd 已安装；服务已启动: systemctl --user status snw-agent-linkd"
