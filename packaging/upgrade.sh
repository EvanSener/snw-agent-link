#!/bin/sh
set -eu

# Upgrade is deliberately local: it never uploads the SQLite database or keys.
BIN=${SNW_AGENT_LINKD_BIN:?请设置 SNW_AGENT_LINKD_BIN}
DATA_DIR=${SNW_AGENT_LINK_DATA_DIR:-"$HOME/.snw-agent-link"}
INSTALL_BIN=${SNW_AGENT_LINKD_INSTALL_BIN:-"$HOME/.local/bin/snw-agent-linkd"}
BACKUP_DIR="$DATA_DIR/backups/$(date -u +%Y%m%dT%H%M%SZ)"
mkdir -p "$BACKUP_DIR"
if [ -f "$DATA_DIR/agent-link.sqlite3" ]; then cp -p "$DATA_DIR/agent-link.sqlite3" "$BACKUP_DIR/agent-link.sqlite3"; fi
if [ -d "$DATA_DIR/identities" ]; then cp -Rp "$DATA_DIR/identities" "$BACKUP_DIR/identities"; fi

tmp="$INSTALL_BIN.new.$$"
install -m 0755 "$BIN" "$tmp"
old="$INSTALL_BIN.old.$$"
if [ -f "$INSTALL_BIN" ]; then mv "$INSTALL_BIN" "$old"; fi
mv "$tmp" "$INSTALL_BIN"

rollback() {
  if [ -f "$old" ]; then mv "$INSTALL_BIN" "$INSTALL_BIN.failed.$$"; mv "$old" "$INSTALL_BIN"; fi
  echo "升级失败，已恢复旧二进制；数据库备份: $BACKUP_DIR" >&2
  exit 1
}
trap rollback INT TERM

if command -v systemctl >/dev/null 2>&1 && systemctl --user is-enabled snw-agent-linkd.service >/dev/null 2>&1; then
  systemctl --user restart snw-agent-linkd.service || rollback
elif command -v launchctl >/dev/null 2>&1; then
  launchctl kickstart -k "gui/$(id -u)/com.snw.agent-linkd" || rollback
fi
rm -f "$old"
trap - INT TERM
echo "升级完成，备份位于: $BACKUP_DIR"
