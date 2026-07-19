#!/usr/bin/env bash
set -Eeuo pipefail

login_server=
auth_key_file=
hostname=

usage() {
  cat <<'EOF'
用法：
  scripts/join-self-hosted-tailnet.sh \
    --login-server https://headscale.example.com \
    --auth-key-file /secure/path/node.key \
    --hostname node-name
EOF
}

while (($#)); do
  case $1 in
    --login-server)
      login_server=${2:-}
      shift 2
      ;;
    --auth-key-file)
      auth_key_file=${2:-}
      shift 2
      ;;
    --hostname)
      hostname=${2:-}
      shift 2
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      printf '未知参数：%s\n' "$1" >&2
      usage >&2
      exit 64
      ;;
  esac
done

command -v tailscale >/dev/null 2>&1 || {
  echo '缺少开源 Tailscale 客户端，请先安装 tailscale/tailscaled' >&2
  exit 69
}
command -v jq >/dev/null 2>&1 || {
  echo '缺少 jq' >&2
  exit 69
}

if [[ ! ${login_server} =~ ^https://[A-Za-z0-9][A-Za-z0-9.-]*(:[0-9]+)?/?$ ]]; then
  echo 'login-server 必须是自建 Headscale 的 HTTPS URL' >&2
  exit 64
fi
normalized_login_server=$(printf '%s' "${login_server}" | tr '[:upper:]' '[:lower:]')
case ${normalized_login_server} in
  *login.tailscale.com*|*controlplane.tailscale.com*|*.trycloudflare.com*)
    echo '拒绝官方 Tailscale SaaS 或 Cloudflare Tunnel 地址' >&2
    exit 64
    ;;
esac
if [[ ! ${hostname} =~ ^[A-Za-z0-9][A-Za-z0-9.-]{0,62}$ ]]; then
  echo 'hostname 必须是 1-63 位字母、数字、点或连字符' >&2
  exit 64
fi
if [[ ! -r ${auth_key_file} || ! -s ${auth_key_file} ]]; then
  echo 'auth-key 文件不可读或为空' >&2
  exit 66
fi

tailscale up \
  --login-server="${login_server%/}" \
  --auth-key="file:${auth_key_file}" \
  --hostname="${hostname}" \
  --accept-dns=false \
  --accept-routes=false \
  --reset

status=$(tailscale status --json)
if ! jq -e '.BackendState == "Running" and .Self.Online == true and (.Self.ID | length > 0)' <<<"${status}" >/dev/null; then
  echo '节点未进入 Running/Online，拒绝继续' >&2
  exit 70
fi
tailnet_ip=$(tailscale ip -4 | head -n 1)
if [[ ! ${tailnet_ip} =~ ^100\. ]]; then
  echo "未获得 Headscale Tailnet IPv4：${tailnet_ip:-empty}" >&2
  exit 70
fi

printf '节点已加入自建 Tailnet：hostname=%s ip=%s login-server=%s\n' \
  "${hostname}" "${tailnet_ip}" "${login_server%/}"
