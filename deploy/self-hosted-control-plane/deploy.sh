#!/usr/bin/env bash
set -Eeuo pipefail

SCRIPT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
ENV_FILE=${SNW_CONTROL_ENV_FILE:-${SCRIPT_DIR}/.env}
STATE_DIR=${SCRIPT_DIR}/.state
CONFIG_FILE=${STATE_DIR}/config.yaml
KEY_DIR=${STATE_DIR}/keys
COMPOSE_FILE=${SCRIPT_DIR}/compose.yaml

log() {
  printf '[snw-control] %s\n' "$*" >&2
}

die() {
  log "失败：$*"
  exit 1
}

require_command() {
  command -v "$1" >/dev/null 2>&1 || die "缺少命令：$1"
}

load_config() {
  if [[ ! -f ${ENV_FILE} ]]; then
    die "缺少 ${ENV_FILE}；先复制 .env.example 并配置域名与 ACME 邮箱"
  fi
  set -a
  # shellcheck disable=SC1090
  source "${ENV_FILE}"
  set +a
  : "${HEADSCALE_DOMAIN:?HEADSCALE_DOMAIN 未配置}"
  : "${HEADSCALE_ACME_EMAIL:?HEADSCALE_ACME_EMAIL 未配置}"
  export HEADSCALE_IMAGE=${HEADSCALE_IMAGE:-docker.m.daocloud.io/headscale/headscale:v0.29.2}
  export HEADSCALE_USER=${HEADSCALE_USER:-snw-agents}
  if [[ ! ${HEADSCALE_DOMAIN} =~ ^[A-Za-z0-9][A-Za-z0-9.-]*[A-Za-z0-9]$ ]]; then
    die "HEADSCALE_DOMAIN 不是合法域名"
  fi
  local normalized_domain
  normalized_domain=$(printf '%s' "${HEADSCALE_DOMAIN}" | tr '[:upper:]' '[:lower:]')
  case ${normalized_domain} in
    login.tailscale.com|controlplane.tailscale.com|*.trycloudflare.com)
      die "拒绝官方 Tailscale SaaS 或 Cloudflare Tunnel 域名"
      ;;
  esac
  if [[ ! ${HEADSCALE_ACME_EMAIL} =~ ^[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}$ ]]; then
    die "HEADSCALE_ACME_EMAIL 不是合法邮箱"
  fi
}

compose() {
  docker compose --file "${COMPOSE_FILE}" "$@"
}

render_config() {
  umask 077
  mkdir -p "${STATE_DIR}" "${KEY_DIR}"
  if [[ -d ${CONFIG_FILE} ]]; then
    chmod 0700 "${CONFIG_FILE}"
    rmdir "${CONFIG_FILE}" 2>/dev/null ||
      die "${CONFIG_FILE} 是非空目录，拒绝覆盖"
  fi
  sed \
    -e "s|__HEADSCALE_DOMAIN__|${HEADSCALE_DOMAIN}|g" \
    -e "s|__HEADSCALE_ACME_EMAIL__|${HEADSCALE_ACME_EMAIL}|g" \
    "${SCRIPT_DIR}/config.yaml.template" >"${CONFIG_FILE}.tmp"
  mv -f "${CONFIG_FILE}.tmp" "${CONFIG_FILE}"
  chmod 0600 "${CONFIG_FILE}"
  compose config >/dev/null
}

headscale() {
  compose exec -T headscale headscale "$@"
}

wait_healthy() {
  local deadline=$((SECONDS + ${SNW_CONTROL_TIMEOUT_SECONDS:-180}))
  while :; do
    local container_id
    container_id=$(compose ps -q headscale 2>/dev/null || true)
    if [[ -n ${container_id} ]]; then
      local health
      health=$(docker inspect --format '{{if .State.Health}}{{.State.Health.Status}}{{else}}{{.State.Status}}{{end}}' "${container_id}")
      if [[ ${health} == healthy ]]; then
        headscale health >/dev/null
        return 0
      fi
    fi
    if (( SECONDS >= deadline )); then
      compose logs --no-color headscale >&2 || true
      die "Headscale 未在时限内进入 healthy"
    fi
    sleep 2
  done
}

user_id() {
  headscale users list --output json |
    jq -er --arg user "${HEADSCALE_USER}" '.[] | select(.name == $user) | .id'
}

ensure_user() {
  local id
  id=$(user_id 2>/dev/null || true)
  if [[ -z ${id} ]]; then
    headscale users create "${HEADSCALE_USER}" --output json >/dev/null
    id=$(user_id)
  fi
  printf '%s\n' "${id}"
}

up() {
  render_config
  compose up --detach
  wait_healthy
  ensure_user >/dev/null
  log "控制面已就绪：https://${HEADSCALE_DOMAIN}；DERP/STUN 使用同一主机的 443/TCP 与 3478/UDP"
}

issue_key() {
  local node_name=${1:-}
  if [[ ! ${node_name} =~ ^[A-Za-z0-9][A-Za-z0-9.-]{0,62}$ ]]; then
    die "节点名必须是 1-63 位字母、数字、点或连字符"
  fi
  wait_healthy
  local id
  id=$(ensure_user)
  local destination=${KEY_DIR}/${node_name}.key
  if [[ -s ${destination} ]]; then
    die "密钥文件已存在：${destination}；不要复用，删除旧文件后重新签发"
  fi
  local response
  response=$(headscale preauthkeys create --user "${id}" --expiration 1h --output json)
  local key
  key=$(jq -er '.key | select(startswith("hskey-auth-"))' <<<"${response}")
  umask 077
  printf '%s\n' "${key}" >"${destination}"
  chmod 0600 "${destination}"
  log "已生成一小时有效、单次使用的节点密钥：${destination}"
  printf '%s\n' "${destination}"
}

status() {
  compose ps
  if [[ -n $(compose ps -q headscale 2>/dev/null || true) ]]; then
    headscale health --output json
    headscale users list --output json |
      jq '[.[] | {id,name,created_at}]'
    headscale nodes list --output json
  fi
}

usage() {
  cat <<'EOF'
用法：
  ./deploy.sh up
  ./deploy.sh issue-key <node-name>
  ./deploy.sh status
  ./deploy.sh logs
  ./deploy.sh down

前置：
  1. 把域名 A/AAAA 直接解析到本机公网 IP，不经过 HTTP Tunnel。
  2. 公网放行 80/TCP、443/TCP、3478/UDP。
  3. 复制 .env.example 为 .env 并填写域名与 ACME 邮箱。
EOF
}

require_command docker
require_command jq
load_config

case ${1:-up} in
  up)
    up
    ;;
  issue-key)
    issue_key "${2:-}"
    ;;
  status)
    render_config
    status
    ;;
  logs)
    render_config
    compose logs --follow --tail=200 headscale
    ;;
  down)
    render_config
    compose down
    ;;
  -h|--help|help)
    usage
    ;;
  *)
    usage >&2
    exit 64
    ;;
esac
