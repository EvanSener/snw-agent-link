#!/usr/bin/env bash
set -Eeuo pipefail

TS_SOCKET=${TS_SOCKET:-/run/tailscale/tailscaled.sock}
TS_STATE_DIR=${TS_STATE_DIR:-/var/lib/tailscale}
LINK_DATA_DIR=${SNW_AGENT_LINK_DATA_DIR:-/var/lib/snw-agent-link}
CODEX_BASE_URL=${CODEX_BASE_URL:-http://host.docker.internal:15721/v1}
CODEX_MODEL=${CODEX_MODEL:-gpt-5.6-sol}
ADAPTER_PORT=${SNW_AGENT_LINK_ADAPTER_PORT:-7780}

log() {
  printf '[%s] %s\n' "${E2E_NODE_NAME:-unknown}" "$*" >&2
}

require_value() {
  local name=$1
  if [[ -z ${!name:-} ]]; then
    log "缺少必填环境变量：${name}"
    exit 64
  fi
}

wait_for_file() {
  local path=$1
  local timeout=${2:-30}
  local deadline=$((SECONDS + timeout))
  while [[ ! -e $path ]]; do
    if (( SECONDS >= deadline )); then
      log "等待文件超时：${path}"
      return 1
    fi
    sleep 0.25
  done
}

write_codex_config() {
  mkdir -p "${CODEX_HOME}"
  chmod 0700 "${CODEX_HOME}"
  cat >"${CODEX_HOME}/config.toml" <<EOF
model = "${CODEX_MODEL}"
model_provider = "cc-switch"

[model_providers.cc-switch]
name = "macOS cc-switch"
base_url = "${CODEX_BASE_URL}"
env_key = "OPENAI_API_KEY"
wire_api = "responses"
EOF
  chmod 0600 "${CODEX_HOME}/config.toml"
}

tailscale_status() {
  tailscale --socket="${TS_SOCKET}" status --json
}

healthcheck() {
  tailscale_status | jq -e '.BackendState == "Running" and (.Self.TailscaleIPs | length > 0)' >/dev/null
  snw-agent-link --data-dir "${LINK_DATA_DIR}" status | jq -e '.gatewayListening == true' >/dev/null
  curl --fail --silent --show-error --max-time 3 \
    -H "Authorization: Bearer ${OPENAI_API_KEY}" \
    "${CODEX_BASE_URL%/}/models" >/dev/null
}

doctor() {
  printf '%s\n' '--- versions ---'
  tailscale version
  codex --version
  snw-agent-link --data-dir "${LINK_DATA_DIR}" status
  printf '%s\n' '--- tailscale ---'
  tailscale_status | jq '{BackendState, Tailnet: .CurrentTailnet, Self: {ID: .Self.ID, HostName: .Self.HostName, TailscaleIPs: .Self.TailscaleIPs, Online: .Self.Online}}'
  printf '%s\n' '--- cc-switch ---'
  curl --fail --silent --show-error --max-time 3 \
    -H "Authorization: Bearer ${OPENAI_API_KEY}" \
    "${CODEX_BASE_URL%/}/models" | jq '{data: [.data[]?.id]}'
  printf '%s\n' '--- adapter ingress ---'
  if python3 -c 'import snw_agent_link_codex.http_server' 2>/dev/null; then
    printf '%s\n' 'available'
  else
    printf '%s\n' 'missing: snw_agent_link_codex.http_server'
    return 3
  fi
}

cleanup() {
  local status=$?
  trap - EXIT INT TERM
  if [[ -n ${LINK_PID:-} ]]; then kill "${LINK_PID}" 2>/dev/null || true; fi
  if [[ -n ${TAILSCALED_PID:-} ]]; then kill "${TAILSCALED_PID}" 2>/dev/null || true; fi
  wait 2>/dev/null || true
  exit "${status}"
}

run_node() {
  require_value E2E_NODE_NAME
  require_value HEADSCALE_URL
  require_value HEADSCALE_PREAUTH_KEY_FILE

  case ${HEADSCALE_URL} in
    *login.tailscale.com*|*controlplane.tailscale.com*)
      log "拒绝官方 Tailscale SaaS 控制面：${HEADSCALE_URL}"
      exit 64
      ;;
  esac

  if [[ ! -c /dev/net/tun ]]; then
    log '缺少 /dev/net/tun；真实 Tailnet E2E 不允许退化到 Docker bridge 或伪造 100.x 地址'
    exit 69
  fi
  if [[ ! -r ${HEADSCALE_PREAUTH_KEY_FILE} ]]; then
    log "Headscale preauth key secret 不可读：${HEADSCALE_PREAUTH_KEY_FILE}"
    exit 66
  fi

  mkdir -p /run/e2e /run/tailscale "${TS_STATE_DIR}" "${LINK_DATA_DIR}" /var/log/e2e
  chmod 0700 "${TS_STATE_DIR}" "${LINK_DATA_DIR}"
  write_codex_config

  local had_tailscale_state=0
  if [[ -s ${TS_STATE_DIR}/tailscaled.state ]]; then
    had_tailscale_state=1
  fi
  tailscaled \
    --socket="${TS_SOCKET}" \
    --state="${TS_STATE_DIR}/tailscaled.state" \
    --tun=tailscale0 \
    >"/var/log/e2e/tailscaled.log" 2>&1 &
  TAILSCALED_PID=$!
  wait_for_file "${TS_SOCKET}" 30

  if [[ ! -s ${HEADSCALE_PREAUTH_KEY_FILE} ]]; then
    log 'Headscale preauth key secret 为空'
    exit 65
  fi
  local state_reused=0
  if [[ ${had_tailscale_state} == 1 ]]; then
    local state_deadline=$((SECONDS + 30))
    until tailscale_status | jq -e '.BackendState == "Running"' >/dev/null 2>&1; do
      if (( SECONDS >= state_deadline )); then
        break
      fi
      sleep 0.5
    done
    if tailscale_status | jq -e '.BackendState == "Running"' >/dev/null 2>&1; then
      state_reused=1
      log '复用已登录的 Headscale 节点状态'
    fi
  fi
  if [[ ${state_reused} == 0 ]]; then
    tailscale --socket="${TS_SOCKET}" up \
      --login-server="${HEADSCALE_URL}" \
      --auth-key="file:${HEADSCALE_PREAUTH_KEY_FILE}" \
      --hostname="${E2E_NODE_NAME}" \
      --accept-dns=false \
      --accept-routes=false \
      --reset
  fi
  local tailnet_ip
  tailnet_ip=$(tailscale --socket="${TS_SOCKET}" ip -4 | head -n 1)
  if [[ ! ${tailnet_ip} =~ ^100\. ]]; then
    log "未获得真实 Tailscale IPv4：${tailnet_ip:-empty}"
    exit 70
  fi
  printf '%s\n' "${tailnet_ip}" > /run/e2e/tailscale-ip
  tailscale_status > /run/e2e/tailscale-status.json

  snw-agent-linkd \
    --data-dir "${LINK_DATA_DIR}" \
    --tailscale-bind-ip "${tailnet_ip}" \
    --gateway-port 7443 \
    --version e2e \
    >"/var/log/e2e/snw-agent-linkd.log" 2>&1 &
  LINK_PID=$!
  wait_for_file "${LINK_DATA_DIR}/snw-agent-link.sock" 30

  local deadline=$((SECONDS + 30))
  until curl --fail --silent --show-error --max-time 2 "http://${tailnet_ip}:7443/healthz" >/dev/null; do
    if (( SECONDS >= deadline )); then
      log 'linkd Tailnet healthz 未就绪'
      exit 70
    fi
    sleep 0.5
  done

  if python3 -c 'import snw_agent_link_codex.http_server' 2>/dev/null; then
    printf '%s\n' 'available' > /run/e2e/adapter-ingress
  else
    printf '%s\n' 'missing' > /run/e2e/adapter-ingress
  fi

  log "节点就绪：Tailnet IP ${tailnet_ip}；adapter ingress $(cat /run/e2e/adapter-ingress)"
  trap cleanup EXIT INT TERM
  while kill -0 "${TAILSCALED_PID}" 2>/dev/null && kill -0 "${LINK_PID}" 2>/dev/null; do
    sleep 2
  done
  log 'tailscaled 或 linkd 意外退出'
  return 1
}

case ${1:-run} in
  run) run_node ;;
  healthcheck) healthcheck ;;
  doctor) doctor ;;
  *) exec "$@" ;;
esac
