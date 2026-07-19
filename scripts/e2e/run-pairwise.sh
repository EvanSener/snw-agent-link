#!/usr/bin/env bash
set -Eeuo pipefail

SCRIPT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
REPO_ROOT=$(cd "${SCRIPT_DIR}/../.." && pwd)
COMPOSE_FILE=${E2E_COMPOSE_FILE:-${REPO_ROOT}/docker/e2e/compose.e2e.yaml}
PROJECT_NAME=${E2E_PROJECT_NAME:-snw-agent-link-e2e}
RUN_ID=${E2E_RUN_ID:-$(date -u +%Y%m%dT%H%M%SZ)}
ARTIFACT_DIR=${E2E_ARTIFACT_DIR:-${REPO_ROOT}/docker/e2e/artifacts/${RUN_ID}}
PRIVATE_DIR=$(mktemp -d "${TMPDIR:-/tmp}/snw-agent-link-e2e.XXXXXX")
RUNTIME_DIR=${REPO_ROOT}/docker/e2e/.state
CC_SWITCH_HOST_URL=${CC_SWITCH_HOST_URL:-http://127.0.0.1:15721/v1}
CC_SWITCH_HOST_URL=${CC_SWITCH_BASE_URL:-${CC_SWITCH_HOST_URL}}
container_cc_switch_url() {
  case $1 in
    http://127.0.0.1/*|http://127.0.0.1:*) printf 'http://host.docker.internal%s\n' "${1#http://127.0.0.1}" ;;
    http://localhost/*|http://localhost:*) printf 'http://host.docker.internal%s\n' "${1#http://localhost}" ;;
    https://127.0.0.1/*|https://127.0.0.1:*) printf 'https://host.docker.internal%s\n' "${1#https://127.0.0.1}" ;;
    https://localhost/*|https://localhost:*) printf 'https://host.docker.internal%s\n' "${1#https://localhost}" ;;
    *) printf '%s\n' "$1" ;;
  esac
}
CODEX_BASE_URL=${CODEX_BASE_URL:-$(container_cc_switch_url "${CC_SWITCH_HOST_URL}")}
CODEX_MODEL=${CODEX_MODEL:-gpt-5.6-sol}
KEEP_ON_FAILURE=${E2E_KEEP_ON_FAILURE:-0}
KEEP_VOLUMES=${E2E_KEEP_VOLUMES:-1}
E2E_NODE_A_NAME=${E2E_NODE_A_NAME:-snw-e2e-a}
E2E_NODE_B_NAME=${E2E_NODE_B_NAME:-snw-e2e-b}
E2E_NODE_C_NAME=${E2E_NODE_C_NAME:-snw-e2e-c}
E2E_AUTO_DOWN=${E2E_AUTO_DOWN:-0}
COLLECT_LOGS_ON_EXIT=${E2E_COLLECT_LOGS_ON_EXIT:-1}
HEADSCALE_USER=${E2E_HEADSCALE_USER:-snw-agents}
CURRENT_PHASE=initializing

export CC_SWITCH_HOST_URL CODEX_BASE_URL CODEX_MODEL E2E_NODE_A_NAME E2E_NODE_B_NAME E2E_NODE_C_NAME

mkdir -p "${ARTIFACT_DIR}"

compose() {
  docker compose --project-name "${PROJECT_NAME}" --file "${COMPOSE_FILE}" "$@"
}

log() {
  printf '[e2e:%s] %s\n' "${CURRENT_PHASE}" "$*" >&2
}

die() {
  log "失败：$*"
  printf '{"ok":false,"phase":%s,"message":%s}\n' \
    "$(jq -Rn --arg value "${CURRENT_PHASE}" '$value')" \
    "$(jq -Rn --arg value "$*" '$value')" \
    >"${ARTIFACT_DIR}/failure.json"
  return 1
}

require_command() {
  command -v "$1" >/dev/null 2>&1 || die "缺少命令：$1"
}

node_name() {
  case $1 in
    node-a) printf '%s\n' "${E2E_NODE_A_NAME}" ;;
    node-b) printf '%s\n' "${E2E_NODE_B_NAME}" ;;
    node-c) printf '%s\n' "${E2E_NODE_C_NAME}" ;;
    *) die "未知节点：$1" ;;
  esac
}

node_host_fingerprint() {
  printf 'docker-%s\n' "$(node_name "$1")"
}

registration_state_dir() {
  printf '%s\n' /var/lib/snw-agent-link/e2e
}

node_token() {
  compose exec -T "$1" sh -c 'cat /var/lib/snw-agent-link/e2e/registration-token'
}

node_agent() {
  compose exec -T "$1" sh -c 'cat /var/lib/snw-agent-link/e2e/agent-id'
}

node_state_ready() {
  compose exec -T "$1" sh -c 'test -s /var/lib/snw-agent-link/e2e/agent-id && test -s /var/lib/snw-agent-link/e2e/registration-token'
}

ipc_call() {
  local node=$1
  local method=$2
  local params=$3
  printf '%s' "${params}" | compose exec -T "${node}" \
    snw-agent-link --data-dir /var/lib/snw-agent-link "${method}"
}

collect_logs() {
  local service
  for service in derper headscale node-a node-b node-c; do
    compose logs --no-color "${service}" 2>/dev/null | \
      sed -E \
        -e 's/tskey-[A-Za-z0-9_-]+/[REDACTED_TS_AUTHKEY]/g' \
        -e 's/hskey-auth-[A-Za-z0-9_-]+/[REDACTED_HEADSCALE_AUTHKEY]/g' \
        -e 's/(Bearer )[A-Za-z0-9._-]+/\1[REDACTED]/g' \
      >"${ARTIFACT_DIR}/${service}.log" || true
  done
}

cleanup_private() {
  rm -rf "${PRIVATE_DIR}"
}

on_exit() {
  local status=$?
  trap - EXIT
  if [[ ${COLLECT_LOGS_ON_EXIT} == 1 ]]; then
    collect_logs
  fi
  if (( status != 0 )) && [[ ${KEEP_ON_FAILURE} == 1 ]]; then
    log "保留失败现场：${PROJECT_NAME}"
  elif [[ ${E2E_AUTO_DOWN:-1} == 1 ]]; then
    down_stack || true
  fi
  cleanup_private
  exit "${status}"
}

prepare_secret_paths() {
  umask 077
  mkdir -p "${RUNTIME_DIR}"
  chmod 0700 "${RUNTIME_DIR}"
  export HEADSCALE_PREAUTH_KEY_A_FILE="${RUNTIME_DIR}/headscale-node-a.key"
  export HEADSCALE_PREAUTH_KEY_B_FILE="${RUNTIME_DIR}/headscale-node-b.key"
  export HEADSCALE_PREAUTH_KEY_C_FILE="${RUNTIME_DIR}/headscale-node-c.key"
  export DERPER_CERT_DIR="${RUNTIME_DIR}/derper-certs"
  export DERP_MAP_FILE="${RUNTIME_DIR}/derp.yaml"
  touch "${HEADSCALE_PREAUTH_KEY_A_FILE}" "${HEADSCALE_PREAUTH_KEY_B_FILE}" "${HEADSCALE_PREAUTH_KEY_C_FILE}"
  chmod 0600 "${HEADSCALE_PREAUTH_KEY_A_FILE}" "${HEADSCALE_PREAUTH_KEY_B_FILE}" "${HEADSCALE_PREAUTH_KEY_C_FILE}"
  mkdir -p "${DERPER_CERT_DIR}"
  chmod 0700 "${DERPER_CERT_DIR}"
  cat >"${RUNTIME_DIR}/derper-openssl.cnf" <<'EOF'
[req]
distinguished_name = subject
x509_extensions = server
prompt = no

[subject]
CN = derper

[server]
basicConstraints = critical,CA:false
keyUsage = critical,digitalSignature,keyEncipherment
extendedKeyUsage = serverAuth
subjectAltName = DNS:derper
EOF
  if [[ ! -s ${DERPER_CERT_DIR}/derper.key || ! -s ${DERPER_CERT_DIR}/derper.crt ]]; then
    openssl req \
      -x509 \
      -newkey rsa:2048 \
      -sha256 \
      -nodes \
      -days 365 \
      -config "${RUNTIME_DIR}/derper-openssl.cnf" \
      -keyout "${DERPER_CERT_DIR}/derper.key" \
      -out "${DERPER_CERT_DIR}/derper.crt" \
      >/dev/null 2>&1
  fi
  chmod 0600 "${DERPER_CERT_DIR}/derper.key"
  chmod 0644 "${DERPER_CERT_DIR}/derper.crt"
  local certificate_sha256
  certificate_sha256=$(
    openssl x509 -in "${DERPER_CERT_DIR}/derper.crt" -outform DER |
      openssl dgst -sha256 -hex |
      awk '{print $NF}'
  )
  if [[ ! ${certificate_sha256} =~ ^[0-9a-fA-F]{64}$ ]]; then
    die '无法计算自托管 DERP 证书 SHA-256'
  fi
  cat >"${DERP_MAP_FILE}" <<EOF
regions:
  900:
    regionid: 900
    regioncode: snw-e2e
    regionname: SNW self-hosted E2E DERP
    nodes:
      - name: 900a
        regionid: 900
        hostname: derper
        certname: sha256-raw:${certificate_sha256}
        derpport: 3340
        stunport: 3478
EOF
  chmod 0600 "${DERP_MAP_FILE}"
}

validate_node_names() {
  local name
  for name in "${E2E_NODE_A_NAME}" "${E2E_NODE_B_NAME}" "${E2E_NODE_C_NAME}"; do
    if [[ ! ${name} =~ ^[[:alnum:]][[:alnum:].-]{0,62}$ ]]; then
      die "节点名不符合 Tailscale/Docker hostname 约束：${name}"
    fi
  done
  if [[ ${E2E_NODE_A_NAME} == "${E2E_NODE_B_NAME}" || ${E2E_NODE_A_NAME} == "${E2E_NODE_C_NAME}" || ${E2E_NODE_B_NAME} == "${E2E_NODE_C_NAME}" ]]; then
    die '三个节点名必须唯一'
  fi
}

preflight() {
  CURRENT_PHASE=preflight
  require_command curl
  require_command docker
  require_command jq
  require_command openssl
  validate_node_names
  prepare_secret_paths
  docker info >/dev/null 2>&1 || die 'Docker daemon 不可用；请先启动 Docker Desktop'
  curl --fail --silent --show-error --max-time 5 \
    -H 'Authorization: Bearer PROXY_MANAGED' \
    "${CC_SWITCH_HOST_URL%/}/models" \
    >"${ARTIFACT_DIR}/cc-switch-models.json" || \
    die "macOS cc-switch 未监听 ${CC_SWITCH_HOST_URL}；禁止回退到官方云端"
  if jq -e '.data | length > 0' "${ARTIFACT_DIR}/cc-switch-models.json" >/dev/null 2>&1 && \
     ! jq -e --arg model "${CODEX_MODEL}" 'any(.data[]?; .id == $model)' "${ARTIFACT_DIR}/cc-switch-models.json" >/dev/null; then
    die "cc-switch /models 已公布模型但不包含固定模型 ${CODEX_MODEL}"
  fi
  compose config >"${ARTIFACT_DIR}/compose.resolved.yaml"
}

headscale() {
  compose exec -T headscale headscale "$@"
}

wait_control_plane_healthy() {
  local deadline=$((SECONDS + ${E2E_CONTROL_TIMEOUT_SECONDS:-120}))
  local service
  while :; do
    local all_healthy=1
    for service in derper headscale; do
      local container_id
      container_id=$(compose ps -q "${service}")
      if [[ -z ${container_id} ]]; then
        all_healthy=0
        continue
      fi
      local health
      health=$(docker inspect --format '{{if .State.Health}}{{.State.Health.Status}}{{else}}{{.State.Status}}{{end}}' "${container_id}")
      if [[ ${health} != healthy ]]; then
        all_healthy=0
      fi
    done
    if [[ ${all_healthy} == 1 ]]; then
      headscale health >/dev/null
      return 0
    fi
    if (( SECONDS >= deadline )); then
      collect_logs
      die '自托管 Headscale/DERP 未在时限内进入 healthy'
    fi
    sleep 2
  done
}

headscale_user_id() {
  headscale users list --output json | \
    jq -er --arg user "${HEADSCALE_USER}" '.[] | select(.name == $user) | .id'
}

ensure_headscale_user() {
  local user_id
  user_id=$(headscale_user_id 2>/dev/null || true)
  if [[ -z ${user_id} ]]; then
    headscale users create "${HEADSCALE_USER}" --output json >/dev/null
    user_id=$(headscale_user_id)
  fi
  printf '%s\n' "${user_id}"
}

write_headscale_key() {
  local user_id=$1
  local destination=$2
  local response
  response=$(headscale preauthkeys create \
    --user "${user_id}" \
    --expiration 1h \
    --output json)
  local key
  key=$(jq -er '.key | select(startswith("hskey-auth-"))' <<<"${response}")
  umask 077
  printf '%s\n' "${key}" >"${destination}"
  chmod 0600 "${destination}"
}

prepare_headscale_keys() {
  local user_id
  user_id=$(ensure_headscale_user)
  local destination
  for destination in "${HEADSCALE_PREAUTH_KEY_A_FILE}" "${HEADSCALE_PREAUTH_KEY_B_FILE}" "${HEADSCALE_PREAUTH_KEY_C_FILE}"; do
    if [[ ! -s ${destination} ]]; then
      write_headscale_key "${user_id}" "${destination}"
    fi
  done
  log "Headscale 用户 ${HEADSCALE_USER} 与三份一次性节点密钥已就绪"
}

wait_healthy() {
  local deadline=$((SECONDS + ${E2E_START_TIMEOUT_SECONDS:-240}))
  local node
  while :; do
    local all_healthy=1
    for node in node-a node-b node-c; do
      local container_id
      container_id=$(compose ps -q "${node}")
      if [[ -z ${container_id} ]]; then
        all_healthy=0
        continue
      fi
      local health
      health=$(docker inspect --format '{{if .State.Health}}{{.State.Health.Status}}{{else}}{{.State.Status}}{{end}}' "${container_id}")
      if [[ ${health} != healthy ]]; then
        all_healthy=0
      fi
    done
    if [[ ${all_healthy} == 1 ]]; then
      return 0
    fi
    if (( SECONDS >= deadline )); then
      collect_logs
      die '三节点未在时限内进入 healthy；查看脱敏 artifacts 日志'
    fi
    sleep 2
  done
}

up_stack() {
  CURRENT_PHASE=up
  preflight
  if [[ ${E2E_RESET_STATE:-0} == 1 ]]; then
    compose down --volumes --remove-orphans >/dev/null 2>&1 || true
  fi
  compose build --pull
  compose up --detach --remove-orphans derper headscale
  wait_control_plane_healthy
  prepare_headscale_keys
  compose up --detach --remove-orphans node-a node-b node-c
  wait_healthy
}

node_tailnet_ip() {
  compose exec -T "$1" tailscale --socket=/run/tailscale/tailscaled.sock ip -4 | head -n 1
}

node_stable_id() {
  compose exec -T "$1" tailscale --socket=/run/tailscale/tailscaled.sock status --json | jq -r '.Self.ID'
}

collect_infra_evidence() {
  CURRENT_PHASE=tailnet-evidence
  headscale version >"${ARTIFACT_DIR}/headscale.version.txt"
  headscale health --output json >"${ARTIFACT_DIR}/headscale.health.json"
  headscale users list --output json | \
    jq '[.[] | {id, name, created_at}]' >"${ARTIFACT_DIR}/headscale.users.json"
  headscale nodes list --output json >"${ARTIFACT_DIR}/headscale.nodes.json"
  compose exec -T derper wget --no-check-certificate -q -O /dev/null https://derper:3340/
  local node
  for node in node-a node-b node-c; do
    compose exec -T "${node}" tailscale --socket=/run/tailscale/tailscaled.sock status --json | \
      jq '{BackendState, CurrentTailnet, Self: {ID: .Self.ID, HostName: .Self.HostName, TailscaleIPs: .Self.TailscaleIPs, Online: .Self.Online}}' \
      >"${ARTIFACT_DIR}/${node}.tailscale.json"
    compose exec -T "${node}" codex --version >"${ARTIFACT_DIR}/${node}.codex-version.txt"
    compose exec -T "${node}" snw-agent-link --data-dir /var/lib/snw-agent-link status \
      >"${ARTIFACT_DIR}/${node}.link-status.json"
    local tailnet_ip
    tailnet_ip=$(node_tailnet_ip "${node}")
    if [[ ! ${tailnet_ip} =~ ^100\. ]]; then
      die "${node} 未使用真实 Tailscale IPv4：${tailnet_ip:-empty}"
    fi
    if ! jq -e '.BackendState == "Running" and .Self.Online == true and (.Self.ID | length > 0)' \
      "${ARTIFACT_DIR}/${node}.tailscale.json" >/dev/null; then
      die "${node} 缺少 Running/Online/StableNodeID 证据"
    fi
  done

  local source
  local target
  for source in node-a node-b node-c; do
    for target in node-a node-b node-c; do
      if [[ ${source} == "${target}" ]]; then continue; fi
      local target_ip
      target_ip=$(node_tailnet_ip "${target}")
      compose exec -T "${source}" tailscale --socket=/run/tailscale/tailscaled.sock \
        ping --timeout=10s "${target_ip}" \
        >"${ARTIFACT_DIR}/${source}-to-${target}.tailscale-ping.txt"
    done
  done
}

assert_adapter_ingress() {
  CURRENT_PHASE=adapter-ingress
  local node
  for node in node-a node-b node-c; do
    if ! compose exec -T "${node}" python3 -c 'import snw_agent_link_codex.http_server' >/dev/null 2>&1; then
      die "核心 Codex adapter 尚无 loopback A2A HTTP ingress：缺少 snw_agent_link_codex.http_server；不得用 mock/bridge 伪造六方向通过"
    fi
  done
}

register_node() {
  local node=$1
  local params
  local configured_name
  configured_name=$(node_name "${node}")
  if node_state_ready "${node}"; then
    local agent token
    agent=$(node_agent "${node}")
    token=$(node_token "${node}")
    params=$(jq -nc \
      --arg agent "${agent}" \
      --arg token "${token}" \
      --arg name "${configured_name}" \
      '{agentId:$agent,registrationToken:$token,displayName:("SNW E2E " + $name),localEndpoint:"http://127.0.0.1:7780/a2a/rest",agentCard:{name:("SNW E2E " + $name),version:"1.0.0"}}')
  else
    params=$(jq -nc \
      --arg name "${configured_name}" \
      '{displayName:("SNW E2E " + $name),localEndpoint:"http://127.0.0.1:7780/a2a/rest",agentCard:{name:("SNW E2E " + $name),version:"1.0.0"}}')
  fi
  local response
  response=$(ipc_call "${node}" agent.ensure "${params}")
  if ! jq -e '.registration.agentId and (.registrationToken | length > 0)' <<<"${response}" >/dev/null; then
    die "${node} agent.ensure 未返回 Agent ID 和 registration token"
  fi
  local state_payload
  state_payload=$(jq -c '{agentId:.registration.agentId,registrationToken:.registrationToken}' <<<"${response}")
  printf '%s' "${state_payload}" | compose exec -T "${node}" bash -c '
    set -Eeuo pipefail
    umask 077
    state_dir=/var/lib/snw-agent-link/e2e
    mkdir -p "${state_dir}"
    payload=$(cat)
    agent_id=$(jq -er .agentId <<<"${payload}")
    registration_token=$(jq -er .registrationToken <<<"${payload}")
    printf "%s\\n" "${agent_id}" >"${state_dir}/agent-id.tmp"
    printf "%s\\n" "${registration_token}" >"${state_dir}/registration-token.tmp"
    chmod 0600 "${state_dir}/agent-id.tmp" "${state_dir}/registration-token.tmp"
    mv -f "${state_dir}/agent-id.tmp" "${state_dir}/agent-id"
    mv -f "${state_dir}/registration-token.tmp" "${state_dir}/registration-token"
  '
  jq 'del(.registrationToken)' <<<"${response}" >"${ARTIFACT_DIR}/${node}.registration.json"
  log "${node} Agent ID：$(node_agent "${node}")"
}

start_adapter_ingress() {
  local node=$1
  local agent
  agent=$(node_agent "${node}")
  local token
  token=$(node_token "${node}")
  if compose exec -T "${node}" nc -z 127.0.0.1 7780 >/dev/null 2>&1; then
    return 0
  fi
  compose exec --detach \
    --env "SNW_AGENT_LINK_AGENT_ID=${agent}" \
    --env "SNW_AGENT_LINK_REGISTRATION_TOKEN=${token}" \
    "${node}" \
    python3 -m snw_agent_link_codex.http_server --host 127.0.0.1 --port 7780
  local deadline=$((SECONDS + 30))
  until compose exec -T "${node}" nc -z 127.0.0.1 7780; do
    if (( SECONDS >= deadline )); then
      die "${node} adapter ingress 未监听 127.0.0.1:7780"
    fi
    sleep 0.5
  done
}

register_and_start_adapters() {
  CURRENT_PHASE=registration
  local node
  for node in node-a node-b node-c; do register_node "${node}"; done
  for node in node-a node-b node-c; do start_adapter_ingress "${node}"; done
}

pair_nodes() {
  local inviter=$1
  local invitee=$2
  local inviter_agent
  local invitee_agent
  inviter_agent=$(node_agent "${inviter}")
  invitee_agent=$(node_agent "${invitee}")
  local inviter_contacts invitee_contacts
  inviter_contacts=$(ipc_call "${inviter}" contact.list "$(jq -nc --arg local "${inviter_agent}" '{localAgentId:$local}')")
  invitee_contacts=$(ipc_call "${invitee}" contact.list "$(jq -nc --arg local "${invitee_agent}" '{localAgentId:$local}')")
  local inviter_active=0 invitee_active=0
  if jq -e --arg remote "${invitee_agent}" '.[]? | select(.remoteAgentId == $remote and .state == "active")' <<<"${inviter_contacts}" >/dev/null; then
    inviter_active=1
  fi
  if jq -e --arg remote "${inviter_agent}" '.[]? | select(.remoteAgentId == $remote and .state == "active")' <<<"${invitee_contacts}" >/dev/null; then
    invitee_active=1
  fi
  if (( inviter_active == 1 && invitee_active == 1 )); then
    log "跳过已 active 配对：${inviter_agent} <-> ${invitee_agent}"
    return 0
  fi
  if (( inviter_active == 1 || invitee_active == 1 )); then
    die "${inviter_agent} 与 ${invitee_agent} 配对状态不一致，拒绝静默覆盖"
  fi
  local inviter_ip
  local invitee_ip
  local inviter_node_id
  local invitee_node_id
  inviter_ip=$(node_tailnet_ip "${inviter}")
  invitee_ip=$(node_tailnet_ip "${invitee}")
  inviter_node_id=$(node_stable_id "${inviter}")
  invitee_node_id=$(node_stable_id "${invitee}")
  local inviter_host
  local invitee_host
  inviter_host=$(node_host_fingerprint "${inviter}")
  invitee_host=$(node_host_fingerprint "${invitee}")

  local invite
  invite=$(ipc_call "${inviter}" pair.invite "$(jq -nc \
    --arg local "${inviter_agent}" --arg remote "${invitee_agent}" \
    --arg host "${inviter_host}" --arg ip "${inviter_ip}" --arg node "${inviter_node_id}" \
    '{localAgentId:$local,remoteAgentId:$remote,localHostFingerprint:$host,tailscaleAddress:$ip,tailscaleNodeId:$node,ttl:3600000000000}')")
  local acceptance
  acceptance=$(ipc_call "${invitee}" pair.accept "$(jq -nc \
    --arg local "${invitee_agent}" --arg host "${invitee_host}" --arg ip "${invitee_ip}" --arg node "${invitee_node_id}" \
    --argjson invite "${invite}" \
    '{localAgentId:$local,localHostFingerprint:$host,tailscaleAddress:$ip,tailscaleNodeId:$node,invite:$invite}')")
  local acceptance_fingerprint
  acceptance_fingerprint=$(jq -r '.envelope.keyFingerprint' <<<"${acceptance}")
  local confirmation
  confirmation=$(ipc_call "${inviter}" pair.approve "$(jq -nc \
    --arg local "${inviter_agent}" --arg host "${invitee_host}" --arg fingerprint "${acceptance_fingerprint}" \
    --argjson acceptance "${acceptance}" \
    '{localAgentId:$local,acceptance:$acceptance,expectedHostFingerprint:$host,expectedAgentFingerprint:$fingerprint}')")
  local receipt
  receipt=$(ipc_call "${invitee}" pair.confirm "$(jq -nc \
    --arg local "${invitee_agent}" --argjson confirmation "${confirmation}" \
    '{localAgentId:$local,confirmation:$confirmation}')")
  ipc_call "${inviter}" pair.activate "$(jq -nc \
    --arg local "${inviter_agent}" --argjson receipt "${receipt}" \
    '{localAgentId:$local,receipt:$receipt}')" >/dev/null
  printf '%s\n' "${receipt}" | jq '{inviteId:.payload.inviteId,invitingAgentId:.payload.invitingAgentId,acceptingAgentId:.payload.acceptingAgentId}' \
    >"${ARTIFACT_DIR}/${inviter}-${invitee}.pairing.json"
}

pair_all() {
  CURRENT_PHASE=pairing
  pair_nodes node-a node-b
  pair_nodes node-a node-c
  pair_nodes node-b node-c
  local node
  for node in node-a node-b node-c; do
    ipc_call "${node}" contact.list "$(jq -nc --arg local "$(node_agent "${node}")" '{localAgentId:$local}')" \
      >"${ARTIFACT_DIR}/${node}.contacts.json"
    if [[ $(jq '[.[] | select(.state == "active")] | length' "${ARTIFACT_DIR}/${node}.contacts.json") -ne 2 ]]; then
      die "${node} 未形成两个 active 联系人"
    fi
  done
}

codex_probe() {
  local node=$1
  local node_upper
  node_upper=$(printf '%s' "${node}" | tr '[:lower:]' '[:upper:]')
  local marker="SNW_E2E_${node_upper}_${RUN_ID}"
  compose exec -T "${node}" codex exec \
    --json \
    --model "${CODEX_MODEL}" \
    --sandbox read-only \
    --skip-git-repo-check \
    "只回复这一段，不要调用工具：${marker}" \
    >"${ARTIFACT_DIR}/${node}.codex-probe.jsonl"
  if ! grep -F "${marker}" "${ARTIFACT_DIR}/${node}.codex-probe.jsonl" >/dev/null; then
    die "${node} Codex LLM route probe 未返回 marker"
  fi
}

probe_all_codex_routes() {
  CURRENT_PHASE=codex-route
  local node
  for node in node-a node-b node-c; do codex_probe "${node}"; done
}

create_thread_handle() {
  local node=$1
  local agent
  agent=$(node_agent "${node}")
  local token
  token=$(node_token "${node}")
  local thread_id
  thread_id=$(
    jq -er 'select(.type == "thread.started") | .thread_id' \
      "${ARTIFACT_DIR}/${node}.codex-probe.jsonl" |
      tail -n 1
  )
  if [[ ! ${thread_id} =~ ^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$ ]]; then
    die "${node} app-server 未返回有效 thread ID"
  fi
  local hook_payload
  hook_payload=$(jq -nc --arg session "${thread_id}" '{session_id:$session,source:"startup",cwd:"/opt/snw-agent-link"}')
  local hook_output
  hook_output=$(printf '%s' "${hook_payload}" | compose exec -T \
    --env "SNW_AGENT_LINK_AGENT_ID=${agent}" \
    --env "SNW_AGENT_LINK_REGISTRATION_TOKEN=${token}" \
    "${node}" \
    python3 /opt/snw-agent-link/adapters/snw-agent-link-codex/hooks/session-start.py)
  if ! jq -e '.hookSpecificOutput.additionalContext | type == "string"' <<<"${hook_output}" >/dev/null 2>&1; then
    die "${node} SessionStart Hook 未返回合法 JSON"
  fi
  local handle
  handle=$(jq -er '.hookSpecificOutput.additionalContext' <<<"${hook_output}" | sed -n 's/.*session_handle=\([^ ]*\).*/\1/p')
  if [[ -z ${handle} ]]; then die "${node} 未生成 session_handle"; fi
  printf '%s\t%s\n' "${thread_id}" "${handle}"
}

mcp_tool() {
  local node=$1
  local token=$2
  local tool_name=$3
  local arguments=$4
  local request_file="${PRIVATE_DIR}/${node}.${tool_name}.$RANDOM.jsonl"
  jq -nc '{jsonrpc:"2.0",id:1,method:"initialize",params:{}}' >"${request_file}"
  jq -nc '{jsonrpc:"2.0",method:"notifications/initialized",params:{}}' >>"${request_file}"
  jq -nc --arg name "${tool_name}" --argjson arguments "${arguments}" \
    '{jsonrpc:"2.0",id:2,method:"tools/call",params:{name:$name,arguments:$arguments}}' >>"${request_file}"
  compose exec -T \
    --env "SNW_AGENT_LINK_AGENT_ID=$(node_agent "${node}")" \
    --env "SNW_AGENT_LINK_REGISTRATION_TOKEN=${token}" \
    "${node}" \
    python3 /opt/snw-agent-link/adapters/snw-agent-link-codex/mcp_server.py \
    <"${request_file}" | jq -s 'map(select(.id == 2))[0]'
}

wait_delivery() {
  local node=$1
  local message_id=$2
  local token
  token=$(node_token "${node}")
  local deadline=$((SECONDS + 60))
  while :; do
    local status
    status=$(ipc_call "${node}" message.status "$(jq -nc \
      --arg source "$(node_agent "${node}")" --arg token "${token}" --arg message "${message_id}" \
      '{sourceAgentId:$source,registrationToken:$token,messageId:$message}')")
    if [[ $(jq -r '.state' <<<"${status}") == delivered ]]; then
      printf '%s\n' "${status}"
      return 0
    fi
    if (( SECONDS >= deadline )); then
      die "${node} 消息 ${message_id} 未在 60 秒内 delivered"
      return 1
    fi
    sleep 1
  done
}

send_direction() {
  local source=$1
  local target=$2
  local source_agent
  local target_agent
  source_agent=$(node_agent "${source}")
  target_agent=$(node_agent "${target}")
  local context_id="ctx-${source_agent}-${target_agent}-${RUN_ID}"
  local thread_and_handle
  thread_and_handle=$(create_thread_handle "${source}")
  local thread_id=${thread_and_handle%%$'\t'*}
  local session_handle=${thread_and_handle#*$'\t'}
  local result
  result=$(mcp_tool "${source}" "$(node_token "${source}")" agent_contact "$(jq -nc \
    --arg target "${target_agent}" --arg message "E2E ${source_agent} -> ${target_agent}" \
    --arg handle "${session_handle}" --arg context "${context_id}" \
    '{target_agent:$target,message:$message,session_handle:$handle,context_id:$context}')")
  if [[ $(jq -r '.result.isError' <<<"${result}") != false ]]; then
    die "${source}->${target} MCP agent_contact 失败：$(jq -r '.result.content[0].text' <<<"${result}")"
  fi
  local message_id
  message_id=$(jq -r '.result.structuredContent.messageId' <<<"${result}")
  local delivery
  delivery=$(wait_delivery "${source}" "${message_id}")
  local target_mailbox
  target_mailbox=$(ipc_call "${target}" mailbox.list "$(jq -nc \
    --arg agent "${target_agent}" --arg token "$(node_token "${target}")" --arg context "${context_id}" \
    '{agentId:$agent,registrationToken:$token,contextId:$context,unreadOnly:false}')")
  if ! jq -e --arg message "${message_id}" '.items[]? | select(.messageId == $message)' <<<"${target_mailbox}" >/dev/null; then
    die "${source}->${target} delivered 但对端 mailbox 缺少 ${message_id}"
  fi
  local binding
  binding=$(mcp_tool "${target}" "$(node_token "${target}")" agent_binding_status "$(jq -nc --arg context "${context_id}" '{context_id:$context}')")
  if [[ $(jq -r '.result.structuredContent.active.threadId // empty' <<<"${binding}") == '' ]]; then
    die "${source}->${target} 对端 adapter 未创建 context/thread binding"
  fi
  jq -nc \
    --arg source "${source_agent}" --arg target "${target_agent}" \
    --arg context "${context_id}" --arg message "${message_id}" --arg thread "${thread_id}" \
    --arg state "$(jq -r '.state' <<<"${delivery}")" \
    '{sourceAgentId:$source,targetAgentId:$target,contextId:$context,messageId:$message,sourceThreadId:$thread,deliveryState:$state}' \
    >"${ARTIFACT_DIR}/${source}-to-${target}.a2a.json"
}

send_all_directions() {
  CURRENT_PHASE=six-direction-a2a
  send_direction node-a node-b
  send_direction node-b node-a
  send_direction node-a node-c
  send_direction node-c node-a
  send_direction node-b node-c
  send_direction node-c node-b
}

negative_admission_tests() {
  CURRENT_PHASE=negative-admission
  local source=node-a
  local target=node-b
  local target_agent target_ip message_id payload response_file http_status
  target_agent=$(node_agent "${target}")
  target_ip=$(node_tailnet_ip "${target}")
  message_id="negative-unpaired-${RUN_ID}"
  payload=$(jq -nc \
    --arg message "${message_id}" \
    '{message:{messageId:$message,contextId:$message,role:"user",parts:[{kind:"text",text:"negative admission probe"}]}}')
  response_file="${PRIVATE_DIR}/unpaired-response.json"
  http_status=$(printf '%s' "${payload}" | compose exec -T "${source}" sh -c \
    'curl --silent --show-error --max-time 5 -o /tmp/snw-unpaired-response.json -w "%{http_code}" \
      -H "Content-Type: application/json" -H "X-SNW-Agent-ID: agent-not-paired" \
      --data-binary @- "http://$0:7443/agents/$1/a2a/rest"; cat /tmp/snw-unpaired-response.json >&2' \
    "${target_ip}" "${target_agent}" 2>"${response_file}")
  if [[ ${http_status} != 403 ]]; then
    die "未配对 Agent 访问 ${target} 未被拒绝：HTTP ${http_status}"
  fi
  cp "${response_file}" "${ARTIFACT_DIR}/negative-unpaired-response.json"

  local ingress
  ingress=$(compose exec -T "${target}" python3 -c \
    'from snw_agent_link_codex.relay import registration_ingress_token; import pathlib; print(registration_ingress_token(pathlib.Path("/var/lib/snw-agent-link/e2e/registration-token").read_text().strip()))')
  response_file="${PRIVATE_DIR}/source-mismatch-response.json"
  payload=$(jq -nc \
    --arg source "${target_agent}" --arg target "${target_agent}" --arg message "negative-source-${RUN_ID}" \
    '{sourceAgentId:$source,targetAgentId:$target,contextId:$message,messageId:$message,body:"source mismatch probe"}')
  http_status=$(printf '%s' "${payload}" | compose exec -T "${target}" sh -c \
    'curl --silent --show-error --max-time 5 -o /tmp/snw-source-mismatch-response.json -w "%{http_code}" \
      -H "Content-Type: application/json" -H "X-SNW-Linkd-Ingress: $0" -H "X-SNW-Agent-ID: agent-a" \
      --data-binary @- http://127.0.0.1:7780/a2a/inbound; cat /tmp/snw-source-mismatch-response.json >&2' \
    "${ingress}" 2>"${response_file}")
  if [[ ${http_status} != 400 ]]; then
    die "Adapter 未拒绝 source/header 不一致：HTTP ${http_status}"
  fi
  cp "${response_file}" "${ARTIFACT_DIR}/negative-source-mismatch-response.json"
}

verify_all() {
  collect_infra_evidence
  assert_adapter_ingress
  register_and_start_adapters
  pair_all
  probe_all_codex_routes
  send_all_directions
  negative_admission_tests
  jq -nc \
    --arg runId "${RUN_ID}" --arg model "${CODEX_MODEL}" \
    '{ok:true,runId:$runId,model:$model,nodes:3,directions:6,tailnet:"headscale-self-hosted",officialSaaS:false}' \
    >"${ARTIFACT_DIR}/result.json"
  CURRENT_PHASE=complete
  log "PASS：证据目录 ${ARTIFACT_DIR}"
}

doctor_all() {
  CURRENT_PHASE=doctor
  wait_control_plane_healthy
  jq -nc \
    --arg version "$(headscale version | tr '\n' ' ')" \
    --argjson health "$(headscale health --output json)" \
    --argjson users "$(headscale users list --output json)" \
    --argjson nodes "$(headscale nodes list --output json)" \
    '{version:$version,health:$health,userCount:($users|length),nodeCount:($nodes|length)}' \
    >"${ARTIFACT_DIR}/headscale.doctor.json"
  compose exec -T derper wget --no-check-certificate -q -O /dev/null https://derper:3340/
  local node
  local failed=0
  for node in node-a node-b node-c; do
    compose exec -T "${node}" /usr/local/bin/e2e-entrypoint doctor \
      >"${ARTIFACT_DIR}/${node}.doctor.txt" || failed=1
  done
  collect_infra_evidence
  if (( failed != 0 )); then
    die '至少一个节点 doctor 失败；缺少 adapter ingress 或运行时依赖时必须非零退出'
  fi
}

down_stack() {
  CURRENT_PHASE=down
  require_command docker
  local node
  if [[ ${E2E_REMOVE_VOLUMES:-0} == 1 ]]; then
    for node in node-a node-b node-c; do
      compose exec -T "${node}" tailscale --socket=/run/tailscale/tailscaled.sock logout >/dev/null 2>&1 || true
    done
  fi
  if [[ ${KEEP_VOLUMES} == 1 && ${E2E_REMOVE_VOLUMES:-0} != 1 ]]; then
    compose down --remove-orphans
  else
    compose down --volumes --remove-orphans
  fi
}

status_all() {
  CURRENT_PHASE=status
  require_command docker
  prepare_secret_paths
  compose ps || true
  if compose ps -q headscale >/dev/null 2>&1 && [[ -n $(compose ps -q headscale 2>/dev/null) ]]; then
    printf 'headscale\t%s\tusers=%s\tnodes=%s\n' \
      "$(headscale version | head -n 1)" \
      "$(headscale users list --output json | jq 'length')" \
      "$(headscale nodes list --output json | jq 'length')"
  fi
  local node
  for node in node-a node-b node-c; do
    local container_id
    container_id=$(compose ps -q "${node}" 2>/dev/null || true)
    if [[ -z ${container_id} ]]; then
      printf '%s\tstopped\n' "${node}"
      continue
    fi
    local health
    health=$(docker inspect --format '{{if .State.Health}}{{.State.Health.Status}}{{else}}{{.State.Status}}{{end}}' "${container_id}" 2>/dev/null || printf '%s' unknown)
    local agent='unregistered'
    agent=$(node_agent "${node}" 2>/dev/null || printf '%s' unregistered)
    printf '%s\t%s\t%s\t%s\n' "${node}" "${health}" "$(node_name "${node}")" "${agent}"
  done
}

print_deploy_summary() {
  printf '\n三节点 E2E 已部署并保持运行。Agent IDs：\n'
  local node
  for node in node-a node-b node-c; do
    printf '  %-6s %-24s %s\n' "${node}" "$(node_agent "${node}")" "$(node_name "${node}")"
  done
  printf '\n常用命令：\n  scripts/deploy-e2e.sh status\n  scripts/deploy-e2e.sh doctor\n  scripts/deploy-e2e.sh pair\n  scripts/deploy-e2e.sh down\n  scripts/deploy-e2e.sh clean\n\n'
}

clean_stack() {
  CURRENT_PHASE=clean
  COLLECT_LOGS_ON_EXIT=0
  prepare_secret_paths
  E2E_REMOVE_VOLUMES=1 down_stack
  rm -rf "${RUNTIME_DIR}"
  rm -rf "${REPO_ROOT}/docker/e2e/artifacts"
  mkdir -p "${REPO_ROOT}/docker/e2e/artifacts"
  log '已删除 Compose 容器、卷和 E2E artifacts；下一次 deploy 将重新注册 Agent'
}

usage() {
  cat <<'EOF'
用法：scripts/e2e/run-pairwise.sh [deploy|status|doctor|down|clean|pair|all|up|verify]

无需 Tailscale 官方账号或 auth key。runner 会启动 Headscale + 自托管 DERP，
自动创建 snw-agents 用户和三份一小时有效、不可复用的 preauth key。
EOF
}

trap on_exit EXIT INT TERM

case ${1:-all} in
  deploy)
    E2E_AUTO_DOWN=0
    up_stack
    verify_all
    print_deploy_summary
    ;;
  status)
    E2E_AUTO_DOWN=0
    status_all
    ;;
  pair)
    E2E_AUTO_DOWN=0
    up_stack
    collect_infra_evidence
    assert_adapter_ingress
    register_and_start_adapters
    pair_all
    print_deploy_summary
    ;;
  clean)
    E2E_AUTO_DOWN=0
    clean_stack
    ;;
  all)
    up_stack
    verify_all
    ;;
  up)
    E2E_AUTO_DOWN=0
    up_stack
    collect_infra_evidence
    ;;
  verify)
    E2E_AUTO_DOWN=0
    prepare_secret_paths
    wait_control_plane_healthy
    wait_healthy
    verify_all
    ;;
  doctor)
    E2E_AUTO_DOWN=0
    prepare_secret_paths
    doctor_all
    ;;
  down)
    E2E_AUTO_DOWN=0
    prepare_secret_paths
    down_stack
    ;;
  -h|--help|help)
    E2E_AUTO_DOWN=0
    usage
    ;;
  *)
    usage >&2
    exit 64
    ;;
esac
