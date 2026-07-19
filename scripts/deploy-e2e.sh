#!/usr/bin/env bash
set -Eeuo pipefail

SCRIPT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
REPO_ROOT=$(cd "${SCRIPT_DIR}/.." && pwd)
ENV_FILE=${E2E_ENV_FILE:-${REPO_ROOT}/docker/e2e/.env}
RUNNER=${REPO_ROOT}/scripts/e2e/run-pairwise.sh

usage() {
  cat <<'EOF'
用法：scripts/deploy-e2e.sh [deploy|status|doctor|down|clean|pair]

首次运行：
  cp docker/e2e/.env.example docker/e2e/.env
  # 编辑 .env 后执行：
  scripts/deploy-e2e.sh deploy
EOF
}

command_name=${1:-deploy}
case ${command_name} in
  deploy|status|doctor|down|clean|pair) ;;
  -h|--help|help)
    usage
    exit 0
    ;;
  *)
    usage >&2
    exit 64
    ;;
esac

if [[ -f ${ENV_FILE} ]]; then
  set -a
  # shellcheck disable=SC1090
  source "${ENV_FILE}"
  set +a
fi

export CC_SWITCH_HOST_URL=${CC_SWITCH_BASE_URL:-${CC_SWITCH_HOST_URL:-http://127.0.0.1:15721/v1}}
export CODEX_MODEL=${CODEX_MODEL:-gpt-5.6-sol}
exec "${RUNNER}" "${command_name}"
