#!/usr/bin/env bash
# ============================================================
#  从仓库根目录的 .env 渲染 frps.toml 与 Caddyfile。
#
#  用法（在仓库根目录执行）：
#     bash deploy/scripts/render.sh
# ============================================================
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"

ENV_FILE="${ROOT}/.env"
FRPS_TPL="${ROOT}/deploy/frps/frps.toml.template"
FRPS_OUT="${ROOT}/deploy/frps/frps.toml"
CADDY_TPL="${ROOT}/deploy/caddy/Caddyfile.template"
CADDY_OUT="${ROOT}/deploy/caddy/Caddyfile"

[[ -f "${ENV_FILE}" ]] || {
  echo "未找到 ${ENV_FILE}，请先复制 .env.example 为 .env 并填写真实值。" >&2
  exit 1
}

# ---- 解析 .env（不使用 source，避免执行到非预期的内容）----
declare -A VARS=()
while IFS= read -r line || [[ -n "${line}" ]]; do
  line="${line%$'\r'}"
  [[ -z "${line// }" ]] && continue
  [[ "${line}" =~ ^[[:space:]]*# ]] && continue
  [[ "${line}" != *=* ]] && continue
  key="${line%%=*}"
  val="${line#*=}"
  key="$(echo "${key}" | xargs)"
  val="$(echo "${val}" | xargs)"
  VARS["${key}"]="${val}"
done < "${ENV_FILE}"

strip_scheme() {
  local v="${1:-}"
  v="${v#http://}"
  v="${v#https://}"
  echo "${v%/}"
}

USER_DOMAIN="$(strip_scheme "${VARS[LT_USER_PUBLIC_URL]:-}")"
ADMIN_DOMAIN="$(strip_scheme "${VARS[LT_ADMIN_PUBLIC_URL]:-}")"

if [[ -z "${USER_DOMAIN}" ]]; then
  echo "LT_USER_PUBLIC_URL 未填写：Caddy 需要一个域名来签发证书。" >&2
  exit 1
fi

VARS[LT_USER_DOMAIN]="${USER_DOMAIN}"
VARS[LT_ADMIN_DOMAIN]="${ADMIN_DOMAIN:-admin.invalid.local}"
VARS[LT_ADMIN_ALLOW_CIDR]="${VARS[LT_ADMIN_ALLOW_CIDR]:-127.0.0.1/32}"
VARS[LT_ACME_EMAIL]="${VARS[LT_ACME_EMAIL]:-admin@${USER_DOMAIN}}"
VARS[LT_TUNNEL_DOMAIN]="${VARS[LT_TUNNEL_DOMAIN]:-}"

REQUIRED=(
  LT_GATEWAY_PORT LT_KCP_PORT LT_VHOST_HTTP_PORT LT_VHOST_HTTPS_PORT
  LT_FRPS_TOKEN LT_PORT_RANGE_START LT_PORT_RANGE_END LT_MAX_PORTS_PER_USER
  LT_FRPS_API_PORT LT_FRPS_API_USER LT_FRPS_API_PASSWORD
  LT_USER_PORT LT_ADMIN_PORT
)
MISSING=()
for k in "${REQUIRED[@]}"; do
  [[ -z "${VARS[$k]:-}" ]] && MISSING+=("$k")
done
if (( ${#MISSING[@]} > 0 )); then
  echo "以下配置项缺失，请在 .env 中补齐：${MISSING[*]}" >&2
  exit 1
fi

for k in "${!VARS[@]}"; do
  if [[ "${VARS[$k]}" == CHANGE_ME* ]]; then
    echo "配置项 ${k} 仍是占位符，请改为真实值。" >&2
    exit 1
  fi
done

render() {
  local tpl="$1" out="$2"
  local text
  text="$(cat "${tpl}")"
  # 长键优先替换，避免前缀重叠导致误替换
  while IFS= read -r k; do
    local v="${VARS[$k]:-}"
    text="${text//\$\{${k}\}/${v}}"
  done < <(printf '%s\n' "${!VARS[@]}" | awk '{ print length, $0 }' | sort -rn | cut -d' ' -f2-)

  if grep -qE '\$\{[A-Z_]+\}' <<< "${text}"; then
    echo "模板 ${tpl} 中存在未替换的占位符：" >&2
    grep -oE '\$\{[A-Z_]+\}' <<< "${text}" | sort -u >&2
    exit 1
  fi

  printf '%s' "${text}" > "${out}"
  echo "已生成 ${out}"
}

render "${FRPS_TPL}" "${FRPS_OUT}"
render "${CADDY_TPL}" "${CADDY_OUT}"

cat <<'EOF'

渲染完成。接下来：
  1) 确保防火墙/安全组只放行 80、443 与隧道端口池（默认 20000-30000），以及网关端口 7000/TCP 与 7001/UDP
  2) 在仓库根目录执行： docker compose -f deploy/docker-compose.yml up -d --build
EOF
