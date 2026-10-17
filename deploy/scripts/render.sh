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
#
# 值的解码与面板 helper 写盘时用的编码（server/cmd/lt-config/envfile.go 的
# encodeEnvValue）互逆，遵循 Compose dotenv 语义：
#   - 双引号值：先处理转义序列（\\、\"、\n、\r、\t），再还原 $$ 插值转义；
#   - 单引号值：按字面保留；
#   - 裸值：只还原 $$。
# 原先用 xargs 做两端去空白，顺带会把引号和反斜杠按 xargs 自己的规则拆掉
# ——helper 为多参数 DNS 配置写出的带引号值到这里就面目全非了。
trim() {
  local s="$1"
  s="${s#"${s%%[![:space:]]*}"}"
  s="${s%"${s##*[![:space:]]}"}"
  printf '%s' "${s}"
}

decode_env_value() {
  local raw="$1"
  local n=${#raw}
  if (( n < 2 )); then
    printf '%s' "${raw//\$\$/\$}"
    return
  fi
  local first="${raw:0:1}" last="${raw:n-1:1}"
  if [[ "${first}" == '"' && "${last}" == '"' ]]; then
    local inner="${raw:1:n-2}"
    # 单趟替换：先把转义的反斜杠换成哨兵字符，避免 \" 与 \\ 互相纠缠；
    # 只处理 Compose 定义的转义序列，未知的保持原样（与 helper 一致）。
    # \x01 不会出现在 helper 写出的值里（控制字符在写入前就被拒绝）。
    local sent=$'\x01'
    inner="${inner//\\\\/${sent}}"
    inner="${inner//\\\"/\"}"
    inner="${inner//\\n/$'\n'}"
    inner="${inner//\\r/$'\r'}"
    inner="${inner//\\t/$'\t'}"
    inner="${inner//${sent}/\\}"
    printf '%s' "${inner//\$\$/\$}"
    return
  fi
  if [[ "${first}" == "'" && "${last}" == "'" ]]; then
    printf '%s' "${raw:1:n-2}"
    return
  fi
  printf '%s' "${raw//\$\$/\$}"
}

declare -A VARS=()
while IFS= read -r line || [[ -n "${line}" ]]; do
  line="${line%$'\r'}"
  [[ -z "${line// }" ]] && continue
  [[ "${line}" =~ ^[[:space:]]*# ]] && continue
  [[ "${line}" != *=* ]] && continue
  key="${line%%=*}"
  val="${line#*=}"
  key="$(trim "${key}")"
  val="$(trim "${val}")"
  VARS["${key}"]="$(decode_env_value "${val}")"
done < "${ENV_FILE}"

strip_scheme() {
  local v="${1:-}"
  v="${v#http://}"
  v="${v#https://}"
  echo "${v%/}"
}

USER_DOMAIN="$(strip_scheme "${VARS[LT_USER_PUBLIC_URL]:-}")"

if [[ -z "${USER_DOMAIN}" ]]; then
  echo "LT_USER_PUBLIC_URL 未填写：Caddy 需要一个域名来签发证书。" >&2
  exit 1
fi

VARS[LT_USER_DOMAIN]="${USER_DOMAIN}"
# 管理后台与用户控制台共用域名，仅保留一个占位符用于可选的 IP 限制示例
VARS[LT_ADMIN_ALLOW_CIDR]="${VARS[LT_ADMIN_ALLOW_CIDR]:-127.0.0.1/32}"
VARS[LT_ACME_EMAIL]="${VARS[LT_ACME_EMAIL]:-admin@${USER_DOMAIN}}"
VARS[LT_TUNNEL_DOMAIN]="${VARS[LT_TUNNEL_DOMAIN]:-}"

# DNS Challenge：泛域名证书的唯一签发途径。
VARS[LT_CADDY_DNS_PROVIDER]="${VARS[LT_CADDY_DNS_PROVIDER]:-}"
if [[ -z "${VARS[LT_CADDY_DNS_ARGS]:-}" ]]; then
  # 默认从环境变量取凭据：这样凭据不落进 Caddyfile，
  # 也就不进版本库、不进日志、不进任何备份。
  VARS[LT_CADDY_DNS_ARGS]='{env.LT_CADDY_DNS_CREDENTIAL}'
fi

# 配了隧道域名却没有 DNS 服务商：这不是「少配一项」，而是根本签不出证书。
# 与其产出一份 Caddy 拒绝加载（或反复重试失败）的配置，不如现在就报错。
if [[ -n "${VARS[LT_TUNNEL_DOMAIN]}" && -z "${VARS[LT_CADDY_DNS_PROVIDER]}" ]]; then
  echo "已设置 LT_TUNNEL_DOMAIN 但 LT_CADDY_DNS_PROVIDER 为空。" >&2
  echo "泛域名证书无法用 HTTP-01/TLS-ALPN-01 验证，只能用 DNS Challenge 签发。" >&2
  echo "请填写 dns 指令名（如 cloudflare，需与 Caddy 镜像里编入的插件一致），" >&2
  echo "或清空 LT_TUNNEL_DOMAIN 以关闭 HTTP/HTTPS 隧道。" >&2
  exit 1
fi

REQUIRED=(
  LT_GATEWAY_PORT LT_KCP_PORT LT_VHOST_HTTP_PORT LT_VHOST_HTTPS_PORT
  LT_FRPS_TOKEN LT_PORT_RANGE_START LT_PORT_RANGE_END LT_MAX_PORTS_PER_USER
  LT_FRPS_API_PORT LT_FRPS_API_USER LT_FRPS_API_PASSWORD
  LT_USER_PORT
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

# ---- HTTPS 隧道模式 ----
#
# edge：证书留在 Caddy，Caddy 用泛域名证书终止 TLS 后走 vhostHTTPPort；
# e2e ：证书留在本地网站，frps 在 vhostHTTPSPort 上按 SNI 透传原始 TLS 连接，
#       这个端口必须对公网放行。
#
# 放到必填项检查之后：e2e 模式下端口号是从 LT_VHOST_HTTPS_PORT 派生的，
# 那个值缺失时这里的派生结果会是一个「看起来没配 e2e」的空值，
# 而真正的问题（端口没填）已经在上面报过了。
VARS[LT_HTTPS_TUNNEL_MODE]="${VARS[LT_HTTPS_TUNNEL_MODE]:-edge}"
VARS[LT_HTTPS_E2E_PORT]=""
case "${VARS[LT_HTTPS_TUNNEL_MODE]}" in
  edge) ;;
  e2e) VARS[LT_HTTPS_E2E_PORT]="${VARS[LT_VHOST_HTTPS_PORT]}" ;;
  *)
    echo "LT_HTTPS_TUNNEL_MODE 只能是 edge 或 e2e，当前为 ${VARS[LT_HTTPS_TUNNEL_MODE]}。" >&2
    exit 1
    ;;
esac

# ---- 条件块 ----
# 模板里用 "# @if VAR" 与 "# @endif" 包住「VAR 为空时整段删除」的内容。
#
# 为什么必须整段删，而不是让它替换成空：渲染是纯文本替换，留空只会得到一份
# 「站点地址是空行」的配置，而 Caddy 会因此拒绝加载**整份** Caddyfile——
# 一个可选项没填，代价是整个反代起不来。泛域名段（LT_TUNNEL_DOMAIN 默认为空）
# 正好是这种情况，也就是「默认配置根本起不来」。
#
# 语义只有一种：变量非空则保留整段，否则连同标记行一起删掉。支持嵌套。
apply_conditionals() {
  local text="$1"
  local line var out=''
  local states='1' # 每层一个字符：1=保留 0=丢弃，末位是当前层
  while IFS= read -r line || [[ -n "${line}" ]]; do
    if [[ "${line}" =~ ^[[:space:]]*#[[:space:]]*@if[[:space:]]+([A-Za-z0-9_]+)[[:space:]]*$ ]]; then
      var="${BASH_REMATCH[1]}"
      if [[ "${states: -1}" == '1' && -n "${VARS[${var}]:-}" ]]; then
        states="${states}1"
      else
        states="${states}0"
      fi
      continue
    fi
    if [[ "${line}" =~ ^[[:space:]]*#[[:space:]]*@endif[[:space:]]*$ ]]; then
      if (( ${#states} > 1 )); then
        # 去掉末位（当前层）。用 %? 而不是 ${x:0:${#x}-1}：后者嵌套展开容易踩坑
        states="${states%?}"
      fi
      continue
    fi
    if [[ "${states: -1}" == '1' ]]; then
      out+="${line}"$'\n'
    fi
  done <<< "${text}"
  printf '%s' "${out}"
}

render() {
  local tpl="$1" out="$2"
  local text
  text="$(apply_conditionals "$(cat "${tpl}")")"
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
  1) 确保防火墙/安全组只放行 80、443 与隧道端口池（默认 20000-30000），以及网关端口 7001/TCP 与 7002/UDP
  2) 在仓库根目录执行：
       docker compose --env-file .env -f deploy/docker-compose.yml up -d --build
     （--env-file 是必须的：.env 在仓库根目录，而默认只读 compose 文件所在目录的那份）
EOF

if [[ -n "${VARS[LT_HTTPS_E2E_PORT]}" ]]; then
  echo "  3) 端到端 HTTPS 已启用（LT_HTTPS_TUNNEL_MODE=e2e）："
  echo "     · 放行 ${VARS[LT_HTTPS_E2E_PORT]}/TCP，证书由本地网站自己持有"
  echo "     · HTTPS 隧道请用 <子域>.${VARS[LT_TUNNEL_DOMAIN]}:${VARS[LT_HTTPS_E2E_PORT]} 访问"
  echo "       （443 由 Caddy 接管，返回的是平台证书，浏览器会提示不匹配）"
fi
