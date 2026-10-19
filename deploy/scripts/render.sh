#!/usr/bin/env bash
# ============================================================
#  从仓库根目录的 .env 渲染 frps.toml 与 Caddyfile。
#
#  用法（在仓库根目录执行）：
#     bash deploy/scripts/render.sh
# ============================================================
set -euo pipefail

# 渲染结果里有 token、管理密码等敏感字段：默认权限收紧到 owner-only。
# 不设的话，脚本在宽松 umask（常见 022）下会产出 0644，同机其他用户可读。
umask 077

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"

# ---- 并发锁 ----
#
# 两个 render 同时跑会交叉读写：A 把 B 刚提交的新文件当成旧文件备份、A 回滚
# 时又把 B 的成果覆盖回去。这里的动作是「备份 + 替换」，天然要求串行。
#
# 用 mkdir 而不是 flock：macOS 默认没有 flock，而渲染脚本在三种平台上都会被
# 手工执行。mkdir 是原子的，失败即说明有人在跑。
LOCK_DIR="${ROOT}/deploy/.render.lock.d"
if ! mkdir "${LOCK_DIR}" 2>/dev/null; then
  # 崩溃可能留下空目录。按 mtime 判定残留：超过 10 分钟既不可能是正常渲染
  # （它只做文本替换），也不该让运维去手工清目录。
  if [[ -n "$(find "${LOCK_DIR}" -maxdepth 0 -mmin +10 2>/dev/null)" ]]; then
    echo "清理上次异常退出留下的渲染锁：${LOCK_DIR}" >&2
    rmdir "${LOCK_DIR}" 2>/dev/null || true
  fi
  if ! mkdir "${LOCK_DIR}" 2>/dev/null; then
    echo "另一个 render 正在运行（锁：${LOCK_DIR}）。请等它结束；若是崩溃残留，10 分钟后会自动清理。" >&2
    exit 1
  fi
fi
RELEASE_LOCK=1
release_lock() {
  if [[ "${RELEASE_LOCK}" == "1" ]]; then
    rmdir "${LOCK_DIR}" 2>/dev/null || true
  fi
}

ENV_FILE="${ROOT}/.env"
FRPS_TPL="${ROOT}/deploy/frps/frps.toml.template"
FRPS_OUT="${ROOT}/deploy/frps/frps.toml"
CADDY_TPL="${ROOT}/deploy/caddy/Caddyfile.template"
CADDY_OUT="${ROOT}/deploy/caddy/Caddyfile"

# 输入文件统一走这里：只接受普通文件（符号链接允许，但必须解析到普通文件），
# 并限制大小。没有上限时，一个被替换成 /dev/zero 的 .env 会让脚本读死；
# 而 FIFO 之类会让 read 永久阻塞——两者都表现为「渲染卡住」，却查不出原因。
MAX_INPUT_BYTES=$((1024 * 1024))
require_input_file() {
  local p="$1" what="$2" size
  if [[ ! -e "${p}" ]]; then
    echo "未找到 ${what}：${p}" >&2
    return 1
  fi
  if [[ ! -f "${p}" ]]; then
    echo "${what} ${p} 不是普通文件：拒绝读取（请换成真实文件，或修正符号链接指向）" >&2
    return 1
  fi
  size=$(wc -c < "${p}" 2>/dev/null || echo 0)
  if (( size > MAX_INPUT_BYTES )); then
    echo "${what} ${p} 大小为 ${size} 字节，超过 ${MAX_INPUT_BYTES} 字节上限：拒绝读取（文件可能已损坏或被替换）" >&2
    return 1
  fi
}

require_input_file "${ENV_FILE}" ".env" || {
  echo "请先复制 .env.example 为 .env 并填写真实值。" >&2
  exit 1
}
require_input_file "${FRPS_TPL}" "frps 模板" || exit 1
require_input_file "${CADDY_TPL}" "Caddyfile 模板" || exit 1

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

split_public_url() {
  local raw="${1:-}"
  local scheme="https"
  # scheme 按小写比较，域名统一折成小写：
  #
  #   - 面板（apply.go）接受 HTTPS:// 大写写法（先 ToLower 再判断），脚本却会
  #     落到「不支持的协议」分支——同一份 .env 在面板里能保存、在脚本里炸。
  #   - 域名大小写无关（DNS 不区分），但 Go 侧的 checkDomain 只接受小写。
  #     这里折成小写，才能保证脚本渲染成功的东西面板也一定接受。
  local lower="${raw,,}"
  if [[ "${lower}" == http://* ]]; then
    scheme="http"
  elif [[ "${lower}" == https://* ]]; then
    scheme="https"
  elif [[ "${lower}" == *://* ]]; then
    echo "LT_USER_PUBLIC_URL 只支持 http 或 https。" >&2
    exit 1
  fi
  raw="${lower#http://}"
  raw="${raw#https://}"
  raw="${raw%/}"
  VARS[LT_USER_SCHEME]="${scheme}"
  VARS[LT_USER_DOMAIN]="${raw}"
}

split_public_url "${VARS[LT_USER_PUBLIC_URL]:-}"
USER_DOMAIN="${VARS[LT_USER_DOMAIN]}"

if [[ -z "${USER_DOMAIN}" ]]; then
  echo "LT_USER_PUBLIC_URL 未填写：面板需要一个对外地址。" >&2
  exit 1
fi

VARS[LT_USER_DOMAIN]="${USER_DOMAIN}"
if [[ "${VARS[LT_USER_SCHEME]}" == "https" ]]; then
  VARS[LT_HSTS_ON]="1"
else
  VARS[LT_HSTS_ON]=""
  echo "提示：LT_USER_PUBLIC_URL 使用 HTTP，Caddy 不申请证书，登录令牌与 API Key 将明文传输。" >&2
fi
# 管理后台与用户控制台共用域名，仅保留一个占位符用于可选的 IP 限制示例
VARS[LT_ADMIN_ALLOW_CIDR]="${VARS[LT_ADMIN_ALLOW_CIDR]:-127.0.0.1/32}"
VARS[LT_ACME_EMAIL]="${VARS[LT_ACME_EMAIL]:-admin@${USER_DOMAIN}}"
VARS[LT_TUNNEL_DOMAIN]="${VARS[LT_TUNNEL_DOMAIN]:-}"
# 与面板保持一致：域名折成小写（DNS 不区分大小写，而 Go 侧只接受小写）。
VARS[LT_TUNNEL_DOMAIN]="${VARS[LT_TUNNEL_DOMAIN],,}"

# 域名规则必须与面板（server/internal/service/tlsconfig.go 的 checkDomain）
# 一致，否则会出现「脚本能渲染、面板拒绝保存」或相反的分叉：
#   - 只填裸域名，不带 scheme、路径或 *；
#   - 至少两段（IPv4 天然满足）；
#   - 总长 ≤253，单个标签 1-63 个字符；
#   - 字符集 [a-z0-9-]，标签不以 - 开头或结尾。
#
# 纯 IP 也走这里：四段数字标签同样满足上述规则。
check_domain() {
  local name="$1" d="$2"
  [[ -z "${d}" ]] && return 0
  # DNS 不区分大小写，但 Go 侧的 checkDomain 只接受小写。这里先折成小写，
  # 三种实现（Bash/PowerShell/Go）才可能对「同一个值是否合法」给出一致结论。
  d="${d,,}"
  # 控制字符一律拒绝：原来只挡空格与制表符，CR/FF/VT 会顺着模板进到
  # Caddyfile 与 frps.toml，产出一份「看起来正常、加载时莫名失败」的配置。
  if [[ "${d}" == *[[:cntrl:]]* ]]; then
    echo "${name} 含有控制字符（换行/回车等），请检查 .env 里的值。" >&2
    exit 1
  fi
  if [[ "${d}" == *" "* || "${d}" == *$'\t'* || "${d}" == */* || "${d}" == *\\* || "${d}" == *"*"* ]]; then
    echo "${name}=${d} 含有非法字符（只填裸域名，不带 scheme、路径或 *）。" >&2
    exit 1
  fi
  if (( ${#d} > 253 )); then
    echo "${name}=${d} 超过 253 个字符。" >&2
    exit 1
  fi
  local IFS='.'
  # shellcheck disable=SC2206
  local labels=(${d})
  if (( ${#labels[@]} < 2 )); then
    echo "${name}=${d} 不是完整域名（至少需要两段，如 panel.example.com）。" >&2
    exit 1
  fi
  local l
  for l in "${labels[@]}"; do
    if [[ -z "${l}" ]]; then
      echo "${name}=${d} 存在空的域名段。" >&2
      exit 1
    fi
    if (( ${#l} > 63 )); then
      echo "${name}=${d} 的域名段 ${l} 超过 63 个字符。" >&2
      exit 1
    fi
    if [[ "${l}" == -* || "${l}" == *- ]]; then
      echo "${name}=${d} 的域名段 ${l} 不能以 - 开头或结尾。" >&2
      exit 1
    fi
    if [[ ! "${l}" =~ ^[a-z0-9-]+$ ]]; then
      echo "${name}=${d} 的域名段 ${l} 只能包含小写字母、数字与 -。" >&2
      exit 1
    fi
  done
}

check_domain LT_USER_DOMAIN "${USER_DOMAIN}"
check_domain LT_TUNNEL_DOMAIN "${VARS[LT_TUNNEL_DOMAIN]}"
if [[ -n "${VARS[LT_TUNNEL_DOMAIN]}" && "${VARS[LT_TUNNEL_DOMAIN]}" == "${USER_DOMAIN}" ]]; then
  echo "LT_TUNNEL_DOMAIN 不能与面板域名相同：泛域名证书会覆盖面板自身的 *.域名。" >&2
  exit 1
fi

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

# 数值校验必须在**任何算术展开之前**跑完。
#
# 原来端口池的两个值直接进 (( )) 比较（`port_num >= ${VARS[LT_PORT_RANGE_START]}`），
# 而 bash 的算术展开会把未过滤的字符串当变量名/表达式求值：一个写成
# "15000 着" 或 "1+1" 的值，要么静默算错、要么让整段比较结果失真，
# 端口冲突检查随之失效——而它守的是「vhost 端口不要撞上隧道端口池」。
require_port() {
  local name="$1" val="$2" max="$3"
  if [[ -z "${val}" ]]; then
    return 0
  fi
  if [[ ! "${val}" =~ ^[0-9]{1,5}$ ]]; then
    echo "${name}=${val} 不是十进制整数。" >&2
    exit 1
  fi
  local n=$((10#${val}))
  if (( n < 1 || n > max )); then
    echo "${name}=${val} 不在 1-${max} 范围内。" >&2
    exit 1
  fi
}

for k in LT_GATEWAY_PORT LT_KCP_PORT LT_VHOST_HTTP_PORT LT_VHOST_HTTPS_PORT \
  LT_FRPS_API_PORT LT_USER_PORT LT_PORT_RANGE_START LT_PORT_RANGE_END; do
  require_port "${k}" "${VARS[$k]:-}" 65535
done
# 单用户端口数不是端口号，但同样会进模板并被 frps 解析：非数字会让 frps
# 启动失败，而失败发生在容器重建之后。
require_port LT_MAX_PORTS_PER_USER "${VARS[LT_MAX_PORTS_PER_USER]:-}" 65535
if (( ${VARS[LT_PORT_RANGE_START]:-0} >= ${VARS[LT_PORT_RANGE_END]:-0} )); then
  echo "LT_PORT_RANGE_START 必须小于 LT_PORT_RANGE_END。" >&2
  exit 1
fi

for k in "${!VARS[@]}"; do
  if [[ "${VARS[$k]}" == CHANGE_ME* ]]; then
    echo "配置项 ${k} 仍是占位符，请改为真实值。" >&2
    exit 1
  fi
done

# vhost 端口由 frps 直接监听在所有网卡上（proxyBindAddr 同时用于隧道端口池，
# 不能收窄到回环），因此它不能与任何公网入口重合，否则 Caddy 与本机转发会
# 互相抢占，或把隧道入口暴露到本不该开放的端口上。
check_vhost_port() {
  local name="$1" port="$2" other="$3"
  [[ -z "${port}" ]] && return 0
  if ! [[ "${port}" =~ ^[0-9]+$ ]]; then
    echo "${name}=${port} 不是十进制端口号。" >&2
    exit 1
  fi
  local port_num=$((10#${port}))
  if (( port_num < 1 || port_num > 65535 )); then
    echo "${name}=${port} 不在 1-65535 范围内。" >&2
    exit 1
  fi
  # 所有实际会监听的本机端口：统一转为十进制整数比较。
  local reserved=(80 443 "${VARS[LT_GATEWAY_PORT]}" "${VARS[LT_KCP_PORT]}"
    "${VARS[LT_USER_PORT]}" "${VARS[LT_FRPS_API_PORT]}" "${other}")
  local p p_num
  for p in "${reserved[@]}"; do
    if [[ -n "${p}" && "${p}" =~ ^[0-9]+$ ]]; then
      p_num=$((10#${p}))
      if (( p_num == port_num )); then
        echo "${name}=${port} 与另一个监听端口冲突，请换一个端口。" >&2
        exit 1
      fi
    fi
  done
  if (( port_num >= ${VARS[LT_PORT_RANGE_START]:-0} && port_num <= ${VARS[LT_PORT_RANGE_END]:-0} )); then
    echo "${name}=${port} 落在隧道端口池 ${VARS[LT_PORT_RANGE_START]}-${VARS[LT_PORT_RANGE_END]} 内，请换一个池外端口。" >&2
    exit 1
  fi
}

check_vhost_port LT_VHOST_HTTP_PORT "${VARS[LT_VHOST_HTTP_PORT]:-}" "${VARS[LT_VHOST_HTTPS_PORT]:-}"
check_vhost_port LT_VHOST_HTTPS_PORT "${VARS[LT_VHOST_HTTPS_PORT]:-}" "${VARS[LT_VHOST_HTTP_PORT]:-}"

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

# 先渲染到同目录的临时文件，等两份都成功后再统一 rename。
#
# 直接覆盖输出的话，第二份渲染失败（模板写错、占位符没填）会留下
# 「frps 新 / Caddy 旧」的混合状态，容器启动时两边对不上，而现场看起来
# 像是渲染成功了。临时文件与正式文件同目录，rename 才是原子的。
PENDING_TMP=()
PENDING_OUT=()

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

  local tmp
  tmp="$(dirname "${out}")/.$(basename "${out}").tmp.$$"
  printf '%s' "${text}" > "${tmp}"
  chmod 600 "${tmp}"
  PENDING_TMP+=("${tmp}")
  PENDING_OUT+=("${out}")
}

# 任何一步失败都清掉临时文件：set -e 会直接退出，不能让半成品留在部署目录里。
cleanup_tmp() {
  local i
  for ((i=0; i<${#PENDING_TMP[@]}; i++)); do
    rm -f "${PENDING_TMP[i]}" 2>/dev/null || true
  done
}
trap 'cleanup_tmp; release_lock' EXIT

render "${FRPS_TPL}" "${FRPS_OUT}"
render "${CADDY_TPL}" "${CADDY_OUT}"

# ---- 提交：两个文件要么一起换新，要么一起回滚 ----
#
# 只把「写临时文件 + rename」做到位还不够：rename 本身是原子的，但**两次**
# rename 不是一次事务。第二次 mv 失败（磁盘满、目标被占用、目录权限变了）
# 时，第一次已经生效——现场是「frps 新 / Caddy 旧」，而脚本退出码非零，
# 运维多半只看最后一行错误就重跑了，这份混合配置会一直留在磁盘上。
#
# 所以提交前先把现有目标备份下来，任一文件提交失败就把已提交的全部还原。
# 备份与目标同目录，还原同样是原子 rename。
BACKUP_TMP=()
BACKUP_OUT=()

backup_targets() {
  local i out bak
  for ((i=0; i<${#PENDING_OUT[@]}; i++)); do
    out="${PENDING_OUT[i]}"
    if [[ -e "${out}" ]]; then
      bak="$(dirname "${out}")/.$(basename "${out}").bak.$$"
      if ! cp -p "${out}" "${bak}"; then
        echo "备份 ${out} 失败，未做任何修改" >&2
        return 1
      fi
      BACKUP_TMP+=("${bak}")
    else
      # 首次运行：没有旧文件可备份，回滚时直接删除新文件。
      BACKUP_TMP+=("")
    fi
    BACKUP_OUT+=("${out}")
  done
  return 0
}

rollback_commit() {
  local i out bak
  for ((i=0; i<${#BACKUP_OUT[@]}; i++)); do
    out="${BACKUP_OUT[i]}"
    bak="${BACKUP_TMP[i]}"
    if [[ -n "${bak}" && -e "${bak}" ]]; then
      if ! mv -f "${bak}" "${out}"; then
        # 还原也失败时绝不能删备份：那是唯一还能恢复现场的东西。
        echo "回滚 ${out} 失败：原内容已保留在 ${bak}，请手工恢复" >&2
      fi
    elif [[ -z "${bak}" ]]; then
      rm -f "${out}"
    fi
  done
}

commit_all() {
  local i out
  for ((i=0; i<${#PENDING_OUT[@]}; i++)); do
    out="${PENDING_OUT[i]}"
    # 先落权限再 rename：目标一旦出现就应该是 0600，而不是先 0644 再收紧
    # （中间那一刻同机其他用户可以读到 token）。
    if ! mv -f "${PENDING_TMP[i]}" "${out}"; then
      echo "写入 ${out} 失败，回滚已提交的配置" >&2
      rollback_commit
      return 1
    fi
    if ! chmod 600 "${out}"; then
      echo "设置 ${out} 权限失败，回滚已提交的配置" >&2
      rollback_commit
      return 1
    fi
    echo "已生成 ${out}"
  done
  return 0
}

if ! backup_targets; then
  # 还没提交任何文件，备份纯属冗余副本：清掉，别在部署目录里留 .bak。
  for bak in "${BACKUP_TMP[@]}"; do
    [[ -n "${bak}" ]] && rm -f "${bak}"
  done
  exit 1
fi
commit_all || exit 1

# 成功提交后才丢弃备份：失败路径上的备份要么已经用于还原，要么是手工
# 恢复的唯一线索。
for bak in "${BACKUP_TMP[@]}"; do
  [[ -n "${bak}" ]] && rm -f "${bak}"
done

cat <<'EOF'

渲染完成。接下来：
  1) 确保防火墙/安全组放行 80 与隧道端口池（默认 20000-30000），以及网关端口 7001/TCP 与 7002/UDP
  2) 在仓库根目录执行：
       docker compose --env-file .env -f deploy/docker-compose.yml up -d --build
     （--env-file 是必须的：.env 在仓库根目录，而默认只读 compose 文件所在目录的那份）
EOF

if [[ "${VARS[LT_USER_SCHEME]}" == "https" ]]; then
  echo "  3) 控制台地址：https://${VARS[LT_USER_DOMAIN]}/"
else
  echo "  3) 控制台地址：http://${VARS[LT_USER_DOMAIN]}/（明文模式，未申请证书）"
fi

if [[ -n "${VARS[LT_HTTPS_E2E_PORT]}" ]]; then
  echo "  4) 端到端 HTTPS 已启用（LT_HTTPS_TUNNEL_MODE=e2e）："
  echo "     · 放行 ${VARS[LT_HTTPS_E2E_PORT]}/TCP，证书由本地网站自己持有"
  echo "     · HTTPS 隧道请用 <子域>.${VARS[LT_TUNNEL_DOMAIN]}:${VARS[LT_HTTPS_E2E_PORT]} 访问"
  echo "       （443 由 Caddy 接管，返回的是平台证书，浏览器会提示不匹配）"
fi
