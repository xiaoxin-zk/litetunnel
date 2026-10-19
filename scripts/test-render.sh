#!/usr/bin/env bash
# ============================================================
#  deploy/scripts/render.sh 的回归夹具。
#
#  为什么要有它：这个脚本产出的是「带 token 的配置 + 0600 权限 + 两文件
#  原子提交」这三件容易被后续改动悄悄破坏的东西，而它们都不在 Go 测试的
#  覆盖范围里。脚本改坏的症状通常是「某次部署后 frps 连不上」或「两个配置
#  一新一旧」，等发现时现场早没了。
#
#  用法：bash scripts/test-render.sh
#  依赖：bash 4+、coreutils（Linux 与 macOS runner 均有）。
# ============================================================
set -uo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
WORK="$(mktemp -d)"
trap 'rm -rf "${WORK}"' EXIT

FAILS=0
CASE=""

fail() {
  echo "  FAIL: $*" >&2
  FAILS=$((FAILS + 1))
}

ok() { echo "  ok: $*"; }

# 每个用例一个独立目录，避免互相影响。
new_fixture() {
  local d="${WORK}/$1"
  mkdir -p "${d}/deploy/scripts" "${d}/deploy/frps" "${d}/deploy/caddy"
  cp "${REPO_ROOT}/deploy/scripts/render.sh" "${d}/deploy/scripts/render.sh"
  cp "${REPO_ROOT}/deploy/frps/frps.toml.template" "${d}/deploy/frps/"
  cp "${REPO_ROOT}/deploy/caddy/Caddyfile.template" "${d}/deploy/caddy/"
  # 用真实的 .env.example 做基底：以后新增必填变量时，夹具会自动跟上，
  # 不需要在这里再维护一份变量清单。
  sed -E \
    -e 's/CHANGE_ME_[A-Za-z0-9_]*/fixture_secret_value/g' \
    -e 's#^LT_USER_PUBLIC_URL=.*#LT_USER_PUBLIC_URL=https://panel.example.com#' \
    -e 's#^LT_GATEWAY_HOST=.*#LT_GATEWAY_HOST=gw.example.com#' \
    -e 's#^LT_ACME_EMAIL=.*#LT_ACME_EMAIL=ops@example.com#' \
    -e 's#^LT_DB_DSN=.*#LT_DB_DSN=./data/litetunnel.db#' \
    "${REPO_ROOT}/.env.example" > "${d}/.env"
  printf '%s' "${d}"
}

run_render() {
  local d="$1"
  ( cd "${d}" && bash deploy/scripts/render.sh >"${d}/render.log" 2>&1 )
}

mode_of() { stat -c '%a' "$1" 2>/dev/null || stat -f '%Lp' "$1"; }

# ------------------------------------------------------------
CASE="happy path（.env 为 CRLF，与仓库里的 .env.example 一致）"
{
  d="$(new_fixture crlf)"
  if run_render "${d}"; then
    ok "渲染成功"
  else
    fail "渲染失败：$(tail -3 "${d}/render.log")"
  fi
  [[ -f "${d}/deploy/frps/frps.toml" ]] && ok "生成 frps.toml" || fail "缺少 frps.toml"
  [[ -f "${d}/deploy/caddy/Caddyfile" ]] && ok "生成 Caddyfile" || fail "缺少 Caddyfile"
  if grep -q 'fixture_secret_value' "${d}/deploy/frps/frps.toml" 2>/dev/null; then
    ok "token 已渲染"
  else
    fail "frps.toml 里没有渲染后的 token"
  fi
  if [[ -f "${d}/deploy/frps/frps.toml" && "$(mode_of "${d}/deploy/frps/frps.toml")" != "600" ]]; then
    fail "frps.toml 权限是 $(mode_of "${d}/deploy/frps/frps.toml")，应为 600"
  else
    ok "frps.toml 权限 600"
  fi
  # 不能留下临时文件或备份：它们的权限同样是 600，但留在部署目录里会被
  # 下一次 git status / 备份脚本收进去。
  leftovers="$(find "${d}/deploy" -name '.*tmp*' -o -name '.*bak*' | wc -l)"
  [[ "${leftovers}" -eq 0 ]] && ok "无临时文件/备份残留" || fail "残留 ${leftovers} 个临时文件"
}

# ------------------------------------------------------------
CASE="LF 换行的 .env（非 Windows 编辑器保存）"
{
  d="$(new_fixture lf)"
  sed -i 's/\r$//' "${d}/.env"
  if run_render "${d}"; then
    ok "渲染成功"
    grep -q 'fixture_secret_value' "${d}/deploy/frps/frps.toml" && ok "token 已渲染" || fail "token 未渲染"
  else
    fail "渲染失败：$(tail -3 "${d}/render.log")"
  fi
}

# ------------------------------------------------------------
CASE="模板有未替换占位符 → 失败且不改动已有配置"
{
  d="$(new_fixture unresolved)"
  run_render "${d}" || true
  before_frps="$(cksum < "${d}/deploy/frps/frps.toml" 2>/dev/null || echo none)"
  # 只在 Caddyfile 模板里加一个不存在的占位符：frps.toml 本来能渲染成功，
  # 用来看「一份成功、一份失败」时是否会留下半更新。
  printf '\n# ${NOT_DEFINED_ANYWHERE}\n' >> "${d}/deploy/caddy/Caddyfile.template"
  if run_render "${d}"; then
    fail "应当失败却成功了"
  else
    ok "按预期失败"
  fi
  grep -q '未替换' "${d}/render.log" && ok "错误信息可读" || fail "错误信息里没有说明未替换占位符"
  after_frps="$(cksum < "${d}/deploy/frps/frps.toml" 2>/dev/null || echo none)"
  [[ "${before_frps}" == "${after_frps}" ]] && ok "frps.toml 未被改动" || fail "frps.toml 被半更新"
  leftovers="$(find "${d}/deploy" -name '.*tmp*' -o -name '.*bak*' | wc -l)"
  [[ "${leftovers}" -eq 0 ]] && ok "无临时文件残留" || fail "残留 ${leftovers} 个临时文件"
}

# ------------------------------------------------------------
CASE="第二个文件提交失败 → 第一个文件回滚"
{
  d="$(new_fixture rollback)"
  run_render "${d}" || true
  before_frps="$(cksum < "${d}/deploy/frps/frps.toml" 2>/dev/null || echo none)"

  # 用一个 chmod 垫片让 Caddyfile 的提交步骤失败：脚本先 mv 再 chmod，
  # 于是「frps 已换新、Caddy 换权限失败」正好复现两个 rename 之间失败
  # 的现场。垫片只拦正式目标，不拦 .tmp. 中间文件，否则渲染阶段就会失败。
  shim="${WORK}/shim"
  mkdir -p "${shim}"
  cat > "${shim}/chmod" <<'SHIM'
#!/usr/bin/env bash
target="${@: -1}"
if [[ "${target}" == *Caddyfile && "${target}" != *.tmp.* ]]; then
  echo "shim: 模拟 chmod 失败" >&2
  exit 1
fi
exec /bin/chmod "$@"
SHIM
  chmod +x "${shim}/chmod"

  if ( cd "${d}" && PATH="${shim}:${PATH}" bash deploy/scripts/render.sh >"${d}/render.log" 2>&1 ); then
    fail "应当失败却成功了"
  else
    ok "按预期失败"
  fi
  after_frps="$(cksum < "${d}/deploy/frps/frps.toml" 2>/dev/null || echo none)"
  [[ "${before_frps}" == "${after_frps}" ]] && ok "frps.toml 已回滚到旧内容" || fail "frps.toml 停在半更新状态"
  leftovers="$(find "${d}/deploy" -name '.*tmp*' -o -name '.*bak*' | wc -l)"
  [[ "${leftovers}" -eq 0 ]] && ok "无临时文件/备份残留" || fail "残留 ${leftovers} 个临时文件"
}

# ------------------------------------------------------------
CASE="dotenv 引号与转义：多参数 DNS 配置不能带引号进模板"
{
  d="$(new_fixture dotenv)"
  # 双引号值里的空格必须原样保留，$$ 必须还原成字面量 $。failure 的形态很隐蔽：
  # 带引号的值会原样进 Caddyfile，Caddy 把它当成**一个**参数，dns 指令收到
  # 错误的参数个数后拒绝加载，而渲染脚本会说「成功」。
  sed -i \
    -e 's#^LT_TUNNEL_DOMAIN=.*#LT_TUNNEL_DOMAIN=tunnel.example.com#' \
    -e 's#^LT_CADDY_DNS_PROVIDER=.*#LT_CADDY_DNS_PROVIDER=cloudflare#' \
    -e 's#^LT_CADDY_DNS_ARGS=.*#LT_CADDY_DNS_ARGS="{env.CF_A} {env.CF_B} prefix$$suffix"#' \
    "${d}/.env"
  if run_render "${d}"; then ok "渲染成功"; else fail "渲染失败：$(tail -3 "${d}/render.log")"; fi
  cf="${d}/deploy/caddy/Caddyfile"
  if grep -qF 'dns cloudflare {env.CF_A} {env.CF_B} prefix$suffix' "${cf}" 2>/dev/null; then
    ok "引号与 \$\$ 按 dotenv 语义解析"
  else
    fail "DNS 参数渲染不符合 dotenv 语义：$(grep -n 'dns ' "${cf}" 2>/dev/null || echo 未找到 dns 行)"
  fi
}

# ------------------------------------------------------------
CASE="端口池非数字输入必须被拒绝"
{
  d="$(new_fixture badport)"
  # 原来这个值直接进 (( )) 做区间比较：bash 把非法内容当算术表达式求值，
  # 端口冲突检查要么静默失效、要么给出误导性的结果。
  sed -i 's#^LT_PORT_RANGE_START=.*#LT_PORT_RANGE_START=15000abc#' "${d}/.env"
  if run_render "${d}"; then
    fail "非数字端口应当被拒绝"
  else
    ok "按预期拒绝"
  fi
  grep -q '不是十进制整数' "${d}/render.log" && ok "错误信息明确" || fail "错误信息未说明是数值问题"
  [[ ! -f "${d}/deploy/frps/frps.toml" ]] && ok "未产出任何配置文件" || fail "校验失败仍写出了配置"
}

# ------------------------------------------------------------
CASE="并发锁：已有锁时拒绝执行，且不误删活锁"
{
  d="$(new_fixture lock)"
  mkdir -p "${d}/deploy/.render.lock.d"
  if run_render "${d}"; then
    fail "已有锁时应当拒绝执行"
  else
    ok "按预期拒绝"
  fi
  grep -q '正在运行' "${d}/render.log" && ok "提示可读" || fail "缺少并发提示"
  [[ -d "${d}/deploy/.render.lock.d" ]] && ok "未误删仍在使用的锁" || fail "锁被误删"
  rmdir "${d}/deploy/.render.lock.d"
}

# ------------------------------------------------------------
CASE="输入文件策略：非普通文件与超限文件"
{
  d="$(new_fixture inputs)"
  mv "${d}/.env" "${d}/.env.real"
  if mkfifo "${d}/.env" 2>/dev/null; then
    if run_render "${d}"; then
      fail "FIFO 作 .env 应当被拒绝"
    else
      grep -q '不是普通文件' "${d}/render.log" && ok "拒绝 FIFO" || fail "错误信息不明确"
    fi
    rm -f "${d}/.env"
  else
    echo "  skip: 当前文件系统不支持 FIFO"
  fi

  # 2 MiB 的 .env：超过 1 MiB 上限，必须直接拒绝而不是读进内存。
  { cat "${d}/.env.real"; head -c $((2 * 1024 * 1024)) /dev/zero | tr '\0' '#'; } > "${d}/.env"
  if run_render "${d}"; then
    fail "超限 .env 应当被拒绝"
  else
    grep -q '上限' "${d}/render.log" && ok "拒绝超限文件" || fail "错误信息里没有提到上限"
  fi
}

# ------------------------------------------------------------
# 面板对外地址带端口：直连部署写成 http://203.0.113.10:7848 是常态，而面板的
# 「面板域名」默认值就是从这个地址派生的（端口保留）。脚本若把冒号判成非法，
# 就会出现「面板保存通过、渲染直接失败」的分叉。
CASE="面板对外地址带端口（host:port）"
{
  d="$(new_fixture port)"
  sed -E -i.bak 's#^LT_USER_PUBLIC_URL=.*#LT_USER_PUBLIC_URL=http://203.0.113.10:7848#' "${d}/.env"
  if run_render "${d}"; then
    ok "渲染成功"
  else
    fail "带端口的对外地址被拒绝：$(tail -3 "${d}/render.log")"
  fi
  if grep -q 'http://203.0.113.10:7848' "${d}/deploy/caddy/Caddyfile" 2>/dev/null; then
    ok "Caddyfile 站点地址保留端口"
  else
    fail "Caddyfile 没有带上端口：$(grep -m1 '^http' "${d}/deploy/caddy/Caddyfile" 2>/dev/null)"
  fi
}

# 端口写错必须仍然被拒绝，不能因为「放宽了端口」把整个域名校验一起废掉。
CASE="面板对外地址端口非法"
{
  d="$(new_fixture badport)"
  sed -E -i.bak 's#^LT_USER_PUBLIC_URL=.*#LT_USER_PUBLIC_URL=http://panel.example.com:99999#' "${d}/.env"
  if run_render "${d}"; then
    fail "端口 99999 应当被拒绝"
  else
    grep -q '端口' "${d}/render.log" && ok "拒绝非法端口" || fail "错误信息里没有提到端口"
  fi
}

echo
if (( FAILS > 0 )); then
  echo "render.sh 夹具失败：${FAILS} 项" >&2
  exit 1
fi
echo "render.sh 夹具全部通过"
