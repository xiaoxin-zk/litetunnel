#!/usr/bin/env bash
# ============================================================
#  frp 版本一致性检查。
#
#  frp 版本同时出现在三个地方，而它们必须一致：
#    - deploy/docker-compose.yml         （实际运行的 frps 镜像）
#    - deploy/systemd/lt-config.env.example（非容器部署的 LT_CFG_FRPS_IMAGE）
#    - server/cmd/lt-config/main.go      （校验用的默认镜像）
#
#  不一致的后果不是「起不来」，而是**校验通过但运行时字段不支持**：
#  lt-config 拿 v0.71.0 校验一份配置，实际跑的却是 v0.60.0，于是容器起来
#  之后 frps 才在日志里报 unknown field——那时配置已经写入、服务已经重建。
#
#  frp-version.txt 是唯一来源；这里只负责「核对」，不负责改写。
#  用法：bash scripts/check-pins.sh
# ============================================================
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "${ROOT}"

WANT="$(tr -d '[:space:]' < frp-version.txt)"
if [[ -z "${WANT}" ]]; then
  echo "frp-version.txt 为空" >&2
  exit 1
fi

FAILS=0

# extract_versions FILE PATTERN：输出文件里所有匹配的版本号（去重、排序）。
extract_versions() {
  local file="$1" pattern="$2"
  grep -oE "${pattern}" "${file}" 2>/dev/null | sed -E 's/.*:v//' | sort -u
}

check_file() {
  local file="$1" pattern="$2" label="$3"
  local found
  found="$(extract_versions "${file}" "${pattern}")"
  if [[ -z "${found}" ]]; then
    echo "FAIL ${label}: ${file} 里找不到 frp 版本引用（期望 v${WANT}）" >&2
    FAILS=$((FAILS + 1))
    return
  fi
  while IFS= read -r v; do
    if [[ "${v}" != "${WANT}" ]]; then
      echo "FAIL ${label}: ${file} 里的版本是 v${v}，frp-version.txt 是 v${WANT}" >&2
      FAILS=$((FAILS + 1))
    fi
  done <<< "${found}"
}

check_file deploy/docker-compose.yml 'fatedier/frps:v[0-9]+\.[0-9]+\.[0-9]+' 'compose 镜像'
check_file deploy/systemd/lt-config.env.example 'fatedier/frps:v[0-9]+\.[0-9]+\.[0-9]+' 'systemd 环境示例'
check_file server/cmd/lt-config/main.go 'fatedier/frps:v[0-9]+\.[0-9]+\.[0-9]+' 'lt-config 默认镜像'

# 发布流程不能自己写死一个版本号：那样 tag 发出去之后才发现与镜像不一致。
if grep -qE '^\s*FRP_VERSION:' .github/workflows/release.yml; then
  echo "FAIL 发布流程: release.yml 仍写死 FRP_VERSION，应从 frp-version.txt 读取" >&2
  FAILS=$((FAILS + 1))
fi

# ---- 端口池三方一致 ----
#
# 端口池同时出现在三处，而且**三处都必须是同一个范围**：
#   - .env.example             —— 运维照着填的值
#   - config.Default()         —— 没配环境变量时面板自己用的值
#   - lt-fw.env.example        —— 宿主机 helper 允许放行的范围（安全边界）
#
# 不一致的症状不是报错，而是「隧道建起来了但端口打不开」：面板分配了
# helper 不允许的端口，防火墙规则永远下不去。这类问题极难归因，因为两个
# 组件各自都认为自己是对的。
pool_value() {
  grep -oE "$2" "$1" 2>/dev/null | head -n1 | grep -oE '[0-9]+$'
}
panel_start="$(pool_value .env.example '^LT_PORT_RANGE_START=[0-9]+')"
panel_end="$(pool_value .env.example '^LT_PORT_RANGE_END=[0-9]+')"
code_start="$(grep -oE 'PortRangeStart: +envInt\("LT_PORT_RANGE_START", [0-9]+\)' server/internal/config/config.go | grep -oE '[0-9]+\)$' | tr -d ')')"
code_end="$(grep -oE 'PortRangeEnd: +envInt\("LT_PORT_RANGE_END", [0-9]+\)' server/internal/config/config.go | grep -oE '[0-9]+\)$' | tr -d ')')"
fw_start="$(pool_value deploy/systemd/lt-fw.env.example '^LT_FW_POOL_START=[0-9]+')"
fw_end="$(pool_value deploy/systemd/lt-fw.env.example '^LT_FW_POOL_END=[0-9]+')"

for pair in "start:${panel_start}:${code_start}:${fw_start}" "end:${panel_end}:${code_end}:${fw_end}"; do
  IFS=':' read -r which a b c <<< "${pair}"
  if [[ -z "${a}" || -z "${b}" || -z "${c}" ]]; then
    echo "FAIL 端口池: 取不到 ${which} 的三个来源（.env.example=${a:-?} config=${b:-?} lt-fw=${c:-?}）" >&2
    FAILS=$((FAILS + 1))
    continue
  fi
  if [[ "${a}" != "${b}" || "${a}" != "${c}" ]]; then
    echo "FAIL 端口池 ${which}: .env.example=${a} / config 默认=${b} / lt-fw=${c} 不一致" >&2
    FAILS=$((FAILS + 1))
  fi
done

if (( FAILS > 0 )); then
  echo >&2
  echo "frp 版本不一致：改版本请先改 frp-version.txt，再同步上面这些引用。" >&2
  exit 1
fi

echo "frp 版本一致：v${WANT}"
