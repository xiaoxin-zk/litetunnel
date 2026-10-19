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

if (( FAILS > 0 )); then
  echo >&2
  echo "frp 版本不一致：改版本请先改 frp-version.txt，再同步上面这些引用。" >&2
  exit 1
fi

echo "frp 版本一致：v${WANT}"
