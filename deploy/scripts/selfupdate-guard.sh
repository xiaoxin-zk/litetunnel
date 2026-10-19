#!/bin/sh
# 面板在线更新的启动看门狗。
# 更新成功时会写 update-pending.json，新进程稳定运行 30 秒后自行删除它。
# 这个脚本在每次启动前执行：标记还在且已超过 45 秒，说明上一次启动没撑过去，
# 就把 .old 换回来，避免 systemd 在坏版本上无限重启。
set -u

DATA_DIR="${LT_DATA_DIR:-/var/lib/litetunnel}"
PANEL_BIN="${LT_PANEL_BIN:-/opt/litetunnel/litetunnel-panel}"
PENDING="$DATA_DIR/update-pending.json"
BACKUP="$PANEL_BIN.old"

[ -f "$PENDING" ] || exit 0

if [ ! -f "$BACKUP" ]; then
  rm -f "$PENDING"
  exit 0
fi

mtime=$(stat -c %Y "$PENDING" 2>/dev/null || date -r "$PENDING" +%s 2>/dev/null || echo 0)
now=$(date +%s)
age=$((now - mtime))

# 刚更新的第一次启动：留给新进程 45 秒去自证稳定。
if [ "$age" -lt 45 ]; then
  exit 0
fi

echo "[selfupdate] 上次更新启动未确认（已过 ${age}s），回滚到上一版本" >&2
if mv -f "$BACKUP" "$PANEL_BIN"; then
  rm -f "$PENDING"
  echo "[selfupdate] 回滚完成，请检查新版本日志" >&2
fi
exit 0
