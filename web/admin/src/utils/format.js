export function formatBytes(bytes) {
  const b = Number(bytes || 0)
  if (!b) return '0 B'
  const units = ['B', 'KB', 'MB', 'GB', 'TB', 'PB']
  let i = 0
  let v = b
  while (v >= 1024 && i < units.length - 1) {
    v /= 1024
    i++
  }
  return `${v.toFixed(i === 0 ? 0 : 2)} ${units[i]}`
}

export function formatTime(value) {
  if (!value) return '-'
  const d = new Date(value)
  if (Number.isNaN(d.getTime())) return '-'
  const pad = (n) => String(n).padStart(2, '0')
  return `${d.getFullYear()}-${pad(d.getMonth() + 1)}-${pad(d.getDate())} ${pad(d.getHours())}:${pad(
    d.getMinutes()
  )}:${pad(d.getSeconds())}`
}

/**
 * 复制到剪贴板。
 *
 * 面板经常用 http://内网IP:7848 访问，这属于「非安全上下文」：
 * navigator.clipboard 在那种页面里是 undefined，只写 Clipboard API 的调用
 * 一定会失败（表现为「复制失败，请手动选中复制」）。所以这里必须先判断
 * 能力再兜底到 execCommand。
 */
export async function copyText(text) {
  const value = String(text ?? '')
  if (!value) return false

  if (navigator.clipboard?.writeText) {
    try {
      await navigator.clipboard.writeText(value)
      return true
    } catch {
      // 权限被拒、页面失焦或浏览器策略限制：继续走兜底
    }
  }

  const ta = document.createElement('textarea')
  ta.value = value
  ta.setAttribute('readonly', '')
  ta.style.position = 'fixed'
  ta.style.top = '-1000px'
  ta.style.opacity = '0'
  document.body.appendChild(ta)
  const prevFocus = document.activeElement
  ta.select()
  ta.setSelectionRange(0, value.length)

  let ok = false
  try {
    ok = document.execCommand('copy')
  } catch {
    ok = false
  }
  document.body.removeChild(ta)
  if (prevFocus instanceof HTMLElement) prevFocus.focus()
  return ok
}
