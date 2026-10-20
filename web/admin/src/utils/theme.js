// 主题切换：localStorage 记住选择，首次访问跟随系统偏好。
// 只切 <html> 上的 dark 类，具体颜色全部由 styles/theme.css 的变量决定，
// 组件里不要再写死颜色，否则深色模式下会出现「白底白字」。
const STORAGE_KEY = 'lt-theme'
const EVENT = 'lt-theme-change'

export function currentTheme() {
  return document.documentElement.classList.contains('dark') ? 'dark' : 'light'
}

export function applyTheme(theme) {
  const dark = theme === 'dark'
  document.documentElement.classList.toggle('dark', dark)
  // 让浏览器原生控件（滚动条、日期选择器）也跟着变
  document.documentElement.style.colorScheme = dark ? 'dark' : 'light'
  try {
    localStorage.setItem(STORAGE_KEY, dark ? 'dark' : 'light')
  } catch {
    // 隐私模式下 localStorage 可能不可用，忽略即可
  }
  window.dispatchEvent(new CustomEvent(EVENT, { detail: { theme: dark ? 'dark' : 'light' } }))
}

export function initTheme() {
  let saved = ''
  try {
    saved = localStorage.getItem(STORAGE_KEY) || ''
  } catch {
    saved = ''
  }
  const prefersDark = window.matchMedia?.('(prefers-color-scheme: dark)').matches
  applyTheme(saved === 'dark' || saved === 'light' ? saved : prefersDark ? 'dark' : 'light')
}

export function toggleTheme() {
  applyTheme(currentTheme() === 'dark' ? 'light' : 'dark')
}

// 返回取消订阅函数，组件卸载时调用。
export function onThemeChange(fn) {
  const handler = (e) => fn(e.detail?.theme || currentTheme())
  window.addEventListener(EVENT, handler)
  return () => window.removeEventListener(EVENT, handler)
}

// 读取 CSS 变量，供 ECharts 这类需要真实颜色值的地方使用。
export function cssVar(name, fallback = '') {
  const v = getComputedStyle(document.documentElement).getPropertyValue(name).trim()
  return v || fallback
}
