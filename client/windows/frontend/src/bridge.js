/**
 * Wails 运行时桥接层。
 *
 * 直接使用 Wails 注入的全局对象，避免依赖代码生成的 wailsjs 目录，
 * 这样前端可以独立于 Go 侧进行开发与构建。
 */

const isWails = typeof window !== 'undefined' && !!window.go?.main?.App

const emptyState = {
  server_url: '',
  logged_in: false,
  username: '',
  gateway_host: '',
  gateway_port: 0,
  tunnel_domain: '',
  tunnels: [],
  traffic_used: 0,
  traffic_quota: 0,
  exceeded: false,
  running: false,
  frpc_found: false,
  frpc_path: '',
  config_path: '',
  auto_start: false
}

/** 浏览器内预览时使用的假实现，方便纯前端调试样式。 */
const mock = {
  GetState: async () => emptyState,
  Login: async () => {
    throw new Error('当前为浏览器预览模式，请在桌面客户端中登录')
  },
  Logout: async () => emptyState,
  Refresh: async () => emptyState,
  StartClient: async () => {},
  StopClient: async () => {},
  GetLogs: async () => [],
  ClearLogs: async () => {},
  SetAutoStart: async () => {},
  OpenDataDir: async () => ''
}

const go = isWails ? window.go.main.App : mock

export const api = {
  getState: () => go.GetState(),
  login: (server, username, password) => go.Login(server, username, password),
  logout: () => go.Logout(),
  refresh: () => go.Refresh(),
  start: () => go.StartClient(),
  stop: () => go.StopClient(),
  logs: () => go.GetLogs(),
  clearLogs: () => go.ClearLogs(),
  setAutoStart: (v) => go.SetAutoStart(v),
  openDataDir: () => go.OpenDataDir()
}

/** 订阅 Wails 事件；非桌面环境下静默忽略。 */
export function onEvent(name, handler) {
  if (typeof window === 'undefined' || !window.runtime?.EventsOn) {
    return () => {}
  }
  window.runtime.EventsOn(name, handler)
  return () => {
    window.runtime.EventsOff?.(name)
  }
}

export const isDesktop = isWails
