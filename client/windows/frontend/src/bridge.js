/**
 * Wails 运行时桥接层。
 *
 * 直接使用 Wails 注入的全局对象，避免依赖代码生成的 wailsjs 目录，
 * 这样前端可以独立于 Go 侧进行开发与构建。
 */

const isWails = typeof window !== 'undefined' && !!window.go?.main?.App

const emptyState = {
  server_url: '',
  // server_fixed：地址由构建注入，界面不提供修改入口
  server_fixed: false,
  // needs_server_url：构建未注入地址，需要手填（仅本地调试构建）
  needs_server_url: false,
  logged_in: false,
  username: '',
  api_key_mask: '',
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
const mockConnectedState = {
  ...emptyState,
  server_url: 'https://demo.invalid',
  server_fixed: true,
  logged_in: true,
  username: 'demo',
  api_key_mask: 'lt_demo123456********',
  gateway_host: 'demo.invalid',
  gateway_port: 7001,
  frpc_found: true,
  tunnels: [
    {
      id: 1,
      name: 'mc-server',
      type: 'tcp',
      local_ip: '127.0.0.1',
      local_port: 25565,
      public_addr: 'demo.invalid:20001',
      status: 'enabled',
      online: true,
      traffic_used: 1073741824,
      bandwidth_limit_str: '不限速'
    },
    {
      id: 2,
      name: 'nas',
      type: 'tcp',
      local_ip: '192.168.1.10',
      local_port: 5000,
      public_addr: 'demo.invalid:20002',
      status: 'enabled',
      online: false,
      traffic_used: 52428800,
      bandwidth_limit_str: '5 MB/s'
    }
  ]
}

const mock = {
  GetState: async () => emptyState,
  Connect: async () => mockConnectedState,
  Logout: async () => emptyState,
  Refresh: async () => mockConnectedState,
  StartClient: async () => {},
  StopClient: async () => {},
  GetLogs: async () => ['[mock] 当前为浏览器预览模式，未连接真实服务端'],
  ClearLogs: async () => {},
  SetAutoStart: async () => {},
  OpenDataDir: async () => '',
  ServerMailEnabled: async () => false,
  SendEmailCode: async () => {},
  ResetPassword: async () => {}
}

const go = isWails ? window.go.main.App : mock

export const api = {
  getState: () => go.GetState(),
  // 只用 API Key 接入；地址由构建注入，未注入时才用第二个参数
  connect: (apiKey, serverUrl) => go.Connect(apiKey, serverUrl),
  logout: () => go.Logout(),
  refresh: () => go.Refresh(),
  start: () => go.StartClient(),
  stop: () => go.StopClient(),
  logs: () => go.GetLogs(),
  clearLogs: () => go.ClearLogs(),
  setAutoStart: (v) => go.SetAutoStart(v),
  openDataDir: () => go.OpenDataDir(),
  // 重置密码：先问服务端有没有开邮件，再决定走验证码还是旧密码
  serverMailEnabled: (serverUrl) => go.ServerMailEnabled(serverUrl),
  sendEmailCode: (serverUrl, email, scene) => go.SendEmailCode(serverUrl, email, scene),
  resetPassword: (serverUrl, account, oldPassword, emailCode, newPassword) =>
    go.ResetPassword(serverUrl, account, oldPassword, emailCode, newPassword)
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
