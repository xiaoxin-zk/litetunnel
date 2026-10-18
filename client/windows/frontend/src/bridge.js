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
  // 自动同步状态：客户端每 20 秒拉取一次隧道清单与 frpc 配置
  last_sync_at: null,
  sync_err: '',
  // config_error 非空表示本地配置文件损坏（已备份，需要重新填 API Key）
  config_error: '',
  group: null,
  payment_enabled: false,
  balance_cents: 0
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
      // status 的取值与服务端一致：active / disabled
      status: 'active',
      online: true,
      // running 表示本机是否已为这条隧道拉起 frpc 进程
      running: true,
      last_error: '',
      last_error_at: null,
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
      status: 'active',
      online: false,
      running: false,
      last_error: '',
      last_error_at: null,
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
  StartTunnel: async () => mockConnectedState,
  StopTunnel: async () => mockConnectedState,
  GetLogs: async () => ['[mock] 当前为浏览器预览模式，未连接真实服务端'],
  ClearLogs: async () => {},
  OpenDataDir: async () => '',
  ServerMailEnabled: async () => false,
  SendEmailCode: async () => {},
  ResetPassword: async () => {},
  ListLocalServices: async () => [
    { port: 25565, proto: 'tcp', addr: '0.0.0.0', pid: 1234, process: 'java.exe', recommended: true },
    { port: 8211, proto: 'udp', addr: '0.0.0.0', pid: 2345, process: 'PalServer.exe', recommended: true }
  ],
  CreateTunnel: async () => mockConnectedState,
  CreateTunnelsBatch: async () => [{ message: '[mock] 已创建 3 条隧道', failures: [] }, mockConnectedState],
  DeleteTunnel: async () => mockConnectedState,
  Redeem: async () => ['[mock] 兑换成功', mockConnectedState]
}

const go = isWails ? window.go.main.App : mock

export const api = {
  getState: () => go.GetState(),
  // 只用 API Key 接入；地址由构建注入，未注入时才用第二个参数
  connect: (apiKey, serverUrl) => go.Connect(apiKey, serverUrl),
  logout: () => go.Logout(),
  refresh: () => go.Refresh(),
  logs: () => go.GetLogs(),
  clearLogs: () => go.ClearLogs(),
  openDataDir: () => go.OpenDataDir(),
  // 重置密码：先问服务端有没有开邮件，再决定走验证码还是旧密码
  serverMailEnabled: (serverUrl) => go.ServerMailEnabled(serverUrl),
  sendEmailCode: (serverUrl, email, scene) => go.SendEmailCode(serverUrl, email, scene),
  resetPassword: (serverUrl, account, oldPassword, emailCode, newPassword) =>
    go.ResetPassword(serverUrl, account, oldPassword, emailCode, newPassword),
  // 枚举本机正在监听的服务，供用户点选而不是手填端口
  listLocalServices: () => go.ListLocalServices(),
  // 隧道管理。remotePort 传 0 表示由服务端自动分配端口，
  // 界面默认不暴露这个参数。
  createTunnel: (name, type, localIp, localPort, remotePort, subdomain) =>
    go.CreateTunnel(name, type, localIp, localPort, remotePort || 0, subdomain || ''),
  createTunnelsBatch: (prefix, type, localIp, ports) =>
    go.CreateTunnelsBatch(prefix, type, localIp, ports),
  deleteTunnel: (id) => go.DeleteTunnel(id),
  // 隧道开关：开启即拉起该隧道自己的 frpc 进程，关闭即停掉它。
  // 没有「先启用再连接」两步——两步之间必然出现「开着却没连上」的状态。
  startTunnel: (id) => go.StartTunnel(id),
  stopTunnel: (id) => go.StopTunnel(id),
  redeem: (code) => go.Redeem(code)
}

/**
 * 订阅 Wails 事件；非桌面环境下静默忽略。
 *
 * 返回的取消函数必须由调用方保存并在卸载时调用：热重载或组件重复挂载时，
 * 不注销就会累积多个同名监听——同一批日志被处理多遍、同一次状态推送被
 * 重复应用，而序号去重会把这些症状掩盖成「偶发的顺序错乱」。
 *
 * 取消是幂等的：重复调用不会重复注销，也不会误伤别的订阅者。
 */
export function onEvent(name, handler) {
  if (typeof window === 'undefined' || !window.runtime?.EventsOn) {
    return () => {}
  }
  const off = window.runtime.EventsOn(name, handler)
  let done = false
  return () => {
    if (done) return
    done = true
    if (typeof off === 'function') {
      off()
      return
    }
    // 老版本运行时只提供按事件名注销：同名监听会被一起移除，
    // 因此一个事件名只应有一个订阅者（见 App.vue 的 subscribe）。
    window.runtime.EventsOff?.(name)
  }
}

export const isDesktop = isWails
