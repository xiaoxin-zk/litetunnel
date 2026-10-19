
const isWails = typeof window !== 'undefined' && !!window.go?.main?.App

const emptyState = {
  server_url: '',
  server_fixed: false,
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
  last_sync_at: null,
  sync_err: '',
  config_error: '',
  group: null,
  payment_enabled: false,
  balance_cents: 0,
  log_epoch: 0
}

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
      status: 'active',
      online: true,
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
  Redeem: async () => ['[mock] 兑换成功', mockConnectedState],
  CheckUpdate: async () => ({
    current: 'dev',
    latest: '',
    has_update: false,
    error: '浏览器预览模式不支持检查更新'
  }),
  DownloadClientUpdate: async () => ({
    current: 'dev',
    has_update: false,
    error: '浏览器预览模式不支持下载更新'
  })
}

const go = isWails ? window.go.main.App : mock

export const api = {
  getState: () => go.GetState(),
  connect: (apiKey, serverUrl) => go.Connect(apiKey, serverUrl),
  logout: () => go.Logout(),
  refresh: () => go.Refresh(),
  logs: () => go.GetLogs(),
  clearLogs: () => go.ClearLogs(),
  openDataDir: () => go.OpenDataDir(),
  serverMailEnabled: (serverUrl) => go.ServerMailEnabled(serverUrl),
  sendEmailCode: (serverUrl, email, scene) => go.SendEmailCode(serverUrl, email, scene),
  resetPassword: (serverUrl, account, oldPassword, emailCode, newPassword) =>
    go.ResetPassword(serverUrl, account, oldPassword, emailCode, newPassword),
  listLocalServices: () => go.ListLocalServices(),
  createTunnel: (name, type, localIp, localPort, remotePort, subdomain) =>
    go.CreateTunnel(name, type, localIp, localPort, remotePort || 0, subdomain || ''),
  createTunnelsBatch: (prefix, type, localIp, ports) =>
    go.CreateTunnelsBatch(prefix, type, localIp, ports),
  deleteTunnel: (id) => go.DeleteTunnel(id),
  startTunnel: (id) => go.StartTunnel(id),
  stopTunnel: (id) => go.StopTunnel(id),
  redeem: (code) => go.Redeem(code),
  checkUpdate: () => go.CheckUpdate(),
  downloadUpdate: () => go.DownloadClientUpdate()
}

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
    window.runtime.EventsOff?.(name)
  }
}

export const isDesktop = isWails
