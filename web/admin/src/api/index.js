import axios from 'axios'
import { ElMessage, ElMessageBox } from 'element-plus'
import router from '../router'

const http = axios.create({
  baseURL: '/api/admin',
  timeout: 20000
})

export const TOKEN_KEY = 'lt_admin_token'

http.interceptors.request.use((cfg) => {
  const token = localStorage.getItem(TOKEN_KEY)
  if (token) {
    cfg.headers.Authorization = `Bearer ${token}`
  }
  return cfg
})

http.interceptors.response.use(
  (res) => {
    const body = res.data
    if (body && typeof body.code === 'number' && body.code !== 0) {
      ElMessage.error(body.message || '请求失败')
      return Promise.reject(new Error(body.message || '请求失败'))
    }
    return body ? body.data : null
  },
  async (err) => {
    const status = err.response?.status
    const body = err.response?.data
    const message = body?.message || err.message || '网络异常'
    if (status === 401) {
      localStorage.removeItem(TOKEN_KEY)
      if (router.currentRoute.value.path !== '/login') {
        router.push('/login')
      }
    }

    // 敏感操作门控：后端返回 step_up_required 时弹出动态口令，验证通过后重试原请求一次。
    if (status === 403 && body?.data?.step_up_required) {
      try {
        await requestStepUp()
      } catch {
        return Promise.reject(err)
      }
      const cfg = err.config || {}
      if (!cfg.__stepUpRetried) {
        cfg.__stepUpRetried = true
        return http(cfg)
      }
    }

    ElMessage.error(message)
    return Promise.reject(err)
  }
)

let stepUpPending = null

function requestStepUp() {
  if (!stepUpPending) {
    stepUpPending = (async () => {
      const { value } = await ElMessageBox.prompt(
        '该操作需要二次验证，请输入认证器中的 6 位动态口令',
        '敏感操作验证',
        {
          inputPattern: /^\d{6}$/,
          inputErrorMessage: '请输入 6 位数字',
          confirmButtonText: '验证',
          cancelButtonText: '取消'
        }
      )
      await http.post('/step-up', { code: value })
      ElMessage.success('验证通过，有效期 15 分钟')
    })().finally(() => {
      stepUpPending = null
    })
  }
  return stepUpPending
}

export default http

export const authApi = {
  profile: () => http.get('/profile'),
  updateProfile: (data) => http.put('/profile', data),
  changePassword: (data) => http.put('/profile/password', data),
  totpSetup: (code) => http.post('/profile/totp/setup', { code: code || '' }),
  totpEnable: (code) => http.post('/profile/totp/enable', { code }),
  totpDisable: (password) => http.post('/profile/totp/disable', { password })
}

export const statsApi = {
  overview: () => http.get('/stats/overview')
}

export const userApi = {
  list: (params) => http.get('/users', { params }),
  create: (data) => http.post('/users', data),
  update: (id, data) => http.put(`/users/${id}`, data),
  remove: (id) => http.delete(`/users/${id}`),
  setStatus: (id, status) => http.post(`/users/${id}/status`, { status }),
  setQuota: (id, traffic_quota) => http.post(`/users/${id}/quota`, { traffic_quota }),
  resetTraffic: (id) => http.post(`/users/${id}/traffic-reset`),
  setGroup: (id, data) => http.post(`/users/${id}/group`, data),
  resetPassword: (id, password) => http.post(`/users/${id}/password`, { password }),
  resetSecret: (id) => http.post(`/users/${id}/reset-secret`)
}

export const groupApi = {
  list: () => http.get('/groups'),
  create: (data) => http.post('/groups', data),
  update: (id, data) => http.put(`/groups/${id}`, data),
  remove: (id) => http.delete(`/groups/${id}`)
}

export const tunnelApi = {
  list: (params) => http.get('/tunnels', { params }),
  setStatus: (id, status) => http.post(`/tunnels/${id}/status`, { status }),
  remove: (id) => http.delete(`/tunnels/${id}`)
}

export const redeemApi = {
  list: (params) => http.get('/redeem-codes', { params }),
  generate: (data) => http.post('/redeem-codes/generate', data),
  setStatus: (id, status) => http.post(`/redeem-codes/${id}/status`, { status }),
  remove: (id) => http.delete(`/redeem-codes/${id}`),
  records: (params) => http.get('/redeem-records', { params })
}

export const adminApi = {
  list: () => http.get('/admins'),
  create: (data) => http.post('/admins', data),
  update: (id, data) => http.put(`/admins/${id}`, data),
  remove: (id) => http.delete(`/admins/${id}`),
  setPassword: (id, password) => http.post(`/admins/${id}/password`, { password }),
  clearTOTP: (id) => http.post(`/admins/${id}/totp-reset`)
}

export const clientPkgApi = {
  list: () => http.get('/client-packages'),
  upload: (file, onProgress) => {
    const fd = new FormData()
    fd.append('file', file)
    return http.post('/client-packages', fd, {
      timeout: 0,
      onUploadProgress: (e) => {
        if (onProgress && e.total) onProgress(Math.round((e.loaded / e.total) * 100))
      }
    })
  },
  remove: (name) => http.delete(`/client-packages/${encodeURIComponent(name)}`)
}

export const systemApi = {
  update: (force) => http.get('/system/update', { params: force ? { force: 1 } : {} }),
  applyUpdate: () => http.post('/system/update/apply'),
  restart: () => http.post('/system/update/restart')
}

export const monitorApi = {
  system: (limit) => http.get('/system/metrics', { params: limit ? { limit } : {} })
}

export const firewallApi = {
  status: () => http.get('/firewall/status'),
  rescan: () => http.post('/firewall/rescan'),
  open: (port, proto) => http.post('/firewall/ports', { port, proto }),
  close: (port, proto) => http.delete('/firewall/ports', { data: { port, proto } }),
  clearFailed: (port) => http.post('/firewall/failed/clear', { port })
}

export const settingsApi = {
  get: () => http.get('/settings'),
  update: (data) => http.put('/settings', data),
  testMail: (to) => http.post('/settings/test-mail', { to })
}

export const backupApi = {
  list: () => http.get('/backups'),
  create: () => http.post('/backups'),
  remove: (name) => http.delete(`/backups/${encodeURIComponent(name)}`),
  restore: (name) => http.post(`/backups/${encodeURIComponent(name)}/restore`)
}

export const adminKeyApi = {
  list: () => http.get('/admin-api-keys'),
  create: (data) => http.post('/admin-api-keys', data),
  revoke: (id) => http.delete(`/admin-api-keys/${id}`)
}

export const mailTemplateApi = {
  list: () => http.get('/mail-templates'),
  save: (event, data) => http.put(`/mail-templates/${event}`, data),
  reset: (event) => http.delete(`/mail-templates/${event}`),
  preview: (event, data) => http.post(`/mail-templates/${event}/preview`, data)
}

export const domainApi = {
  status: () => http.get('/domain/status'),
  apply: (apply = true) => http.post('/domain/apply', { apply }),
  dnsCheck: () => http.post('/domain/dns-check')
}

export const alertApi = {
  settings: () => http.get('/alerts/settings'),
  saveSettings: (data) => http.put('/alerts/settings', data),
  test: () => http.post('/alerts/settings/test'),
  events: (limit) => http.get('/alerts/events', { params: limit ? { limit } : {} }),
  resolve: (id) => http.post(`/alerts/events/${id}/resolve`),
  metrics: (limit) => http.get('/alerts/metrics', { params: limit ? { limit } : {} })
}

export const logApi = {
  audit: (params) => http.get('/audit-logs', { params }),
  clients: (params) => http.get('/clients', { params }),
  logins: (params) => http.get('/login-logs', { params })
}
