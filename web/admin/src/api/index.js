import axios from 'axios'
import { ElMessage } from 'element-plus'
import router from '../router'

// 管理后台只访问管理域接口，且默认部署在仅本机可达的端口上。
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
  (err) => {
    const status = err.response?.status
    const message = err.response?.data?.message || err.message || '网络异常'
    if (status === 401) {
      localStorage.removeItem(TOKEN_KEY)
      if (router.currentRoute.value.path !== '/login') {
        router.push('/login')
      }
    }
    ElMessage.error(message)
    return Promise.reject(err)
  }
)

export default http

export const authApi = {
  login: (data) => http.post('/auth/login', data),
  profile: () => http.get('/profile'),
  changePassword: (data) => http.put('/profile/password', data),
  totpSetup: () => http.post('/profile/totp/setup'),
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

export const logApi = {
  audit: (params) => http.get('/audit-logs', { params }),
  clients: (params) => http.get('/clients', { params })
}
