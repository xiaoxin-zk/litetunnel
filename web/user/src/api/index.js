import axios from 'axios'
import { ElMessage } from 'element-plus'
import router from '../router'

const http = axios.create({
  baseURL: '/api/user',
  timeout: 20000
})

export const TOKEN_KEY = 'lt_user_token'

http.interceptors.request.use((cfg) => {
  const token = localStorage.getItem(TOKEN_KEY)
  if (token) {
    cfg.headers.Authorization = `Bearer ${token}`
  }
  return cfg
})

function attachResponseHandlers(instance, { redirectOn401 = true } = {}) {
  instance.interceptors.response.use(
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
      if (redirectOn401 && status === 401) {
        localStorage.removeItem(TOKEN_KEY)
        if (router.currentRoute.value.path !== '/login') {
          router.push('/login')
        }
      }
      ElMessage.error(message)
      return Promise.reject(err)
    }
  )
  return instance
}

attachResponseHandlers(http)

const pub = attachResponseHandlers(
  axios.create({ baseURL: '/api', timeout: 20000 }),
  { redirectOn401: false }
)

export default http

export const publicApi = {
  settings: () => pub.get('/public/settings'),
  captcha: () => pub.get('/public/captcha')
}

export const sessionApi = {
  login: (data) => pub.post('/auth/login', data)
}

export const authApi = {
  register: (data) => http.post('/auth/register', data),
  logout: () => http.post('/logout'),
  forgotPassword: (account) => http.post('/auth/forgot-password', { account }),
  resetPassword: (data) => http.post('/auth/reset-password', data),
  mailStatus: () => http.get('/auth/mail-status'),
  sendEmailCode: (data) => http.post('/auth/send-email-code', data)
}

export const profileApi = {
  get: () => http.get('/profile'),
  update: (data) => http.put('/profile', data),
  changePassword: (data) => http.put('/profile/password', data),
  requestEmailChange: (data) => http.post('/profile/email-code', data),
  confirmEmailChange: (data) => http.post('/profile/email', data),
  deleteAccount: (password) => http.delete('/profile', { data: { password } })
}

export const tunnelApi = {
  list: () => http.get('/tunnels'),
  create: (data) => http.post('/tunnels', data),
  update: (id, data) => http.put(`/tunnels/${id}`, data),
  remove: (id) => http.delete(`/tunnels/${id}`),
  setStatus: (id, status) => http.post(`/tunnels/${id}/status`, { status })
}

export const apiKeyApi = {
  meta: () => http.get('/apikey'),
  reveal: () => http.post('/apikey/reveal'),
  rotate: () => http.post('/apikey/rotate')
}

export const redeemApi = {
  submit: (code) => http.post('/redeem', { code }),
  records: (params) => http.get('/redeem/records', { params })
}

export const clientApi = {
  info: () => http.get('/client/info'),
  configText: () => http.get('/client/config'),
  downloads: () => http.get('/client/downloads')
}

export const statsApi = {
  overview: () => http.get('/stats/overview'),
  traffic: (days = 7) => http.get('/stats/traffic', { params: { days } })
}

export async function downloadFrpcConfig() {
  const token = localStorage.getItem(TOKEN_KEY)
  const res = await fetch('/api/user/client/config?download=1', {
    headers: { Authorization: `Bearer ${token}` }
  })
  if (!res.ok) {
    ElMessage.error('获取配置失败，请重新登录')
    return
  }
  const blob = await res.blob()
  const url = URL.createObjectURL(blob)
  const a = document.createElement('a')
  a.href = url
  a.download = 'frpc.toml'
  a.click()
  URL.revokeObjectURL(url)
}

export async function downloadClientFile(name) {
  const token = localStorage.getItem(TOKEN_KEY)
  const res = await fetch(`/api/user/client/downloads/${encodeURIComponent(name)}`, {
    headers: { Authorization: `Bearer ${token}` }
  })
  if (!res.ok) {
    ElMessage.error('下载失败')
    return
  }
  const blob = await res.blob()
  const url = URL.createObjectURL(blob)
  const a = document.createElement('a')
  a.href = url
  a.download = name
  a.click()
  URL.revokeObjectURL(url)
}
