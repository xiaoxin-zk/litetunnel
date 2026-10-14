import axios from 'axios'
import { ElMessage } from 'element-plus'
import router from '../router'

// 用户控制台只访问用户域接口；管理端接口在公网端口上并不存在。
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
  register: (data) => http.post('/auth/register', data),
  login: (data) => http.post('/auth/login', data),
  logout: () => http.post('/logout')
}

export const profileApi = {
  get: () => http.get('/profile'),
  update: (data) => http.put('/profile', data),
  changePassword: (data) => http.put('/profile/password', data)
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

/** 触发浏览器下载 frpc.toml。 */
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

/** 触发客户端安装包下载。 */
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
