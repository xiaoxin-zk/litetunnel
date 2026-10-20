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

// 把 blob 交给浏览器下载。
//
// 两个细节决定了「点了没反应」会不会发生：
//   1. <a> 必须先插入文档再 click（部分浏览器对游离节点不触发下载）；
//   2. 不能 click 之后立刻 revokeObjectURL——浏览器是异步去读这个 URL 的，
//      提前释放会让下载直接失败或得到 0 字节文件。延迟释放，页面关掉时
//      浏览器也会自己回收。
function saveBlob(blob, filename) {
  const url = URL.createObjectURL(blob)
  const a = document.createElement('a')
  a.href = url
  a.download = filename
  a.style.display = 'none'
  document.body.appendChild(a)
  a.click()
  document.body.removeChild(a)
  setTimeout(() => URL.revokeObjectURL(url), 60_000)
}

// 下载接口需要 Bearer token，浏览器原生 <a href> 带不上，所以只能 fetch 取 blob。
// 这里把失败原因区分开：登录过期、文件不存在、服务端错误，各给各的提示，
// 不要一律「下载失败」。
async function fetchBlob(url, what) {
  const token = localStorage.getItem(TOKEN_KEY)
  let res
  try {
    res = await fetch(url, { headers: { Authorization: `Bearer ${token}` } })
  } catch {
    ElMessage.error(`下载${what}失败：网络异常，请检查连接后重试`)
    return null
  }
  if (res.status === 401) {
    ElMessage.error('登录状态已失效，请重新登录后再下载')
    return null
  }
  if (res.status === 404) {
    ElMessage.error(`${what}不存在或已被删除，请联系管理员重新上传`)
    return null
  }
  if (!res.ok) {
    ElMessage.error(`下载${what}失败（HTTP ${res.status}），请稍后重试`)
    return null
  }
  const blob = await res.blob()
  if (blob.size === 0) {
    ElMessage.error(`下载${what}失败：服务器返回了空文件`)
    return null
  }
  return blob
}

export async function downloadFrpcConfig() {
  const blob = await fetchBlob('/api/user/client/config?download=1', '配置')
  if (blob) saveBlob(blob, 'frpc.toml')
}

export async function downloadClientFile(name) {
  const blob = await fetchBlob(`/api/user/client/downloads/${encodeURIComponent(name)}`, '安装包')
  if (!blob) return
  saveBlob(blob, name)
  ElMessage.success(`已开始下载 ${name}`)
}
