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
  downloads: () => http.get('/client/downloads'),
  // 换取短时下载地址，交给浏览器原生下载
  downloadLink: (name) => http.get(`/client/download-link/${encodeURIComponent(name)}`)
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
//
// 逐块读取（ReadableStream）而不是一次性 res.blob()，有两个好处：
//   - 传输中途断开时立刻 reject 并提示，不会让用户对着「没反应」等；
//   - 能把已下载字节数报给调用方，页面上显示进度。
// 注意：这仍然是「先缓存到内存再交给浏览器」，大文件仍会占用内存；
// 要彻底改成浏览器原生下载，需要服务端签发短时单次下载地址。
async function downloadToBlob(url, what, onProgress) {
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

  const total = Number(res.headers.get('Content-Length')) || 0
  const chunks = []
  let loaded = 0
  try {
    if (res.body && typeof res.body.getReader === 'function') {
      const reader = res.body.getReader()
      for (;;) {
        const { done, value } = await reader.read()
        if (done) break
        chunks.push(value)
        loaded += value.byteLength
        if (onProgress) onProgress(loaded, total)
      }
    } else {
      // 老浏览器没有流式读取：退回一次性读取，至少不会漏掉异常。
      const buf = await res.arrayBuffer()
      chunks.push(new Uint8Array(buf))
      loaded = buf.byteLength
      if (onProgress) onProgress(loaded, total || loaded)
    }
  } catch (e) {
    // 浏览器/代理/网络在传输过程中断开都会走到这里。不接住的话调用方
    // 只能看到「没有反应」——这正是之前用户反馈的现象。
    if (e?.name === 'AbortError') {
      ElMessage.warning(`下载${what}已取消`)
    } else {
      ElMessage.error(`下载${what}中断：连接已断开，请重试`)
    }
    return null
  }

  const blob = new Blob(chunks, {
    type: res.headers.get('Content-Type') || 'application/octet-stream'
  })
  if (blob.size === 0) {
    ElMessage.error(`下载${what}失败：服务器返回了空文件`)
    return null
  }
  // 有 Content-Length 时校验长度：代理截断、连接提前关闭都会在这里暴露，
  // 而不是让用户拿到一个损坏的 zip。
  if (total && blob.size !== total) {
    ElMessage.error(`下载${what}不完整（${blob.size}/${total} 字节），请重试`)
    return null
  }
  return blob
}

export async function downloadFrpcConfig() {
  const blob = await downloadToBlob('/api/user/client/config?download=1', '配置')
  if (blob) saveBlob(blob, 'frpc.toml')
}

// 安装包下载：向服务端换一个短时签名地址，再用浏览器原生下载。
//
// 为什么不再走 fetch + Blob：那条路径必须先把整个文件读进内存才触发保存，
// 慢网下用户在传输完成前看不到任何下载动作（浏览器下载列表里也没有条目）。
// 原生下载是流式的：点击即出现在下载列表，有进度、可暂停、可断点续传。
// 地址是短时（3 分钟）且绑定当前用户的，不是无鉴权公开链接。
export async function downloadClientFile(name) {
  let d
  try {
    d = await clientApi.downloadLink(name)
  } catch {
    // axios 拦截器已经提示了具体原因
    return false
  }
  if (!d?.url) {
    ElMessage.error('获取下载地址失败，请稍后重试')
    return false
  }
  const a = document.createElement('a')
  a.href = d.url
  a.download = name
  a.style.display = 'none'
  document.body.appendChild(a)
  a.click()
  document.body.removeChild(a)
  return true
}
