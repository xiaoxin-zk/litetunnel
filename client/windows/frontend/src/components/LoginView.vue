<template>
  <div class="page">
    <div class="card panel">
      <div class="brand">
        <div class="logo">LT</div>
        <div>
          <h1>LiteTunnel</h1>
          <p>粘贴 API Key 即可连接你的游戏服务器、网站或 NAS</p>
        </div>
      </div>

      <label class="field">
        <span>服务地址</span>
        <div v-if="state.server_fixed" class="fixed-server">
          {{ state.server_url || '未配置' }}
        </div>
        <input
          v-else
          v-model="form.server"
          placeholder="例如 https://panel.example.com 或 http://1.2.3.4"
          spellcheck="false"
          autocomplete="off"
          @keyup.enter="submit"
        />
        <em class="muted">
          {{ state.server_fixed ? '由客户端内置，无需填写' : '当前为调试构建，请填写控制台地址（http 会明文传输 API Key）' }}
        </em>
      </label>

      <div v-if="notice" class="notice">{{ notice }}</div>

      <div v-if="state.config_error" class="notice">{{ state.config_error }}</div>

      <template v-if="mode === 'login'">
        <label class="field">
          <span>API Key</span>
          <input
            v-model="form.apiKey"
            placeholder="lt_xxxxxxxxxxxxxxxxxxxx"
            spellcheck="false"
            autocomplete="off"
            @keyup.enter="submit"
          />
          <em class="muted">在控制台「API Key」页复制，注册后即自动生成</em>
        </label>

        <div v-if="error" class="error">{{ error }}</div>

        <button class="btn-primary submit" :disabled="loading" @click="submit">
          {{ loading ? '正在连接…' : '连接' }}
        </button>

        <p class="hint muted">
          客户端只在本地保存这一把 Key，不保存账号密码；Key 可在控制台随时重置。
        </p>
        <p class="hint muted">
          <a class="link" @click="openReset">忘记密码？</a>
        </p>
        <p class="hint muted version">{{ state.version }}</p>
      </template>

      <template v-else>
        <label class="field">
          <span>用户名或邮箱</span>
          <input v-model="reset.account" placeholder="注册时使用的账号" spellcheck="false" autocomplete="off" />
        </label>

        <label v-if="mailEnabled" class="field">
          <span>邮箱验证码</span>
          <div class="row">
            <input
              v-model="reset.emailCode"
              maxlength="6"
              placeholder="6 位验证码"
              spellcheck="false"
              autocomplete="off"
            />
            <button class="btn-ghost" :disabled="countdown > 0 || sending" @click="sendCode">
              {{ countdown > 0 ? `${countdown}s` : '获取验证码' }}
            </button>
          </div>
          <em class="muted">发送到账号绑定的邮箱</em>
        </label>

        <label v-else class="field">
          <span>当前密码</span>
          <input v-model="reset.oldPassword" type="password" placeholder="用于验证身份" autocomplete="off" />
          <em class="muted">本站未启用邮件服务，因此用当前密码验证身份</em>
        </label>

        <label class="field">
          <span>新密码</span>
          <input v-model="reset.password" type="password" placeholder="至少 8 位" autocomplete="off" />
        </label>

        <label class="field">
          <span>确认新密码</span>
          <input v-model="reset.confirm" type="password" autocomplete="off" />
        </label>

        <div v-if="error" class="error">{{ error }}</div>

        <button class="btn-primary submit" :disabled="loading" @click="submitReset">
          {{ loading ? '正在提交…' : '重置密码' }}
        </button>
        <p class="hint muted">
          重置成功后所有已登录设备都会下线，客户端需要重新填写 API Key。
        </p>
        <p class="hint muted">
          <a class="link" @click="mode = 'login'">返回连接</a>
        </p>
      </template>
    </div>
  </div>
</template>

<script setup>
import { onUnmounted, reactive, ref, watch } from 'vue'
import { api } from '../bridge'

const props = defineProps({
  state: { type: Object, default: () => ({}) }
})
const emit = defineEmits(['connected'])

const loading = ref(false)
const error = ref('')
const form = reactive({ server: '', apiKey: '' })

let attempt = 0
// 用计数器而不是「序号是否仍然最新」决定何时收起 loading：
// 编辑表单会让序号前进，旧请求结束时若不清计数，按钮会永久禁用。
let loadPending = 0
let sendPending = 0

async function submit() {
  error.value = ''
  if (!form.apiKey.trim()) {
    error.value = '请粘贴 API Key'
    return
  }
  if (!props.state.server_fixed && !form.server.trim()) {
    error.value = '请填写服务地址'
    return
  }

  const seq = ++attempt
  loadPending++
  loading.value = true
  try {
    const next = await api.connect(form.apiKey.trim(), form.server.trim())
    if (seq !== attempt) return
    emit('connected', next)
  } catch (e) {
    if (seq !== attempt) return
    error.value = typeof e === 'string' ? e : e?.message || '连接失败，请检查 API Key 是否正确'
  } finally {
    loadPending--
    if (loadPending <= 0) {
      loadPending = 0
      loading.value = false
    }
  }
}


const mode = ref('login')

watch(() => form.server, () => { attempt++ }, { flush: 'sync' })
watch(mode, () => { attempt++ }, { flush: 'sync' })
const sending = ref(false)
const countdown = ref(0)
const mailEnabled = ref(false)
const notice = ref('')
const reset = reactive({ account: '', emailCode: '', oldPassword: '', password: '', confirm: '' })

watch(
  () => [form.apiKey, reset.account, reset.emailCode, reset.oldPassword, reset.password, reset.confirm],
  () => { attempt++ },
  { flush: 'sync' }
)

let countdownTimer = null
function stopCountdown() {
  if (countdownTimer) {
    clearInterval(countdownTimer)
    countdownTimer = null
  }
}
onUnmounted(stopCountdown)

async function openReset() {
  error.value = ''
  notice.value = ''
  mode.value = 'reset' // 上面的 watch 会推进代次
  const seq = ++attempt
  try {
    const enabled = await api.serverMailEnabled(form.server.trim())
    if (seq !== attempt) return
    mailEnabled.value = enabled
  } catch {
    if (seq !== attempt) return
    mailEnabled.value = false
  }
}

async function sendCode() {
  const account = reset.account.trim()
  if (!account) {
    error.value = '请先填写用户名或邮箱'
    return
  }
  error.value = ''
  const seq = ++attempt
  sendPending++
  sending.value = true
  try {
    await api.sendEmailCode(form.server.trim(), account, 'reset')
    if (seq !== attempt) return
    countdown.value = 60
    stopCountdown()
    countdownTimer = setInterval(() => {
      countdown.value -= 1
      if (countdown.value <= 0) stopCountdown()
    }, 1000)
  } catch (e) {
    if (seq !== attempt) return
    error.value = typeof e === 'string' ? e : e?.message || '验证码发送失败'
  } finally {
    sendPending--
    if (sendPending <= 0) {
      sendPending = 0
      sending.value = false
    }
  }
}

async function submitReset() {
  error.value = ''
  notice.value = ''

  if (!reset.account.trim()) {
    error.value = '请填写用户名或邮箱'
    return
  }
  if (mailEnabled.value && !reset.emailCode.trim()) {
    error.value = '请填写邮箱验证码'
    return
  }
  if (!mailEnabled.value && !reset.oldPassword) {
    error.value = '请填写当前密码'
    return
  }
  if (reset.password.length < 8) {
    error.value = '新密码至少 8 位'
    return
  }
  if (reset.password !== reset.confirm) {
    error.value = '两次输入的密码不一致'
    return
  }

  const seq = ++attempt
  loadPending++
  loading.value = true
  try {
    await api.resetPassword(
      form.server.trim(),
      reset.account.trim(),
      reset.oldPassword,
      reset.emailCode.trim(),
      reset.password
    )
    if (seq !== attempt) return
    reset.oldPassword = ''
    reset.emailCode = ''
    reset.password = ''
    reset.confirm = ''
    mode.value = 'login'
    notice.value = '密码已重置。请用新密码登录控制台，并重新获取 API Key 后连接。'
  } catch (e) {
    if (seq !== attempt) return
    error.value = typeof e === 'string' ? e : e?.message || '重置失败，请检查填写的信息'
  } finally {
    loadPending--
    if (loadPending <= 0) {
      loadPending = 0
      loading.value = false
    }
  }
}

watch(
  () => props.state?.server_url,
  (v) => {
    if (!props.state?.server_fixed && !form.server) {
      form.server = v || ''
    }
  },
  { immediate: true }
)
</script>

<style scoped>
.page {
  height: 100%;
  display: flex;
  align-items: center;
  justify-content: center;
  padding: 28px;
  background: radial-gradient(900px 480px at 15% 0%, #dbeafe 0%, transparent 60%),
    radial-gradient(700px 420px at 100% 100%, #e0e7ff 0%, transparent 55%), #f5f7fb;
}

.panel {
  width: 100%;
  max-width: 420px;
  padding: 30px 28px 24px;
}

.brand {
  display: flex;
  gap: 13px;
  align-items: center;
  margin-bottom: 22px;
}

.logo {
  width: 46px;
  height: 46px;
  border-radius: 13px;
  background: linear-gradient(135deg, #2563eb, #4f46e5);
  color: #fff;
  font-weight: 700;
  display: flex;
  align-items: center;
  justify-content: center;
}

h1 {
  margin: 0;
  font-size: 19px;
}

.brand p {
  margin: 4px 0 0;
  font-size: 12.5px;
  color: #6b7280;
}

.field {
  display: block;
  margin-bottom: 16px;
}

.field > span {
  display: block;
  font-size: 13px;
  font-weight: 500;
  margin-bottom: 6px;
  color: #374151;
}

.field em {
  display: block;
  margin-top: 5px;
  font-style: normal;
}

.fixed-server {
  padding: 11px 13px;
  border-radius: 10px;
  background: #f3f4f6;
  color: #4b5563;
  font-size: 13.5px;
  font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace;
  -webkit-user-select: text;
  user-select: text;
}

.error {
  background: #fee2e2;
  color: #b91c1c;
  border-radius: 9px;
  padding: 10px 12px;
  font-size: 13px;
  margin-bottom: 14px;
  -webkit-user-select: text;
  user-select: text;
}

.notice {
  background: #dcfce7;
  color: #166534;
  border-radius: 9px;
  padding: 10px 12px;
  font-size: 13px;
  line-height: 1.7;
  margin-bottom: 16px;
  -webkit-user-select: text;
  user-select: text;
}

.row {
  display: flex;
  gap: 8px;
}

.row input {
  flex: 1;
  min-width: 0;
}

.btn-ghost {
  flex: 0 0 auto;
  padding: 0 14px;
  border-radius: 10px;
  border: 1px solid #d1d5db;
  background: #fff;
  color: #374151;
  font-size: 13px;
  cursor: pointer;
  white-space: nowrap;
}

.btn-ghost:disabled {
  opacity: 0.55;
  cursor: not-allowed;
}

.link {
  color: #2563eb;
  cursor: pointer;
  text-decoration: none;
}

.version {
  margin-top: 8px;
  font-family: ui-monospace, Menlo, Consolas, monospace;
  font-size: 11.5px;
  opacity: 0.75;
  -webkit-user-select: text;
  user-select: text;
}

.link:hover {
  text-decoration: underline;
}

.submit {
  width: 100%;
  padding: 12px;
  font-size: 15px;
  font-weight: 500;
}

.hint {
  margin: 16px 0 0;
  text-align: center;
  line-height: 1.7;
}
</style>
