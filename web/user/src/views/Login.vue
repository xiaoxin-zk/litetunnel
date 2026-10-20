<template>
  <div class="page">
    <div class="panel lt-card">
      <div class="brand">
        <img v-if="site.site_logo" class="logo-img" :src="site.site_logo" alt="logo" />
        <div v-else class="logo">LT</div>
        <div>
          <h1>{{ site.site_name || 'LiteTunnel' }}</h1>
          <p>{{ site.site_subtitle || '登录后管理你的隧道、客户端与账号' }}</p>
        </div>
      </div>

      <el-alert
        v-if="site.announcement"
        type="info"
        :closable="false"
        show-icon
        style="margin-bottom: 16px"
        :title="site.announcement"
      />

      <div v-if="site.home_content" class="home-content">{{ site.home_content }}</div>

      <el-tabs v-model="tab" class="tabs">
        <el-tab-pane label="登录" name="login">
          <el-form :model="form" :rules="rules" ref="formRef" label-position="top" @submit.prevent>
            <el-form-item label="账号" prop="username">
              <el-input
                v-model="form.username"
                size="large"
                :prefix-icon="User"
                placeholder="用户名或管理员账号"
                autocomplete="username"
              />
            </el-form-item>

            <el-form-item label="密码" prop="password">
              <el-input
                v-model="form.password"
                type="password"
                size="large"
                show-password
                :prefix-icon="Lock"
                placeholder="登录密码"
                autocomplete="current-password"
                @keyup.enter="submit"
              />
            </el-form-item>

            <el-form-item v-if="totpVisible" label="动态口令" prop="totp_code">
              <el-input
                v-model="form.totp_code"
                size="large"
                maxlength="6"
                :prefix-icon="Key"
                placeholder="认证器 App 中的 6 位口令"
                @keyup.enter="submit"
              />
            </el-form-item>

            <el-form-item v-if="loginCaptcha && captcha" :label="`验证码：${captcha.question}`" prop="captcha_answer">
              <el-input
                v-model="form.captcha_answer"
                size="large"
                placeholder="填写计算结果"
                @keyup.enter="submit"
              >
                <template #append>
                  <el-button :icon="Refresh" @click="loadCaptcha" />
                </template>
              </el-input>
            </el-form-item>

            <div v-if="error" class="error">{{ error }}</div>

            <el-button type="primary" size="large" class="submit" :loading="loading" @click="submit">
              登录
            </el-button>

            <div class="links">
              <el-button link type="primary" @click="$router.push('/forgot-password')">
                忘记密码？
              </el-button>
              <el-button v-if="site.register_enabled" link type="primary" @click="tab = 'register'">
                注册账号
              </el-button>
            </div>

            <template v-if="site.oauth_github || site.oauth_google">
              <el-divider>或使用第三方账号登录</el-divider>
              <div class="oauth-row">
                <el-button v-if="site.oauth_github" class="oauth-btn" @click="oauthLogin('github')">
                  GitHub 登录
                </el-button>
                <el-button v-if="site.oauth_google" class="oauth-btn" @click="oauthLogin('google')">
                  Google 登录
                </el-button>
              </div>
              <p class="oauth-hint">仅支持已注册并绑定过的账号，不会自动创建新账号</p>
            </template>
          </el-form>
        </el-tab-pane>

        <el-tab-pane v-if="site.register_enabled" label="注册" name="register">
          <el-form :model="reg" :rules="regRules" ref="regRef" label-position="top" @submit.prevent>
            <el-form-item label="用户名" prop="username">
              <el-input v-model="reg.username" size="large" placeholder="3-32 位字母、数字或下划线" />
            </el-form-item>
            <el-form-item label="密码" prop="password">
              <el-input v-model="reg.password" type="password" size="large" show-password placeholder="至少 8 位" />
            </el-form-item>
            <el-form-item label="确认密码" prop="confirm">
              <el-input v-model="reg.confirm" type="password" size="large" show-password />
            </el-form-item>
            <el-form-item label="邮箱" :prop="requireEmail ? 'email' : ''">
              <el-input
                v-model="reg.email"
                size="large"
                :placeholder="requireEmail ? '必填，用于接收验证码' : '选填，用于找回密码'"
              />
            </el-form-item>

            <el-form-item v-if="requireEmail" label="邮箱验证码" prop="email_code">
              <el-input v-model="reg.email_code" size="large" maxlength="6" placeholder="6 位验证码">
                <template #append>
                  <el-button :disabled="countdown > 0" @click="sendEmailCode">
                    {{ countdown > 0 ? `${countdown}s` : '获取验证码' }}
                  </el-button>
                </template>
              </el-input>
            </el-form-item>

            <el-form-item v-if="captcha" :label="`验证码：${captcha.question}`" prop="captcha_answer">
              <el-input v-model="reg.captcha_answer" size="large" placeholder="填写计算结果">
                <template #append>
                  <el-button :icon="Refresh" @click="loadCaptcha" />
                </template>
              </el-input>
            </el-form-item>

            <el-form-item prop="agreed">
              <el-checkbox v-model="reg.agreed">
                我已阅读并同意
                <el-button link type="primary" style="padding: 0 2px" @click="termsVisible = true">
                  《服务条款与禁止滥用规定》
                </el-button>
              </el-checkbox>
            </el-form-item>

            <div v-if="regError" class="error">{{ regError }}</div>

            <el-button type="primary" size="large" class="submit" :loading="regLoading" @click="submitRegister">
              注册
            </el-button>
          </el-form>
        </el-tab-pane>
      </el-tabs>

      <div v-if="site.icp" class="icp">{{ site.icp }}</div>
    </div>

    <el-dialog v-model="termsVisible" title="服务条款与禁止滥用规定" width="620px">
      <pre class="terms">{{ site.terms || '暂无条款内容' }}</pre>
      <template #footer>
        <el-button @click="termsVisible = false">关闭</el-button>
        <el-button type="primary" @click="agreeTerms">我已阅读并同意</el-button>
      </template>
    </el-dialog>
  </div>
</template>

<script setup>
import { computed, onMounted, reactive, ref } from 'vue'
import { useRoute, useRouter } from 'vue-router'
import { ElMessage } from 'element-plus'
import { User, Lock, Key, Refresh } from '@element-plus/icons-vue'
import { authApi, publicApi, sessionApi, TOKEN_KEY } from '../api'
import { useCountdown } from '../composables/useCountdown'

const ADMIN_TOKEN_KEY = 'lt_admin_token'

const router = useRouter()
const route = useRoute()
const tab = ref('login')
const site = ref({})
const captcha = ref(null)
const totpVisible = ref(false)
const termsVisible = ref(false)
const loginCaptcha = ref(false)

const formRef = ref()
const regRef = ref()
const loading = ref(false)
const regLoading = ref(false)
const error = ref('')
const regError = ref('')

const form = reactive({ username: '', password: '', totp_code: '', captcha_answer: '' })
const reg = reactive({
  username: '',
  password: '',
  confirm: '',
  email: '',
  email_code: '',
  captcha_answer: '',
  agreed: false
})

const requireEmail = computed(
  () => !!site.value.mail_enabled && !!site.value.register_require_email
)
const { countdown, start: startCountdown } = useCountdown()

async function sendEmailCode() {
  const email = reg.email.trim()
  if (!email) {
    ElMessage.warning('请先填写邮箱')
    return
  }
  try {
    await authApi.sendEmailCode({ email, scene: 'register' })
    ElMessage.success('验证码已发送，请查收')
    startCountdown()
  } catch {
  }
}

const rules = {
  username: [{ required: true, message: '请输入账号', trigger: 'blur' }],
  password: [{ required: true, message: '请输入密码', trigger: 'blur' }]
}

const regRules = {
  username: [
    { required: true, message: '请输入用户名', trigger: 'blur' },
    { pattern: /^[A-Za-z0-9_]{3,32}$/, message: '仅允许 3-32 位字母、数字或下划线', trigger: 'blur' }
  ],
  password: [
    { required: true, message: '请输入密码', trigger: 'blur' },
    { min: 8, message: '密码至少 8 位', trigger: 'blur' }
  ],
  confirm: [
    {
      validator: (_r, v, cb) => (v !== reg.password ? cb(new Error('两次输入的密码不一致')) : cb()),
      trigger: 'blur'
    }
  ]
}

async function loadSettings() {
  try {
    site.value = (await publicApi.settings()) || {}
  } catch {
    site.value = {}
  }
}

async function loadCaptcha() {
  try {
    captcha.value = await publicApi.captcha()
    form.captcha_answer = ''
    reg.captcha_answer = ''
  } catch {
    captcha.value = null
  }
}

async function submit() {
  error.value = ''
  await formRef.value.validate()

  if (loginCaptcha.value && captcha.value && !form.captcha_answer.trim()) {
    error.value = '请填写验证码'
    return
  }

  loading.value = true
  try {
    const data = await sessionApi.login({
      username: form.username.trim(),
      password: form.password,
      totp_code: form.totp_code.trim(),
      captcha_ticket: loginCaptcha.value ? captcha.value?.ticket || '' : '',
      captcha_answer: loginCaptcha.value ? form.captcha_answer.trim() : ''
    })

    if (data.role === 'admin') {
      localStorage.setItem(ADMIN_TOKEN_KEY, data.token)
      ElMessage.success('登录成功，正在进入管理后台')
      window.location.href = data.redirect || '/lt-console/'
      return
    }

    localStorage.setItem(TOKEN_KEY, data.token)
    ElMessage.success('登录成功')
    router.push('/')
  } catch (e) {
    const body = e?.response?.data
    if (body?.data?.totp_required || /动态口令/.test(body?.message || '')) {
      totpVisible.value = true
      error.value = '该账号已启用双因素认证，请输入动态口令'
    } else if (body?.data?.captcha_required) {
      loginCaptcha.value = true
      error.value = body?.message || '请输入验证码后重试'
      await loadCaptcha()
    } else {
      error.value = body?.message || '登录失败，请检查账号与密码'
    }
  } finally {
    loading.value = false
  }
}

async function submitRegister() {
  regError.value = ''
  await regRef.value.validate()

  if (!reg.agreed) {
    regError.value = '请先阅读并同意服务条款与禁止滥用规定'
    return
  }
  if (requireEmail.value) {
    if (!reg.email.trim()) {
      regError.value = '请填写邮箱，注册需要邮箱验证'
      return
    }
    if (!reg.email_code.trim()) {
      regError.value = '请填写邮箱验证码'
      return
    }
  }
  if (captcha.value && !reg.captcha_answer.trim()) {
    regError.value = '请填写验证码'
    return
  }

  regLoading.value = true
  try {
    await authApi.register({
      username: reg.username.trim(),
      password: reg.password,
      email: reg.email.trim(),
      email_code: reg.email_code.trim(),
      agreed: reg.agreed,
      captcha_ticket: captcha.value?.ticket || '',
      captcha_answer: reg.captcha_answer.trim()
    })
    ElMessage.success('注册成功，请登录')
    form.username = reg.username.trim()
    tab.value = 'login'
  } catch (e) {
    regError.value = e?.response?.data?.message || '注册失败'
    await loadCaptcha()
  } finally {
    regLoading.value = false
  }
}

function agreeTerms() {
  reg.agreed = true
  termsVisible.value = false
}

function oauthLogin(provider) {
  window.location.href = `/api/auth/oauth/${provider}/start`
}

function handleOAuthRedirect() {
  const oauthError = route.query.oauth_error
  if (oauthError) {
    error.value = String(oauthError)
    router.replace({ path: '/login' })
    return
  }
  const oauthToken = route.query.oauth_token
  if (oauthToken) {
    localStorage.setItem(TOKEN_KEY, String(oauthToken))
    ElMessage.success('第三方登录成功')
    router.replace('/')
  }
}

onMounted(async () => {
  handleOAuthRedirect()
  await loadSettings()
  if (site.value.register_captcha) await loadCaptcha()
})
</script>

<style scoped>
.page {
  min-height: 100vh;
  display: flex;
  align-items: center;
  justify-content: center;
  padding: 24px;
  background:
    radial-gradient(1200px 600px at 20% 0%, var(--lt-glow-1) 0%, transparent 60%),
    radial-gradient(900px 500px at 100% 100%, var(--lt-glow-2) 0%, transparent 55%),
    var(--lt-canvas);
}

.panel {
  width: 100%;
  max-width: 440px;
  padding: 30px 28px 22px;
}

.brand {
  display: flex;
  gap: 13px;
  align-items: center;
  margin-bottom: 18px;
}

.logo-img {
  width: 46px;
  height: 46px;
  border-radius: 13px;
  object-fit: contain;
  background: var(--lt-surface);
  flex-shrink: 0;
}

.oauth-row {
  display: flex;
  gap: 10px;
  margin-top: 4px;
}

.oauth-btn {
  flex: 1;
}

.oauth-hint {
  margin: 10px 0 0;
  color: var(--lt-ink-soft);
  font-size: 12px;
  text-align: center;
}

.home-content {
  white-space: pre-wrap;
  margin-bottom: 16px;
  padding: 12px 14px;
  border-radius: 10px;
  background: var(--lt-surface-2);
  color: var(--lt-ink-2);
  font-size: 13px;
  line-height: 1.8;
}

.logo {
  width: 46px;
  height: 46px;
  border-radius: 13px;
  background: linear-gradient(135deg, var(--lt-primary), var(--lt-primary-strong));
  color: #fff;
  font-weight: 700;
  display: flex;
  align-items: center;
  justify-content: center;
}

.brand h1 {
  margin: 0;
  font-size: 19px;
}

.brand p {
  margin: 4px 0 0;
  font-size: 12.5px;
  color: var(--lt-ink-soft);
}

.tabs :deep(.el-tabs__header) {
  margin-bottom: 18px;
}

.submit {
  width: 100%;
}

.links {
  margin-top: 10px;
  display: flex;
  justify-content: space-between;
}

.error {
  background: var(--lt-danger-soft);
  color: var(--lt-danger);
  border-radius: 9px;
  padding: 10px 12px;
  font-size: 13px;
  margin-bottom: 14px;
}

.icp {
  margin-top: 16px;
  text-align: center;
  font-size: 12px;
  color: var(--lt-ink-soft);
}

.terms {
  white-space: pre-wrap;
  font-family: inherit;
  font-size: 13px;
  line-height: 1.9;
  color: var(--lt-ink-2);
  margin: 0;
  max-height: 420px;
  overflow: auto;
}
</style>
