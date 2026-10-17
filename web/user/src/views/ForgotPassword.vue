<template>
  <div class="page">
    <div class="panel">
      <div class="brand">
        <div class="logo">LT</div>
        <div>
          <h1>重置密码</h1>
          <p>{{ mailEnabled ? '通过邮箱验证码重置' : '通过当前密码验证身份' }}</p>
        </div>
      </div>

      <el-alert
        v-if="mailEnabled === false"
        type="info"
        :closable="false"
        show-icon
        style="margin-bottom: 16px"
        title="站点未启用邮件服务"
        description="因此改用「当前密码 + 新密码」的方式验证身份。如果你已忘记当前密码，请联系管理员重置。"
      />

      <el-form :model="form" :rules="rules" ref="formRef" label-position="top" @submit.prevent>
        <el-form-item label="用户名或邮箱" prop="account">
          <el-input
            v-model="form.account"
            size="large"
            placeholder="请输入用户名或注册邮箱"
            :prefix-icon="User"
          />
        </el-form-item>

        <!-- 站点启用邮件：用一次性验证码证明身份 -->
        <el-form-item v-if="mailEnabled" label="邮箱验证码" prop="email_code">
          <el-input v-model="form.email_code" size="large" maxlength="6" placeholder="6 位验证码">
            <template #append>
              <el-button :disabled="countdown > 0" @click="sendCode">
                {{ countdown > 0 ? `${countdown}s` : '获取验证码' }}
              </el-button>
            </template>
          </el-input>
        </el-form-item>

        <!-- 站点未启用邮件：用当前密码证明身份 -->
        <el-form-item v-else label="当前密码" prop="old_password">
          <el-input
            v-model="form.old_password"
            type="password"
            size="large"
            show-password
            :prefix-icon="Lock"
            placeholder="用于验证身份"
          />
        </el-form-item>

        <el-form-item label="新密码" prop="password">
          <el-input
            v-model="form.password"
            type="password"
            size="large"
            show-password
            placeholder="至少 8 位"
          />
        </el-form-item>

        <el-form-item label="确认新密码" prop="confirm">
          <el-input v-model="form.confirm" type="password" size="large" show-password />
        </el-form-item>

        <div v-if="error" class="error">{{ error }}</div>

        <el-button type="primary" size="large" class="submit" :loading="loading" @click="submit">
          重置密码
        </el-button>
      </el-form>

      <div class="footer">
        <el-button link @click="$router.push('/login')">返回登录</el-button>
      </div>
    </div>
  </div>
</template>

<script setup>
import { onMounted, reactive, ref } from 'vue'
import { useRouter } from 'vue-router'
import { ElMessage } from 'element-plus'
import { User, Lock } from '@element-plus/icons-vue'
import { authApi } from '../api'

const router = useRouter()
const formRef = ref()
const loading = ref(false)
const error = ref('')
const countdown = ref(0)
// null 表示尚未探测出来，避免首屏闪烁
const mailEnabled = ref(null)

const form = reactive({
  account: '',
  email_code: '',
  old_password: '',
  password: '',
  confirm: ''
})

const rules = {
  account: [{ required: true, message: '请输入用户名或邮箱', trigger: 'blur' }],
  password: [
    { required: true, message: '请输入新密码', trigger: 'blur' },
    { min: 8, message: '密码至少 8 位', trigger: 'blur' }
  ],
  confirm: [
    {
      validator: (_r, v, cb) => (v !== form.password ? cb(new Error('两次输入的密码不一致')) : cb()),
      trigger: 'blur'
    }
  ]
}

async function sendCode() {
  const account = form.account.trim()
  if (!account) {
    ElMessage.warning('请先填写用户名或邮箱')
    return
  }
  try {
    // scene=reset：无论邮箱是否注册过都返回成功，避免这个接口变成账号枚举工具
    await authApi.sendEmailCode({ email: account, scene: 'reset' })
    ElMessage.success('找回请求已受理；若长时间未收到验证码，请稍后重新申请')
    countdown.value = 60
    const timer = setInterval(() => {
      countdown.value -= 1
      if (countdown.value <= 0) clearInterval(timer)
    }, 1000)
  } catch {
    // 失败提示由响应拦截器统一处理
  }
}

async function submit() {
  error.value = ''
  await formRef.value.validate()

  if (mailEnabled.value && !form.email_code.trim()) {
    error.value = '请填写邮箱验证码'
    return
  }
  if (!mailEnabled.value && !form.old_password) {
    error.value = '请填写当前密码'
    return
  }

  loading.value = true
  try {
    await authApi.resetPassword({
      account: form.account.trim(),
      email_code: mailEnabled.value ? form.email_code.trim() : '',
      old_password: mailEnabled.value ? '' : form.old_password,
      password: form.password
    })
    ElMessage.success('密码已重置，所有设备已下线，请用新密码登录')
    router.push('/login')
  } catch (e) {
    error.value = e?.response?.data?.message || '重置失败，请检查填写的信息'
  } finally {
    loading.value = false
  }
}

onMounted(async () => {
  try {
    const data = await authApi.mailStatus()
    mailEnabled.value = !!data?.mail_enabled
  } catch {
    // 探测失败时按「未启用邮件」处理：旧密码模式在任何配置下都可用
    mailEnabled.value = false
  }
})
</script>

<style scoped>
.page {
  min-height: 100vh;
  display: flex;
  align-items: center;
  justify-content: center;
  padding: 24px;
  background: radial-gradient(1200px 600px at 20% 0%, #dbeafe 0%, transparent 60%),
    radial-gradient(900px 500px at 100% 100%, #e0e7ff 0%, transparent 55%), #f5f7fb;
}

.panel {
  width: 100%;
  max-width: 430px;
  background: #fff;
  border-radius: 18px;
  padding: 32px 30px 22px;
  box-shadow: 0 20px 50px rgba(16, 24, 40, 0.12);
}

.brand {
  display: flex;
  gap: 14px;
  align-items: center;
  margin-bottom: 20px;
}

.logo {
  width: 48px;
  height: 48px;
  border-radius: 14px;
  background: linear-gradient(135deg, #2563eb, #4f46e5);
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
  color: #6b7280;
}

.submit {
  width: 100%;
}

.error {
  background: #fee2e2;
  color: #b91c1c;
  border-radius: 9px;
  padding: 10px 12px;
  font-size: 13px;
  margin-bottom: 14px;
}

.footer {
  margin-top: 14px;
  text-align: center;
}
</style>
