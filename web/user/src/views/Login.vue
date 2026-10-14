<template>
  <div class="login-page">
    <div class="login-panel">
      <div class="brand">
        <div class="logo">LT</div>
        <div>
          <h1>LiteTunnel</h1>
          <p>轻量内网穿透 · 游戏联机 · 网站与 NAS 映射</p>
        </div>
      </div>

      <el-tabs v-model="tab" class="tabs">
        <el-tab-pane label="登录" name="login">
          <el-form :model="loginForm" :rules="rules" ref="loginRef" label-position="top" @submit.prevent>
            <el-form-item label="用户名" prop="username">
              <el-input v-model="loginForm.username" size="large" placeholder="请输入用户名" :prefix-icon="User" />
            </el-form-item>
            <el-form-item label="密码" prop="password">
              <el-input
                v-model="loginForm.password"
                type="password"
                size="large"
                show-password
                placeholder="请输入密码"
                :prefix-icon="Lock"
                @keyup.enter="doLogin"
              />
            </el-form-item>
            <el-button type="primary" size="large" class="submit" :loading="loading" @click="doLogin">
              登录
            </el-button>
          </el-form>
        </el-tab-pane>

        <el-tab-pane label="注册" name="register">
          <el-form :model="regForm" :rules="regRules" ref="regRef" label-position="top" @submit.prevent>
            <el-form-item label="用户名" prop="username">
              <el-input v-model="regForm.username" size="large" placeholder="3-32 位字母、数字或下划线" :prefix-icon="User" />
            </el-form-item>
            <el-form-item label="邮箱（选填）" prop="email">
              <el-input v-model="regForm.email" size="large" placeholder="用于找回账号" :prefix-icon="Message" />
            </el-form-item>
            <el-form-item label="密码" prop="password">
              <el-input v-model="regForm.password" type="password" size="large" show-password placeholder="至少 8 位" :prefix-icon="Lock" />
            </el-form-item>
            <el-form-item label="确认密码" prop="confirm">
              <el-input v-model="regForm.confirm" type="password" size="large" show-password placeholder="再次输入密码" :prefix-icon="Lock" />
            </el-form-item>
            <el-button type="primary" size="large" class="submit" :loading="loading" @click="doRegister">
              注册并登录
            </el-button>
          </el-form>
        </el-tab-pane>
      </el-tabs>

      <p class="tip">登录后即可创建隧道、下载客户端并查看实时流量。</p>
    </div>
  </div>
</template>

<script setup>
import { reactive, ref } from 'vue'
import { useRouter } from 'vue-router'
import { ElMessage } from 'element-plus'
import { User, Lock, Message } from '@element-plus/icons-vue'
import { authApi, TOKEN_KEY } from '../api'

const router = useRouter()
const tab = ref('login')
const loading = ref(false)
const loginRef = ref()
const regRef = ref()

const loginForm = reactive({ username: '', password: '' })
const regForm = reactive({ username: '', email: '', password: '', confirm: '' })

const rules = {
  username: [{ required: true, message: '请输入用户名', trigger: 'blur' }],
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
      validator: (_r, value, cb) => {
        if (value !== regForm.password) cb(new Error('两次输入的密码不一致'))
        else cb()
      },
      trigger: 'blur'
    }
  ]
}

async function doLogin() {
  await loginRef.value.validate()
  loading.value = true
  try {
    const data = await authApi.login({ ...loginForm })
    localStorage.setItem(TOKEN_KEY, data.token)
    ElMessage.success('登录成功')
    router.push('/dashboard')
  } finally {
    loading.value = false
  }
}

async function doRegister() {
  await regRef.value.validate()
  loading.value = true
  try {
    await authApi.register({
      username: regForm.username,
      password: regForm.password,
      email: regForm.email
    })
    const data = await authApi.login({ username: regForm.username, password: regForm.password })
    localStorage.setItem(TOKEN_KEY, data.token)
    ElMessage.success('注册成功，欢迎使用')
    router.push('/dashboard')
  } finally {
    loading.value = false
  }
}
</script>

<style scoped>
.login-page {
  min-height: 100vh;
  display: flex;
  align-items: center;
  justify-content: center;
  padding: 24px;
  background: radial-gradient(1200px 600px at 20% 0%, #dbeafe 0%, transparent 60%),
    radial-gradient(900px 500px at 100% 100%, #e0e7ff 0%, transparent 55%), #f5f7fb;
}

.login-panel {
  width: 100%;
  max-width: 420px;
  background: #fff;
  border-radius: 18px;
  padding: 32px 30px 24px;
  box-shadow: 0 20px 50px rgba(16, 24, 40, 0.12);
}

.brand {
  display: flex;
  gap: 14px;
  align-items: center;
  margin-bottom: 8px;
}

.logo {
  width: 48px;
  height: 48px;
  border-radius: 14px;
  background: linear-gradient(135deg, #2563eb, #4f46e5);
  color: #fff;
  font-weight: 700;
  font-size: 18px;
  display: flex;
  align-items: center;
  justify-content: center;
  letter-spacing: 0.5px;
}

.brand h1 {
  margin: 0;
  font-size: 20px;
}

.brand p {
  margin: 4px 0 0;
  font-size: 12px;
  color: #6b7280;
}

.tabs {
  margin-top: 18px;
}

.submit {
  width: 100%;
  margin-top: 6px;
}

.tip {
  margin: 18px 0 0;
  text-align: center;
  font-size: 12px;
  color: #9ca3af;
}
</style>
