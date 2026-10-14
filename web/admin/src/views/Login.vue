<template>
  <div class="login-page">
    <div class="login-panel">
      <div class="brand">
        <div class="logo">LT</div>
        <div>
          <h1>LiteTunnel 管理后台</h1>
          <p>仅限管理员访问，本页不应暴露在公网</p>
        </div>
      </div>

      <el-form :model="form" :rules="rules" ref="formRef" label-position="top" @submit.prevent>
        <el-form-item label="管理员账号" prop="username">
          <el-input v-model="form.username" size="large" :prefix-icon="User" placeholder="请输入管理员账号" />
        </el-form-item>
        <el-form-item label="密码" prop="password">
          <el-input
            v-model="form.password"
            type="password"
            size="large"
            show-password
            :prefix-icon="Lock"
            placeholder="请输入密码"
            @keyup.enter="submit"
          />
        </el-form-item>
        <el-button type="primary" size="large" style="width: 100%" :loading="loading" @click="submit">
          登录
        </el-button>
      </el-form>

      <el-alert
        type="warning"
        :closable="false"
        show-icon
        style="margin-top: 18px"
        title="安全提示"
        description="所有登录与操作都会写入审计日志。请通过本机反代或 VPN 访问本页面。"
      />
    </div>
  </div>
</template>

<script setup>
import { reactive, ref } from 'vue'
import { useRouter } from 'vue-router'
import { ElMessage } from 'element-plus'
import { User, Lock } from '@element-plus/icons-vue'
import { authApi, TOKEN_KEY } from '../api'

const router = useRouter()
const formRef = ref()
const loading = ref(false)
const form = reactive({ username: '', password: '' })

const rules = {
  username: [{ required: true, message: '请输入管理员账号', trigger: 'blur' }],
  password: [{ required: true, message: '请输入密码', trigger: 'blur' }]
}

async function submit() {
  await formRef.value.validate()
  loading.value = true
  try {
    const data = await authApi.login({ ...form })
    localStorage.setItem(TOKEN_KEY, data.token)
    ElMessage.success('登录成功')
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
  background: radial-gradient(1000px 500px at 15% 0%, #1e293b 0%, transparent 60%), #0b1220;
}

.login-panel {
  width: 100%;
  max-width: 420px;
  background: #fff;
  border-radius: 18px;
  padding: 32px 30px 26px;
  box-shadow: 0 24px 60px rgba(0, 0, 0, 0.35);
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
  background: linear-gradient(135deg, #0f172a, #334155);
  color: #fff;
  font-weight: 700;
  display: flex;
  align-items: center;
  justify-content: center;
}

.brand h1 {
  margin: 0;
  font-size: 18px;
}

.brand p {
  margin: 4px 0 0;
  font-size: 12px;
  color: #6b7280;
}
</style>
