<template>
  <div class="page">
    <div class="panel">
      <div class="brand">
        <div class="logo">LT</div>
        <div>
          <h1>设置新密码</h1>
          <p>重置后所有已登录设备都会下线</p>
        </div>
      </div>

      <template v-if="!done">
        <el-form :model="form" :rules="rules" ref="formRef" label-position="top" @submit.prevent>
          <el-form-item label="新密码" prop="password">
            <el-input v-model="form.password" type="password" size="large" show-password placeholder="至少 8 位" />
          </el-form-item>
          <el-form-item label="确认密码" prop="confirm">
            <el-input
              v-model="form.confirm"
              type="password"
              size="large"
              show-password
              placeholder="再次输入新密码"
              @keyup.enter="submit"
            />
          </el-form-item>
          <el-button type="primary" size="large" class="submit" :loading="loading" @click="submit">
            确认重置
          </el-button>
        </el-form>

        <el-alert
          v-if="error"
          type="error"
          :closable="false"
          show-icon
          style="margin-top: 16px"
          :title="error"
        />
      </template>

      <el-result v-else icon="success" title="密码已重置" sub-title="所有设备已下线，请用新密码重新登录">
        <template #extra>
          <el-button type="primary" @click="$router.push('/login')">去登录</el-button>
        </template>
      </el-result>
    </div>
  </div>
</template>

<script setup>
import { onMounted, reactive, ref } from 'vue'
import { useRoute } from 'vue-router'
import { authApi } from '../api'

const route = useRoute()
const formRef = ref()
const loading = ref(false)
const done = ref(false)
const error = ref('')
const token = ref('')
const form = reactive({ password: '', confirm: '' })

const rules = {
  password: [
    { required: true, message: '请输入新密码', trigger: 'blur' },
    { min: 8, message: '密码至少 8 位', trigger: 'blur' }
  ],
  confirm: [
    {
      validator: (_r, value, cb) => {
        if (value !== form.password) cb(new Error('两次输入的密码不一致'))
        else cb()
      },
      trigger: 'blur'
    }
  ]
}

async function submit() {
  await formRef.value.validate()
  loading.value = true
  error.value = ''
  try {
    await authApi.resetPassword({ token: token.value, password: form.password })
    done.value = true
  } catch (e) {
    error.value = e?.response?.data?.message || '重置失败，链接可能已失效'
  } finally {
    loading.value = false
  }
}

onMounted(() => {
  token.value = String(route.query.token || '')
  if (!token.value) {
    error.value = '链接缺少令牌参数，请重新申请找回密码'
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
</style>
