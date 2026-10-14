<template>
  <div class="page">
    <div class="panel">
      <div class="brand">
        <div class="logo">LT</div>
        <div>
          <h1>找回密码</h1>
          <p>通过注册邮箱重置登录密码</p>
        </div>
      </div>

      <template v-if="!sent">
        <el-form :model="form" :rules="rules" ref="formRef" label-position="top" @submit.prevent>
          <el-form-item label="用户名或邮箱" prop="account">
            <el-input
              v-model="form.account"
              size="large"
              placeholder="请输入用户名或注册邮箱"
              :prefix-icon="Message"
              @keyup.enter="submit"
            />
          </el-form-item>
          <el-button type="primary" size="large" class="submit" :loading="loading" @click="submit">
            发送重置链接
          </el-button>
        </el-form>

        <el-alert
          v-if="mailEnabled === false"
          type="warning"
          :closable="false"
          show-icon
          style="margin-top: 16px"
          title="站点未启用邮件服务"
          description="当前无法自助找回密码，请联系管理员重置。"
        />
      </template>

      <el-result v-else icon="success" title="请求已提交" :sub-title="sentMessage">
        <template #extra>
          <el-button @click="$router.push('/login')">返回登录</el-button>
        </template>
      </el-result>

      <div class="footer">
        <el-button link @click="$router.push('/login')">返回登录</el-button>
      </div>
    </div>
  </div>
</template>

<script setup>
import { onMounted, reactive, ref } from 'vue'
import { ElMessage } from 'element-plus'
import { Message } from '@element-plus/icons-vue'
import { authApi } from '../api'

const formRef = ref()
const loading = ref(false)
const sent = ref(false)
const sentMessage = ref('')
const mailEnabled = ref(null)
const form = reactive({ account: '' })

const rules = {
  account: [{ required: true, message: '请输入用户名或邮箱', trigger: 'blur' }]
}

async function submit() {
  await formRef.value.validate()
  loading.value = true
  try {
    const data = await authApi.forgotPassword(form.account.trim())
    sentMessage.value = data?.message || '请查收邮件并按提示重置密码'
    sent.value = true
  } catch (e) {
    // 站点未配置邮件时会明确报错，这是配置问题而非账号问题，可以如实提示
    ElMessage.error(e?.response?.data?.message || '提交失败，请稍后重试')
  } finally {
    loading.value = false
  }
}

onMounted(async () => {
  try {
    const data = await authApi.mailStatus()
    mailEnabled.value = !!data?.mail_enabled
  } catch {
    mailEnabled.value = null
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

.footer {
  margin-top: 14px;
  text-align: center;
}
</style>
