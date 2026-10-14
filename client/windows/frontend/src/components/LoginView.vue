<template>
  <div class="page">
    <div class="card panel">
      <div class="brand">
        <div class="logo">LT</div>
        <div>
          <h1>LiteTunnel</h1>
          <p>登录后即可一键连接你的游戏服务器、网站或 NAS</p>
        </div>
      </div>

      <label class="field">
        <span>服务器地址</span>
        <input
          v-model="form.server"
          placeholder="例如 https://tunnel.example.com"
          spellcheck="false"
          autocomplete="off"
          @keyup.enter="submit"
        />
        <em class="muted">填写控制台地址，无需带 /api 路径</em>
      </label>

      <label class="field">
        <span>用户名</span>
        <input v-model="form.username" placeholder="控制台注册的用户名" autocomplete="off" @keyup.enter="submit" />
      </label>

      <label class="field">
        <span>密码</span>
        <input v-model="form.password" type="password" placeholder="登录密码" @keyup.enter="submit" />
      </label>

      <div v-if="error" class="error">{{ error }}</div>

      <button class="btn-primary submit" :disabled="loading" @click="submit">
        {{ loading ? '正在登录…' : '登录并连接' }}
      </button>

      <p class="hint muted">
        客户端仅保存可吊销的接入凭据，不会在本地留存账号密码。
      </p>
    </div>
  </div>
</template>

<script setup>
import { onMounted, reactive, ref } from 'vue'
import { api } from '../bridge'

const props = defineProps({ initialServer: String })
const emit = defineEmits(['logged-in'])

const loading = ref(false)
const error = ref('')
const form = reactive({ server: props.initialServer || '', username: '', password: '' })

async function submit() {
  error.value = ''
  if (!form.server.trim()) {
    error.value = '请填写服务器地址'
    return
  }
  if (!form.username.trim() || !form.password) {
    error.value = '请填写用户名与密码'
    return
  }

  loading.value = true
  try {
    const state = await api.login(form.server.trim(), form.username.trim(), form.password)
    form.password = ''
    emit('logged-in', state)
  } catch (e) {
    error.value = typeof e === 'string' ? e : e?.message || '登录失败，请检查地址与账号'
  } finally {
    loading.value = false
  }
}

onMounted(() => {
  form.server = props.initialServer || ''
})
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
