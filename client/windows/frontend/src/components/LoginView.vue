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

      <!-- 服务地址：构建注入时只读展示，未注入时允许手填（仅调试构建） -->
      <label class="field">
        <span>服务地址</span>
        <div v-if="state.server_fixed" class="fixed-server">
          {{ state.server_url || '未配置' }}
        </div>
        <input
          v-else
          v-model="form.server"
          placeholder="例如 https://panel.example.com"
          spellcheck="false"
          autocomplete="off"
          @keyup.enter="submit"
        />
        <em class="muted">
          {{ state.server_fixed ? '由客户端内置，无需填写' : '当前为调试构建，请填写控制台地址' }}
        </em>
      </label>

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
    </div>
  </div>
</template>

<script setup>
import { reactive, ref, watch } from 'vue'
import { api } from '../bridge'

const props = defineProps({
  state: { type: Object, default: () => ({}) }
})
const emit = defineEmits(['connected'])

const loading = ref(false)
const error = ref('')
const form = reactive({ server: '', apiKey: '' })

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

  loading.value = true
  try {
    const next = await api.connect(form.apiKey.trim(), form.server.trim())
    emit('connected', next)
  } catch (e) {
    error.value = typeof e === 'string' ? e : e?.message || '连接失败，请检查 API Key 是否正确'
  } finally {
    loading.value = false
  }
}

// 未注入地址的调试构建下，把上次填过的地址回填出来。
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
