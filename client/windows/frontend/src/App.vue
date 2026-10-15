<template>
  <div class="app">
    <transition name="fade" mode="out-in">
      <LoginView v-if="!state.logged_in" :state="state" @connected="onConnected" />
      <MainView v-else :state="state" :logs="logs" :notice="notice" @update="onUpdate" />
    </transition>
  </div>
</template>

<script setup>
import { onMounted, ref } from 'vue'
import LoginView from './components/LoginView.vue'
import MainView from './components/MainView.vue'
import { api, onEvent } from './bridge'

const state = ref({
  logged_in: false,
  tunnels: [],
  server_url: '',
  server_fixed: false,
  needs_server_url: false,
  running: false
})
const logs = ref([])
// 主进程推送的轻提示（例如「检测到配置变更，已自动同步并重新连接」）。
//
// 用带时间戳的对象而不是纯字符串：同一条消息连续推送两次时，
// 字符串相等不会触发子组件的 watch，第二次提示就丢了。
const notice = ref(null)

async function loadState() {
  state.value = await api.getState()
}

async function loadLogs() {
  logs.value = await api.logs()
}

function onConnected(next) {
  state.value = next
  loadLogs()
}

function onUpdate(next) {
  if (next) state.value = next
  else loadState()
}

onMounted(async () => {
  await loadState()
  await loadLogs()

  // 主进程推送的实时状态与日志。
  onEvent('state', (payload) => {
    state.value = payload
  })
  onEvent('log', (line) => {
    logs.value = [...logs.value.slice(-499), line]
  })
  onEvent('notice', (msg) => {
    notice.value = { text: msg, at: Date.now() }
  })
})
</script>

<style scoped>
.app {
  height: 100%;
}

.fade-enter-active,
.fade-leave-active {
  transition: opacity 0.18s ease;
}

.fade-enter-from,
.fade-leave-to {
  opacity: 0;
}
</style>
