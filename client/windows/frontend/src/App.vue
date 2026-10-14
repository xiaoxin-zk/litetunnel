<template>
  <div class="app">
    <transition name="fade" mode="out-in">
      <LoginView v-if="!state.logged_in" :initial-server="state.server_url" @logged-in="onLoggedIn" />
      <MainView v-else :state="state" :logs="logs" @update="onUpdate" />
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
  running: false
})
const logs = ref([])

async function loadState() {
  state.value = await api.getState()
}

async function loadLogs() {
  logs.value = await api.logs()
}

function onLoggedIn(next) {
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
