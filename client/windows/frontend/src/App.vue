<template>
  <div class="app">
    <transition name="fade" mode="out-in">
      <LoginView v-if="!state.logged_in" :state="state" @connected="onConnected" />
      <MainView
        v-else
        :state="state"
        :logs="logs"
        :notice="notice"
        @update="onUpdate"
        @clearlogs="onClearLogs"
      />
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

// 日志先攒进缓冲，每 200 毫秒合并成一次更新。
//
// frpc 的日志现在输出到 console，一次连接失败可能瞬间刷出上千行。原先每行都
// 执行一次 `logs.value = [...logs.value.slice(-499), line]`——把整个数组重建
// 一遍并触发一次渲染，上千行就是上千次，界面会明显卡住（鼠标划过列表都在卡）。
//
// 合并之后每 200 毫秒只重建一次，日志一条不少，只是显示晚一点点。
//
// 注意这一层**不减少事件数量**：主进程那侧已经按 120 毫秒成批推送（事件
// 「logs」带数组），这里还会再合并一次，是因为多个批次可能在同一个渲染
// 周期内到达——两边各管一段：主进程管跨进程调用的次数，这里管 DOM 更新次数。
const pendingLogs = []
// 缓冲上限：200 毫秒内涌入的极端量（例如日志被反复重试刷屏）也不至于把
// 内存撑起来。界面本来就只保留最近 500 行，丢掉更早的那部分没有损失。
const maxPendingLogs = 2000
let logTimer = null

function pushLog(payload) {
  // 主进程成批推送（数组）；也接受单行字符串，这样前端热重载、或与旧版
  // 主进程混跑时都不会丢日志。
  if (Array.isArray(payload)) {
    for (const line of payload) pendingLogs.push(line)
  } else {
    pendingLogs.push(payload)
  }
  if (pendingLogs.length > maxPendingLogs) {
    pendingLogs.splice(0, pendingLogs.length - maxPendingLogs)
  }
  if (logTimer) return
  logTimer = setTimeout(() => {
    logTimer = null
    const batch = pendingLogs.splice(0, pendingLogs.length)
    if (!batch.length) return
    logs.value = [...logs.value, ...batch].slice(-500)
  }, 200)
}

function onConnected(next) {
  state.value = next
  loadLogs()
}

function onUpdate(next) {
  if (next) state.value = next
  else loadState()
}

// 清空日志必须同时清掉**前端这一层**：主进程清完缓冲后，页面上的
// logs 数组如果不动，旧行会一直留在界面上，看起来就像「清空没生效」。
// 待合并队列也要一起丢，否则 200ms 后它会把清空前的行重新补回来。
async function onClearLogs() {
  await api.clearLogs()
  pendingLogs.length = 0
  logs.value = []
}

onMounted(async () => {
  await loadState()
  await loadLogs()

  // 主进程推送的实时状态与日志。
  onEvent('state', (payload) => {
    state.value = payload
  })
  onEvent('logs', pushLog)
  onEvent('log', pushLog)
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
