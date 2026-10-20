<template>
  <div class="app">
    <!-- 首帧状态还没回来时先留白，由 index.html 里的启动画面盖着，
         避免先闪一下登录页再切到主界面。 -->
    <div v-if="!ready" class="boot-pad"></div>
    <transition v-else name="fade" mode="out-in">
      <LoginView v-if="!state.logged_in" :state="state" @connected="onConnected" />
      <MainView
        v-else
        :state="state"
        :logs="logs"
        :notice="notice"
        :clear-logs="onClearLogs"
        :open-data-dir="onOpenDataDir"
        @update="onUpdate"
      />
    </transition>
  </div>
</template>

<script setup>
import { onMounted, onUnmounted, ref } from 'vue'
import LoginView from './components/LoginView.vue'
import MainView from './components/MainView.vue'
import { api, onEvent } from './bridge'

const state = ref({
  logged_in: false,
  tunnels: [],
  server_url: '',
  server_fixed: false,
  needs_server_url: false,
  running: false,
  log_epoch: 0,
  auth_gen: 0,
  state_seq: 0
})
const logs = ref([])
const notice = ref(null)
const ready = ref(false)

// 首个状态到达后移除 index.html 里的启动画面。
// 有 4 秒兜底：后端异常时也不能让用户一直看着转圈。
function markReady() {
  if (ready.value) return
  ready.value = true
  const splash = document.getElementById('lt-splash')
  if (!splash) return
  splash.classList.add('lt-hide')
  setTimeout(() => splash.remove(), 260)
}

let stateSeq = 0

let seenAuthGen = -1
let seenStateSeq = -1

function stateIsStale(next) {
  const gen = typeof next.auth_gen === 'number' ? next.auth_gen : 0
  const seq = typeof next.state_seq === 'number' ? next.state_seq : 0
  if (gen !== seenAuthGen) return gen < seenAuthGen
  return seq < seenStateSeq
}

function markStateSeen(next) {
  const gen = typeof next.auth_gen === 'number' ? next.auth_gen : 0
  const seq = typeof next.state_seq === 'number' ? next.state_seq : 0
  seenAuthGen = gen
  seenStateSeq = seq
}

let wasLoggedIn = false

function applyState(next) {
  if (!next) return
  if (stateIsStale(next)) return
  markStateSeen(next)
  const wasIn = wasLoggedIn
  wasLoggedIn = !!next.logged_in
  state.value = next
  // frpc 还在释放时不急着收启动画面：否则会先闪一下「未找到 frpc」的警告条。
  if (next.frpc_found) markReady()
  if (wasIn && !wasLoggedIn) {
    discardLogsForLogout(next.log_epoch)
  }
}

function discardLogsForLogout(epoch) {
  logSeq++
  if (typeof epoch === 'number') {
    logEpoch.value = epoch
  } else {
    logEpoch.value += 1
  }
  pendingLogs.length = 0
  logs.value = []
  lastSeq.value = 0
  if (logTimer) {
    clearTimeout(logTimer)
    logTimer = null
  }
}

async function loadState() {
  const seq = ++stateSeq
  const s = await api.getState()
  if (seq !== stateSeq) return
  applyState(s)
}

const logEpoch = ref(0)
const lastSeq = ref(0)
let logSeq = 0

async function loadLogs() {
  const seq = ++logSeq
  const snap = await api.logs()
  if (seq !== logSeq) return
  if (snap && Array.isArray(snap.lines)) {
    const seqs = snap.seqs || []
    let maxSeq = 0
    for (const s of seqs) {
      if (s > maxSeq) maxSeq = s
    }
    if ((snap.epoch || 0) === logEpoch.value && maxSeq < lastSeq.value) {
      return
    }
    logEpoch.value = snap.epoch || 0
    lastSeq.value = maxSeq
    logs.value = snap.lines
    for (let i = pendingLogs.length - 1; i >= 0; i--) {
      if (pendingLogs[i].seq !== 0 && pendingLogs[i].seq <= maxSeq) {
        pendingLogs.splice(i, 1)
      }
    }
    return
  }
  logs.value = Array.isArray(snap) ? snap : []
}

const pendingLogs = []
const maxPendingLogs = 2000
let logTimer = null

function pushLog(payload) {
  if (disposed) return
  let batch = payload
  let seqs = null
  if (payload && !Array.isArray(payload) && typeof payload === 'object') {
    if (typeof payload.epoch === 'number') {
      if (payload.epoch < logEpoch.value) {
        return // 清空前的在途批次
      }
      if (payload.epoch > logEpoch.value) {
        logEpoch.value = payload.epoch
        pendingLogs.length = 0
        logs.value = []
        lastSeq.value = 0
      }
    }
    batch = payload.lines || []
    seqs = payload.seqs || null
  }
  if (Array.isArray(batch)) {
    for (let i = 0; i < batch.length; i++) {
      const seq = seqs ? seqs[i] : 0
      if (seq !== 0 && seq <= lastSeq.value) continue
      if (seq > lastSeq.value) lastSeq.value = seq
      pendingLogs.push({ seq, text: batch[i] })
    }
  } else if (batch) {
    pendingLogs.push({ seq: 0, text: batch })
  }
  if (pendingLogs.length > maxPendingLogs) {
    pendingLogs.splice(0, pendingLogs.length - maxPendingLogs)
  }
  if (logTimer) return
  logTimer = setTimeout(() => {
    logTimer = null
    if (disposed) return
    const batch = pendingLogs.splice(0, pendingLogs.length)
    if (!batch.length) return
    logs.value = [...logs.value, ...batch.map((item) => item.text)].slice(-500)
  }, 200)
}

function onConnected(next) {
  stateSeq++ // 使在途的 loadState 失效
  applyState(next)
  loadLogs()
}

function onUpdate(next) {
  stateSeq++
  if (next) applyState(next)
  else loadState()
}

async function onClearLogs() {
  logSeq++ // 使在途的 loadLogs 失效：旧快照不该在清空后重新冒回来
  const res = await api.clearLogs()
  if (res && typeof res.epoch === 'number') {
    logEpoch.value = res.epoch
  } else {
    logEpoch.value += 1
  }
  pendingLogs.length = 0
  logs.value = []
  lastSeq.value = 0
}

async function onOpenDataDir() {
  await api.openDataDir()
}

const unsubscribes = []

let disposed = false

function subscribe(name, handler) {
  unsubscribes.push(
    onEvent(name, (payload) => {
      if (disposed) return
      handler(payload)
    })
  )
}

onMounted(async () => {
  disposed = false // 同一模块被重复挂载（热重载）时重新开放
  // 兜底：真的没有 frpc（或后端异常）时也要把界面露出来，不能卡在启动画面。
  setTimeout(markReady, 1500)
  subscribe('state', (payload) => {
    stateSeq++ // 事件状态比任何在途快照都新，让它们失效
    applyState(payload)
  })
  subscribe('logs', pushLog)
  subscribe('log', pushLog)
  subscribe('notice', (msg) => {
    notice.value = { text: msg, at: Date.now() }
  })

  await loadState()
  await loadLogs()
})

onUnmounted(() => {
  disposed = true

  while (unsubscribes.length) {
    const off = unsubscribes.pop()
    try {
      off()
    } catch {
    }
  }

  if (logTimer) {
    clearTimeout(logTimer)
    logTimer = null
  }
  pendingLogs.length = 0
})
</script>

<style scoped>
.app {
  height: 100%;
}

.boot-pad {
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
