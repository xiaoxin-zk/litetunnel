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
  running: false
})
const logs = ref([])
// 主进程推送的轻提示（例如「检测到配置变更，已自动同步并重新连接」）。
//
// 用带时间戳的对象而不是纯字符串：同一条消息连续推送两次时，
// 字符串相等不会触发子组件的 watch，第二次提示就丢了。
const notice = ref(null)

// 快照请求代次：loadState / loadLogs 的异步结果可能晚于登出/重新接入返回。
// 旧账号的慢响应若被放行，会把新账号的状态或日志覆盖掉——登录后短暂闪回
// 上一个账号、或日志混入上一账号的行。只在「没有更新的写入发生」时才提交。
let stateSeq = 0

async function loadState() {
  const seq = ++stateSeq
  const s = await api.getState()
  if (seq !== stateSeq) return
  state.value = s
}

// 日志代次：清空时主进程会递增它，并随每个批次下发。
// 清空前发出、清空后才到达的批次代次更小，直接丢弃——否则用户会看到
// 「刚清空，旧日志又自己回来了」。
const logEpoch = ref(0)
// 已显示的最大日志序号。快照与实时事件可能包含同一行，
// 只比代次会重复追加，必须按序号去重。
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
    // 快照可能比当前已显示的内容旧（请求在途时又来了新日志）：
    // 同代次下不覆盖，避免把新行丢掉。
    if ((snap.epoch || 0) === logEpoch.value && maxSeq < lastSeq.value) {
      return
    }
    logEpoch.value = snap.epoch || 0
    lastSeq.value = maxSeq
    logs.value = snap.lines
    // 快照已经包含这些行：把待合并队列里的同序号项剔掉，否则 200ms 后
    // 计时器会把它们再追加一遍（快照与事件重叠的重复来源）。
    for (let i = pendingLogs.length - 1; i >= 0; i--) {
      if (pendingLogs[i].seq !== 0 && pendingLogs[i].seq <= maxSeq) {
        pendingLogs.splice(i, 1)
      }
    }
    return
  }
  // 兼容旧版主进程：直接返回字符串数组。
  logs.value = Array.isArray(snap) ? snap : []
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
// 待合并队列里的每一项都带序号：快照返回时要把已经被快照覆盖的行剔掉，
// 只留字符串的话分不清哪一行已经在快照里了。
const pendingLogs = []
// 缓冲上限：200 毫秒内涌入的极端量（例如日志被反复重试刷屏）也不至于把
// 内存撑起来。界面本来就只保留最近 500 行，丢掉更早的那部分没有损失。
const maxPendingLogs = 2000
let logTimer = null

function pushLog(payload) {
  // 主进程成批推送 {epoch, seqs, lines}；也接受数组与单行字符串，这样前端
  // 热重载、或与旧版主进程混跑时都不会丢日志。
  let batch = payload
  let seqs = null
  if (payload && !Array.isArray(payload) && typeof payload === 'object') {
    if (typeof payload.epoch === 'number') {
      if (payload.epoch < logEpoch.value) {
        return // 清空前的在途批次
      }
      if (payload.epoch > logEpoch.value) {
        // 主进程已经清空过缓冲（代次前进），而本端还没看到清空回执：
        // 可能是清空请求仍在途中，也可能是热重载后本地状态被重置。
        // 此时手上的旧行都属于上一个代次，留着它们就会与新代次的行混在
        // 一起；而且代次不追赶的话，后面每一批都会按旧代次比较，旧批次
        // 永远拦不住。序号一并归零：新代次的序号基线可能已经不同。
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
      // seq 为 0 的是客户端合成行（如「已丢弃 N 行」），始终显示。
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
    const batch = pendingLogs.splice(0, pendingLogs.length)
    if (!batch.length) return
    logs.value = [...logs.value, ...batch.map((item) => item.text)].slice(-500)
  }, 200)
}

function onConnected(next) {
  stateSeq++ // 使在途的 loadState 失效
  state.value = next
  loadLogs()
}

function onUpdate(next) {
  stateSeq++
  if (next) state.value = next
  else loadState()
}

// 清空日志必须同时清掉**前端这一层**：主进程清完缓冲后，页面上的
// logs 数组如果不动，旧行会一直留在界面上，看起来就像「清空没生效」。
// 待合并队列也要一起丢，否则 200ms 后它会把清空前的行重新补回来。
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

// 事件取消函数必须保存：热重载或组件重复挂载时，不注销就会累积多个同名
// 监听。日志表面上看不出问题（序号去重会挡掉重复行），但同一批行会被处理
// 多遍；更麻烦的是上一次挂载留下的回调仍持有旧的 ref，写进一个已经没人看的
// 组件实例，表现为「改了却不生效」这类无法复现的现象。
const unsubscribes = []

function subscribe(name, handler) {
  unsubscribes.push(onEvent(name, handler))
}

onMounted(async () => {
  // 先注册事件、再读快照：反过来的话，两次 await 之间主进程推送的状态
  // 和日志会被丢掉——它们不属于任何快照，只能靠事件到达。
  subscribe('state', (payload) => {
    stateSeq++ // 事件状态比任何在途快照都新，让它们失效
    state.value = payload
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
  while (unsubscribes.length) {
    const off = unsubscribes.pop()
    try {
      off()
    } catch {
      // 注销失败不该影响卸载；下一次挂载会重新订阅。
    }
  }
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
