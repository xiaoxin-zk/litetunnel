<template>
  <div class="app">
    <transition name="fade" mode="out-in">
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
  // 日志代次也要有初值：退出登录时会拿服务端的值来对齐本端，
  // 缺字段的话第一次比较拿到的是 undefined，判断会落到「无变化」分支上。
  log_epoch: 0,
  // 状态排序键的初值（见 seenAuthGen 的说明）。缺了它们，
  // stateIsStale 会把首帧的 auth_gen/state_seq 当成 undefined。
  auth_gen: 0,
  state_seq: 0
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

// 已接受状态的排序键 (auth_gen, state_seq)。
//
// # 为什么不能只靠 stateSeq（上面那个）
//
// 那个 stateSeq 只用于「让在途的 loadState 失效」，它挡不住**事件**乱序：
// 退出登录时主进程会先推一份 logged_in=false，而某个隧道进程的退出回调
// 可能在登出**之后**才取号并再推一份 logged_in=true —— 序号更大，前端
// 照单全收，界面在用户已经退出后又闪回一次已登录。
//
// 主进程为此在每份状态里带了 (auth_gen, state_seq)（见 State.AuthGen /
// State.StateSeq）：auth_gen 是账号代次，登出与接入都会让它前进。比较规则
// 就是字典序——
//   - auth_gen 更小：整份丢弃。它属于上一个账号，序号再大也是旧内容；
//   - auth_gen 相等：再比 state_seq，更小则丢弃；
//   - auth_gen 更大：接受，序号基线随新账号重来。
//
// 这样「旧账号的迟到事件」无论何时到达都进不来，而不是靠运气赶在登出推送
// 之前。初值用 -1 而不是 0：首次收到的状态可能是 gen=0、seq=1，用 0 做初值
// 会让「gen=0 且 seq=0」这种极端情况被误判成重复。
let seenAuthGen = -1
let seenStateSeq = -1

// stateIsStale 判断一份状态是否比已经接受的更旧（见上面 seenAuthGen 的说明）。
function stateIsStale(next) {
  const gen = typeof next.auth_gen === 'number' ? next.auth_gen : 0
  const seq = typeof next.state_seq === 'number' ? next.state_seq : 0
  if (gen !== seenAuthGen) return gen < seenAuthGen
  return seq < seenStateSeq
}

// markStateSeen 记下已接受状态的排序键。
function markStateSeen(next) {
  const gen = typeof next.auth_gen === 'number' ? next.auth_gen : 0
  const seq = typeof next.state_seq === 'number' ? next.state_seq : 0
  seenAuthGen = gen
  seenStateSeq = seq
}

// wasLoggedIn 记住上一次看到的登录态，用来识别「已登录 → 未登录」这一次跳变。
//
// 只看当前的 logged_in 是不够的：退出登录之后前端会立刻收到一份未登录的
// 状态，而页面上那批日志属于**刚退出的那个账号**；等新账号接入时它就会
// 出现在新账号的日志区里。登录态由真变假这个瞬间是唯一能可靠判断
// 「该把日志一起丢掉」的时机。
let wasLoggedIn = false

// applyState 提交一份新状态，并在登录态由真变假时丢弃本端日志。
//
// 所有写入 state 的路径都必须走它（快照、事件、组件回传），否则总有
// 一条路径能把旧账号的日志带进新账号：例如 MainView 里的 logout 是走
// @update 回传状态的，那条路径并不经过 'state' 事件。
function applyState(next) {
  if (!next) return
  // 排序键过滤：比已接受的更旧就直接丢弃（见 seenAuthGen 的说明）。
  //
  // 放在这里而不是只放在 'state' 事件回调里：快照（loadState）、事件、
  // 组件 @update 回传三条路径都会写 state，任何一条漏掉都能把旧状态带回来。
  if (stateIsStale(next)) return
  markStateSeen(next)
  const wasIn = wasLoggedIn
  wasLoggedIn = !!next.logged_in
  state.value = next
  if (wasIn && !wasLoggedIn) {
    discardLogsForLogout(next.log_epoch)
  }
}

// discardLogsForLogout 清空前端这一层的日志，并把代次对齐到服务端。
//
// 主进程在退出登录时已经清空了缓冲、递增了代次，但前端这份 logs 数组
// 与待合并队列都还在。代次必须**取服务端的值**而不是本地自增：清空是
// 主进程做的，本地自增可能与真实代次差开一位，此后每一批日志都会被
// 判成「旧代次」而整批丢弃——日志区就再也不动了。
//
// 序号基线一并归零：新代次的第一行序号未必接着上一代。
function discardLogsForLogout(epoch) {
  // 使在途的 loadLogs 失效：旧快照不该在登出之后重新冒回来。
  logSeq++
  if (typeof epoch === 'number') {
    logEpoch.value = epoch
  } else {
    // 万一主进程没带这个字段（旧版），至少保证本端代次前进：
    // 否则迟到的旧批次代次相等，会被当成有效内容放进来。
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
  if (disposed) return
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
    // clearTimeout 只拦得住「还没进队列」的回调；已经进入队列的会在卸载
    // 之后照常执行，这里再挡一次。
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

// 打开数据目录。失败原因由主进程带回（见 App.OpenDataDir），
// 这里原样抛出，交给 MainView 的统一命令执行去提示——不吞掉。
async function onOpenDataDir() {
  await api.openDataDir()
}

// 事件取消函数必须保存：热重载或组件重复挂载时，不注销就会累积多个同名
// 监听。日志表面上看不出问题（序号去重会挡掉重复行），但同一批行会被处理
// 多遍；更麻烦的是上一次挂载留下的回调仍持有旧的 ref，写进一个已经没人看的
// 组件实例，表现为「改了却不生效」这类无法复现的现象。
const unsubscribes = []

// disposed 在卸载后置位。
//
// 注销与 clearTimeout 都是「尽力而为」：Wails 按事件名注销，已在派发中的
// 回调仍会执行；timer 也可能已经进入了回调队列。置位之后所有入口先看一眼，
// 迟到的写操作直接丢弃——否则热重载时旧组件实例仍会被写入。
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
  // 先注册事件、再读快照：反过来的话，两次 await 之间主进程推送的状态
  // 和日志会被丢掉——它们不属于任何快照，只能靠事件到达。
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
      // 注销失败不该影响卸载；下一次挂载会重新订阅。
    }
  }

  // 合并缓冲的定时器也要停：200ms 后的回调闭包仍持有本组件的 ref，
  // 热重载或重复挂载后它会往一个已经没人看的实例里写日志。
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

.fade-enter-active,
.fade-leave-active {
  transition: opacity 0.18s ease;
}

.fade-enter-from,
.fade-leave-to {
  opacity: 0;
}
</style>
