<template>
  <div class="layout">
    <!-- 顶栏 -->
    <header class="header card">
      <div class="status">
        <span class="dot" :class="dotClass"></span>
        <div>
          <div class="status-text">{{ statusText }}</div>
          <div class="muted">
            {{ state.gateway_host || '-' }}:{{ state.gateway_port || '-' }}
            <template v-if="state.username"> · {{ state.username }}</template>
          </div>
          <div class="muted" :class="{ 'sync-warn': state.sync_err }">{{ syncText }}</div>
        </div>
      </div>

      <div class="actions">
        <button class="btn-ghost" :disabled="busy" @click="refresh">立即同步</button>
        <button v-if="!state.running" class="btn-primary" :disabled="busy || !state.frpc_found" @click="start">
          启动连接
        </button>
        <button v-else class="btn-danger" :disabled="busy" @click="stop">断开连接</button>
        <button class="btn-ghost" @click="logout">退出登录</button>
      </div>
    </header>

    <div v-if="message" class="banner" :class="messageType">{{ message }}</div>
    <div v-if="!state.frpc_found" class="banner warn">
      未找到 frpc 可执行文件。请将 <b>frpc.exe</b> 放到程序同目录后重新打开客户端。
    </div>

    <div class="body">
      <!-- 隧道列表 -->
      <section class="card tunnels">
        <div class="card-head">
          <span>隧道（{{ state.tunnels.length }}）</span>
          <div class="head-actions">
            <span class="muted" v-if="state.traffic_quota > 0">
              流量 {{ fmtBytes(state.traffic_used) }} / {{ fmtBytes(state.traffic_quota) }}
            </span>
            <span class="muted" v-else>流量 {{ fmtBytes(state.traffic_used) }}</span>
            <button class="btn-ghost mini" @click="openRedeem">兑换码</button>
            <button class="btn-primary mini" :disabled="atTunnelLimit" @click="openCreate">新建隧道</button>
          </div>
        </div>

        <div v-if="state.exceeded" class="exceeded">
          流量额度已用尽，隧道无法建立新连接。可使用兑换码增加额度，或联系管理员。
        </div>

        <!-- 分组限制提示：提前告知，避免用户填完表单才被拒 -->
        <div v-if="groupHint" class="muted" style="margin-bottom: 10px">{{ groupHint }}</div>

        <div v-if="!state.tunnels.length" class="empty">
          还没有隧道。点右上角「新建隧道」，填一个本机服务的端口即可——
          <b>公网端口由服务端自动分配</b>，不需要自己挑。
        </div>

        <div v-for="t in state.tunnels" :key="t.id" class="tunnel">
          <div class="tunnel-main">
            <div class="tunnel-name">
              {{ t.name }}
              <span class="tag" :class="tagClass(t)">{{ tagText(t) }}</span>
            </div>
            <div class="muted">
              本地 <span class="mono">{{ t.local_ip }}:{{ t.local_port }}</span>
              ·
              {{ t.type.toUpperCase() }}
              <template v-if="t.bandwidth_limit_str"> · 限速 {{ t.bandwidth_limit_str }}</template>
            </div>
          </div>

          <div class="tunnel-addr">
            <span class="mono">{{ t.public_addr || '—' }}</span>
            <button v-if="t.public_addr" class="btn-ghost mini" @click="copy(t.public_addr)">复制</button>
            <button class="btn-ghost mini" :disabled="busy" @click="toggleTunnel(t)">
              {{ t.status === 'active' ? '停用' : '启用' }}
            </button>
            <button class="btn-ghost mini danger" :disabled="busy" @click="removeTunnel(t)">删除</button>
          </div>
        </div>
      </section>

      <!-- 日志 -->
      <section class="card logs">
        <div class="card-head">
          <span>运行日志</span>
          <div class="head-actions">
            <button class="btn-ghost mini" @click="clearLogs">清空</button>
          </div>
        </div>
        <div ref="logBox" class="log-box">
          <div v-if="!logs.length" class="muted">暂无日志，启动连接后这里会显示 frpc 的输出。</div>
          <div v-for="(line, i) in logs" :key="i" class="log-line">{{ line }}</div>
        </div>
      </section>
    </div>

    <!-- ============ 新建隧道 ============ -->
    <div v-if="createOpen" class="modal" @click.self="createOpen = false">
      <div class="modal-card">
        <div class="modal-title">新建隧道</div>

        <label class="field">
          <span>隧道名称</span>
          <input v-model="form.name" placeholder="例如 mc-server（仅字母数字与 -_）" spellcheck="false" />
        </label>

        <label class="field">
          <span>协议</span>
          <select v-model="form.type">
            <option v-for="p in allowedProtocols" :key="p" :value="p">{{ protocolLabel(p) }}</option>
          </select>
        </label>

        <label class="field">
          <span>本机端口</span>
          <input v-model.number="form.localPort" type="number" min="1" max="65535" placeholder="例如 Minecraft 填 25565" />
          <em class="muted">你的服务在本机监听的端口</em>
        </label>

        <label class="field">
          <span>本机地址</span>
          <input v-model="form.localIp" placeholder="127.0.0.1" spellcheck="false" />
          <em class="muted">通常填 127.0.0.1；服务在别的机器上时填它的局域网 IP</em>
        </label>

        <!-- 远程端口默认自动分配，放在「高级」里避免干扰 -->
        <label class="switch-line">
          <input type="checkbox" v-model="showAdvanced" />
          <span>我想指定公网端口</span>
        </label>
        <label v-if="showAdvanced" class="field">
          <span>公网端口</span>
          <input v-model.number="form.remotePort" type="number" min="1" max="65535" placeholder="留空则自动分配" />
          <em class="muted">留空或填 0 由服务端从端口池自动分配</em>
        </label>

        <div v-if="dialogError" class="error">{{ dialogError }}</div>

        <div class="modal-actions">
          <button class="btn-ghost" @click="createOpen = false">取消</button>
          <button class="btn-primary" :disabled="busy" @click="submitCreate">
            {{ busy ? '创建中…' : '创建' }}
          </button>
        </div>
      </div>
    </div>

    <!-- ============ 兑换码 ============ -->
    <div v-if="redeemOpen" class="modal" @click.self="redeemOpen = false">
      <div class="modal-card">
        <div class="modal-title">使用兑换码</div>

        <label class="field">
          <span>兑换码</span>
          <input
            v-model="redeemCode"
            placeholder="LT-XXXX-XXXX-XXXX"
            spellcheck="false"
            autocomplete="off"
            @keyup.enter="submitRedeem"
          />
          <em class="muted">可从管理员处获得，用于增加流量额度或提升分组</em>
        </label>

        <div v-if="dialogError" class="error">{{ dialogError }}</div>

        <div class="modal-actions">
          <button class="btn-ghost" @click="redeemOpen = false">取消</button>
          <button class="btn-primary" :disabled="busy" @click="submitRedeem">
            {{ busy ? '兑换中…' : '兑换' }}
          </button>
        </div>
      </div>
    </div>

    <!-- 底部 -->
    <footer class="footer">
      <label class="switch">
        <input type="checkbox" :checked="state.auto_start" @change="toggleAutoStart($event.target.checked)" />
        <span>启动客户端后自动连接</span>
      </label>
      <div class="footer-right">
        <!-- 版本号常驻显示：出问题时第一件事就是确认「跑的是哪个版本」，
             藏进关于页反而多一步。 -->
        <span class="muted mono" v-if="state.version">{{ state.version }}</span>
        <span class="muted mono" v-if="state.config_path">{{ state.config_path }}</span>
        <button class="btn-ghost mini" @click="openDataDir">打开数据目录</button>
      </div>
    </footer>
  </div>
</template>

<script setup>
import { computed, nextTick, ref, watch } from 'vue'
import { api } from '../bridge'

const props = defineProps({
  state: { type: Object, required: true },
  logs: { type: Array, default: () => [] },
  // 主进程推送的轻提示，例如「检测到配置变更，已自动同步并重新连接」
  notice: { type: Object, default: null }
})
const emit = defineEmits(['update'])

const busy = ref(false)
const message = ref('')
const messageType = ref('ok')
const logBox = ref()

// ---- 新建隧道 ----
const createOpen = ref(false)
const showAdvanced = ref(false)
const dialogError = ref('')
const form = ref({ name: '', type: 'tcp', localIp: '127.0.0.1', localPort: null, remotePort: null })

// ---- 兑换码 ----
const redeemOpen = ref(false)
const redeemCode = ref('')

/** 分组允许的协议。服务端没下发分组时按全放行处理（老版本服务端的兼容）。 */
const allowedProtocols = computed(() => {
  const raw = props.state.group?.allow_protocols
  if (!raw) return ['tcp', 'udp', 'http', 'https']
  return String(raw)
    .split(',')
    .map((s) => s.trim().toLowerCase())
    .filter(Boolean)
})

const protocolLabel = (p) => ({ tcp: 'TCP', udp: 'UDP', http: 'HTTP（网站）', https: 'HTTPS（网站）' }[p] || p.toUpperCase())

/** 分组限制提示。为空表示不限，不显示。 */
const groupHint = computed(() => {
  const g = props.state.group
  if (!g) return ''
  const parts = []
  if (g.max_tunnels > 0) parts.push(`最多 ${g.max_tunnels} 条隧道`)
  if (g.bandwidth_limit_str) parts.push(`单隧道限速 ${g.bandwidth_limit_str}`)
  if (parts.length === 0) return ''
  return `当前分组「${g.name || '默认'}」：${parts.join('，')}`
})

/** 是否已达隧道数量上限。提前禁用按钮，避免用户填完才被拒。 */
const atTunnelLimit = computed(() => {
  const max = props.state.group?.max_tunnels
  if (!max || max <= 0) return false
  return props.state.tunnels.length >= max
})

function openCreate() {
  dialogError.value = ''
  showAdvanced.value = false
  // 协议默认选分组允许的第一个，避免默认值恰好不被允许
  form.value = {
    name: '',
    type: allowedProtocols.value[0] || 'tcp',
    localIp: '127.0.0.1',
    localPort: null,
    remotePort: null
  }
  createOpen.value = true
}

async function submitCreate() {
  dialogError.value = ''
  const f = form.value

  if (!f.name || !/^[A-Za-z0-9_-]{1,64}$/.test(f.name.trim())) {
    dialogError.value = '隧道名称仅允许 1-64 位字母、数字、下划线或连字符'
    return
  }
  if (!f.localPort || f.localPort < 1 || f.localPort > 65535) {
    dialogError.value = '请填写 1-65535 之间的本机端口'
    return
  }
  if (!allowedProtocols.value.includes(f.type)) {
    dialogError.value = `当前分组不允许 ${f.type.toUpperCase()} 协议`
    return
  }

  busy.value = true
  try {
    // remotePort 不填就不传（0 = 交给服务端自动分配）
    const next = await api.createTunnel(
      f.name.trim(),
      f.type,
      (f.localIp || '127.0.0.1').trim(),
      Number(f.localPort),
      showAdvanced.value ? Number(f.remotePort) || 0 : 0
    )
    emit('update', next)
    createOpen.value = false
    flash('隧道已创建，公网端口由服务端自动分配')
  } catch (e) {
    dialogError.value = typeof e === 'string' ? e : e?.message || '创建失败'
  } finally {
    busy.value = false
  }
}

async function toggleTunnel(t) {
  busy.value = true
  try {
    const next = await api.setTunnelStatus(t.id, t.status === 'active' ? 'disabled' : 'active')
    emit('update', next)
    flash(t.status === 'active' ? '隧道已停用，端口已收回' : '隧道已启用')
  } catch (e) {
    flash(typeof e === 'string' ? e : e?.message || '操作失败', 'warn')
  } finally {
    busy.value = false
  }
}

async function removeTunnel(t) {
  if (!window.confirm(`确定删除隧道「${t.name}」吗？\n删除后公网端口会被收回，正在使用该地址的人将无法连接。`)) {
    return
  }
  busy.value = true
  try {
    const next = await api.deleteTunnel(t.id)
    emit('update', next)
    flash('隧道已删除')
  } catch (e) {
    flash(typeof e === 'string' ? e : e?.message || '删除失败', 'warn')
  } finally {
    busy.value = false
  }
}

function openRedeem() {
  dialogError.value = ''
  redeemCode.value = ''
  redeemOpen.value = true
}

async function submitRedeem() {
  dialogError.value = ''
  const code = redeemCode.value.trim()
  if (!code) {
    dialogError.value = '请输入兑换码'
    return
  }

  busy.value = true
  try {
    const [msg, next] = await api.redeem(code)
    emit('update', next)
    redeemOpen.value = false
    // 服务端返回的文案已经区分了类型（流量 / 余额 / 分组），直接用它，
    // 在客户端里猜类型容易说错。
    flash(msg || '兑换成功')
  } catch (e) {
    dialogError.value = typeof e === 'string' ? e : e?.message || '兑换失败，请检查兑换码'
  } finally {
    busy.value = false
  }
}



const statusText = computed(() => {
  if (props.state.running) return '已连接，隧道正在运行'
  if (props.state.exceeded) return '流量已用尽'
  return '未连接'
})

/** 同步状态文案。让用户确信「网页端改的东西客户端已经跟上了」。 */
const syncText = computed(() => {
  if (props.state.sync_err) return `自动同步异常：${props.state.sync_err}`
  if (!props.state.last_sync_at) return '尚未同步'
  const d = new Date(props.state.last_sync_at)
  if (Number.isNaN(d.getTime())) return '已同步'
  const p = (n) => String(n).padStart(2, '0')
  return `每 20 秒自动同步 · 上次 ${p(d.getHours())}:${p(d.getMinutes())}:${p(d.getSeconds())}`
})

// 自动同步在配置变化时会重启 frpc，必须让用户知道原因，
// 否则「连接闪了一下」会被当成故障。
watch(
  () => props.notice,
  (n) => {
    if (n?.text) flash(n.text)
  }
)

const dotClass = computed(() => {
  if (props.state.running) return 'on'
  if (props.state.exceeded) return 'err'
  return 'off'
})

function tagText(t) {
  if (t.status !== 'active') return '已停用'
  return t.online ? '在线' : '等待连接'
}

function tagClass(t) {
  if (t.status !== 'active') return 'tag-info'
  return t.online ? 'tag-success' : 'tag-warn'
}

function fmtBytes(bytes) {
  const b = Number(bytes || 0)
  if (!b) return '0 B'
  const units = ['B', 'KB', 'MB', 'GB', 'TB']
  let i = 0
  let v = b
  while (v >= 1024 && i < units.length - 1) {
    v /= 1024
    i++
  }
  return `${v.toFixed(i === 0 ? 0 : 2)} ${units[i]}`
}

function flash(text, type = 'ok') {
  message.value = text
  messageType.value = type
  setTimeout(() => {
    if (message.value === text) message.value = ''
  }, 4000)
}

async function run(fn, successText) {
  busy.value = true
  try {
    const next = await fn()
    emit('update', next)
    if (successText) flash(successText)
  } catch (e) {
    flash(typeof e === 'string' ? e : e?.message || '操作失败', 'warn')
  } finally {
    busy.value = false
  }
}

const refresh = () => run(() => api.refresh(), '配置已同步')
const start = () => run(() => api.start(), '已启动连接')
const stop = () => run(() => api.stop(), '已断开连接')
const logout = () => run(() => api.logout())

async function clearLogs() {
  await api.clearLogs()
  emit('update')
  flash('日志已清空')
}

async function toggleAutoStart(checked) {
  await api.setAutoStart(checked)
  emit('update')
}

async function openDataDir() {
  await api.openDataDir()
}

async function copy(text) {
  try {
    await navigator.clipboard.writeText(text)
    flash('已复制到剪贴板')
  } catch {
    flash('复制失败，请手动复制', 'warn')
  }
}

// 日志自动滚到底部。
watch(
  () => props.logs.length,
  async () => {
    await nextTick()
    if (logBox.value) logBox.value.scrollTop = logBox.value.scrollHeight
  }
)
</script>

<style scoped>
.layout {
  height: 100%;
  display: flex;
  flex-direction: column;
  padding: 16px;
  gap: 12px;
}

.header {
  display: flex;
  align-items: center;
  justify-content: space-between;
  padding: 14px 18px;
  flex-shrink: 0;
}

.status {
  display: flex;
  align-items: center;
  gap: 12px;
}

.dot {
  width: 11px;
  height: 11px;
  border-radius: 50%;
  flex-shrink: 0;
}

.dot.on {
  background: #22c55e;
  box-shadow: 0 0 0 4px rgba(34, 197, 94, 0.16);
}

.dot.off {
  background: #cbd5e1;
  box-shadow: 0 0 0 4px rgba(203, 213, 225, 0.2);
}

.dot.err {
  background: #ef4444;
  box-shadow: 0 0 0 4px rgba(239, 68, 68, 0.16);
}

.status-text {
  font-weight: 600;
  font-size: 14.5px;
}

.actions {
  display: flex;
  gap: 8px;
}

.banner {
  padding: 10px 14px;
  border-radius: 10px;
  font-size: 13px;
  flex-shrink: 0;
}

.banner.ok {
  background: #dcfce7;
  color: #15803d;
}

.banner.warn {
  background: #fef3c7;
  color: #b45309;
}

.body {
  flex: 1;
  display: grid;
  grid-template-columns: 1.15fr 1fr;
  gap: 12px;
  min-height: 0;
}

.card-head {
  display: flex;
  align-items: center;
  justify-content: space-between;
  padding: 13px 16px;
  border-bottom: 1px solid #eef1f6;
  font-weight: 600;
  font-size: 14px;
}

.head-actions {
  display: flex;
  gap: 6px;
}

.tunnels,
.logs {
  display: flex;
  flex-direction: column;
  min-height: 0;
  overflow: hidden;
}

.exceeded {
  margin: 12px 16px 0;
  background: #fee2e2;
  color: #b91c1c;
  padding: 9px 12px;
  border-radius: 9px;
  font-size: 12.5px;
}

.empty {
  padding: 30px 16px;
  text-align: center;
  color: #9ca3af;
  font-size: 13px;
}

.tunnel {
  display: flex;
  align-items: center;
  justify-content: space-between;
  gap: 12px;
  padding: 13px 16px;
  border-bottom: 1px solid #f3f5f9;
}

.tunnel:last-child {
  border-bottom: none;
}

.tunnel-name {
  font-weight: 600;
  display: flex;
  align-items: center;
  gap: 8px;
  margin-bottom: 4px;
}

.tunnel-addr {
  display: flex;
  align-items: center;
  gap: 8px;
  flex-shrink: 0;
}

.tunnel-addr .mono {
  font-size: 12.5px;
  color: #334155;
  -webkit-user-select: text;
  user-select: text;
}

.mini {
  padding: 4px 10px;
  font-size: 12px;
  border-radius: 7px;
}

.log-box {
  flex: 1;
  overflow-y: auto;
  padding: 12px 14px;
  background: #0b1220;
  color: #cbd5e1;
  font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace;
  font-size: 12px;
  line-height: 1.75;
  -webkit-user-select: text;
  user-select: text;
}

.log-line {
  white-space: pre-wrap;
  word-break: break-all;
}

.footer {
  display: flex;
  align-items: center;
  justify-content: space-between;
  flex-shrink: 0;
  padding: 0 4px;
}

.switch {
  display: flex;
  align-items: center;
  gap: 8px;
  font-size: 13px;
  color: #475569;
  cursor: pointer;
}

.switch input {
  width: 15px;
  height: 15px;
  accent-color: #2563eb;
}

.footer-right {
  display: flex;
  align-items: center;
  gap: 10px;
}

.footer-right .mono {
  max-width: 320px;
  overflow: hidden;
  text-overflow: ellipsis;
  white-space: nowrap;
}
/* 同步异常时用暖色提示，但不用红色报错样式：
   网络抖动是常态，每 20 秒闪一次红色会让人以为坏了。 */
.sync-warn {
  color: #b45309;
}

/* ---- 弹层（新建隧道 / 兑换码）---- */

.modal {
  position: fixed;
  inset: 0;
  background: rgba(15, 23, 42, 0.45);
  display: flex;
  align-items: center;
  justify-content: center;
  padding: 24px;
  z-index: 50;
}

.modal-card {
  width: 100%;
  max-width: 420px;
  background: #fff;
  border-radius: 14px;
  padding: 22px 22px 18px;
  box-shadow: 0 24px 60px rgba(15, 23, 42, 0.28);
  max-height: 90vh;
  overflow-y: auto;
}

.modal-title {
  font-size: 16px;
  font-weight: 600;
  color: #0f172a;
  margin-bottom: 16px;
}

.modal-actions {
  display: flex;
  justify-content: flex-end;
  gap: 8px;
  margin-top: 18px;
}

.field {
  display: block;
  margin-bottom: 14px;
}

.field > span {
  display: block;
  font-size: 13px;
  font-weight: 500;
  margin-bottom: 6px;
  color: #374151;
}

.field input,
.field select {
  width: 100%;
  padding: 9px 12px;
  border: 1px solid #d1d5db;
  border-radius: 9px;
  font-size: 13.5px;
  color: #0f172a;
  background: #fff;
  outline: none;
  box-sizing: border-box;
}

.field input:focus,
.field select:focus {
  border-color: #2563eb;
}

.field em {
  display: block;
  margin-top: 5px;
  font-style: normal;
}

.switch-line {
  display: flex;
  align-items: center;
  gap: 8px;
  font-size: 13px;
  color: #4b5563;
  margin-bottom: 14px;
  cursor: pointer;
}

/* 弹层内的错误提示。用后代选择器限定作用域，
   避免与页面其他位置的 .error 互相影响。 */
.modal-card .error {
  background: #fee2e2;
  color: #b91c1c;
  border-radius: 9px;
  padding: 10px 12px;
  font-size: 13px;
  line-height: 1.6;
  margin-bottom: 4px;
}

.btn-ghost.danger {
  color: #b91c1c;
  border-color: #fecaca;
}

.btn-ghost.danger:hover {
  background: #fef2f2;
}

/* 隧道地址行现在最多有四个按钮（复制/启停/删除），
   窄窗口下允许换行，避免把地址挤没。 */
.tunnel-addr {
  flex-wrap: wrap;
  justify-content: flex-end;
}
</style>
