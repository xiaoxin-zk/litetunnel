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
        </div>
      </div>

      <div class="actions">
        <button class="btn-ghost" :disabled="busy" @click="refresh">同步配置</button>
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
          <span class="muted" v-if="state.traffic_quota > 0">
            流量 {{ fmtBytes(state.traffic_used) }} / {{ fmtBytes(state.traffic_quota) }}
          </span>
          <span class="muted" v-else>流量 {{ fmtBytes(state.traffic_used) }}</span>
        </div>

        <div v-if="state.exceeded" class="exceeded">
          流量额度已用尽，隧道无法建立新连接。请在控制台兑换或联系管理员。
        </div>

        <div v-if="!state.tunnels.length" class="empty">
          还没有隧道。请到控制台创建后点击「同步配置」。
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

    <!-- 底部 -->
    <footer class="footer">
      <label class="switch">
        <input type="checkbox" :checked="state.auto_start" @change="toggleAutoStart($event.target.checked)" />
        <span>启动客户端后自动连接</span>
      </label>
      <div class="footer-right">
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
  logs: { type: Array, default: () => [] }
})
const emit = defineEmits(['update'])

const busy = ref(false)
const message = ref('')
const messageType = ref('ok')
const logBox = ref()

const statusText = computed(() => {
  if (props.state.running) return '已连接，隧道正在运行'
  if (props.state.exceeded) return '流量已用尽'
  return '未连接'
})

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
</style>
