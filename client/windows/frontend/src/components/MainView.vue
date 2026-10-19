<template>
  <div class="layout">
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
        <button
          class="btn-ghost"
          :disabled="busy"
          :title="busy ? '正在执行，请稍候' : '停止所有隧道并清除本地凭据'"
          @click="logout"
        >
          退出登录
        </button>
      </div>
    </header>

    <div class="account card">
      <div class="acc">
        <span>账号</span>
        <b>{{ state.username || '—' }}</b>
      </div>
      <div class="acc">
        <span>当前分组</span>
        <b>{{ state.group?.name || '默认' }}</b>
      </div>
      <div class="acc">
        <span>单隧道限速</span>
        <b>{{ state.group?.bandwidth_limit_str || '不限' }}</b>
      </div>
      <div class="acc">
        <span>可用协议</span>
        <b>{{ protocolText }}</b>
      </div>
      <div v-if="httpsEntry" class="acc">
        <span>HTTPS 隧道入口</span>
        <b>{{ httpsEntry }}</b>
      </div>
      <div class="acc">
        <span>隧道数</span>
        <b>
          {{ state.tunnels.length }}<template v-if="maxTunnels"> / {{ maxTunnels }}</template>
        </b>
      </div>
      <div class="acc">
        <span>流量</span>
        <b :class="{ 'acc-err': state.exceeded }">{{ trafficText }}</b>
      </div>
      <div v-if="state.payment_enabled" class="acc">
        <span>余额</span>
        <b>¥ {{ ((state.balance_cents || 0) / 100).toFixed(2) }}</b>
      </div>
    </div>

    <div v-if="message" class="banner" :class="messageType">{{ message }}</div>
    <div v-if="state.config_error" class="banner warn">{{ state.config_error }}</div>
    <div v-if="!state.frpc_found" class="banner warn">
      未找到 frpc 可执行文件。请将 <b>frpc.exe</b> 放到程序同目录后重新打开客户端。
    </div>

    <div class="body">
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

        <div v-if="groupHint" class="muted" style="margin-bottom: 10px">{{ groupHint }}</div>

        <div v-if="!state.tunnels.length" class="empty">
          还没有隧道。点右上角「新建隧道」，填一个本机服务的端口即可——
          <b>公网端口由服务端自动分配</b>，不需要自己挑。
        </div>

        <div v-for="t in state.tunnels" :key="t.id" class="tunnel">
          <div class="tunnel-main">
            <div class="tunnel-name">
              {{ t.name }}
              <span class="tag" :class="tagClass(t)" :title="tagHint(t)">{{ tagText(t) }}</span>
            </div>
            <div class="muted">
              本地 <span class="mono">{{ t.local_ip }}:{{ t.local_port }}</span>
              ·
              {{ t.type.toUpperCase() }}
              <template v-if="t.bandwidth_limit_str"> · 限速 {{ t.bandwidth_limit_str }}</template>
            </div>
            <div v-if="t.last_error" class="tunnel-err">
              {{ t.last_error }}
              <template v-if="t.last_error_at"> · {{ fmtTime(t.last_error_at) }}</template>
            </div>
          </div>

          <div class="tunnel-addr">
            <span class="mono">{{ t.public_addr || '—' }}</span>
            <button v-if="t.public_addr" class="btn-ghost mini" @click="copy(t.public_addr)">复制</button>
            <button
              class="tunnel-toggle"
              :class="{ on: t.running }"
              :disabled="busy || !state.frpc_found"
              :title="t.running ? '断开这条隧道' : '连接这条隧道'"
              @click="toggleTunnel(t)"
            >
              <span class="knob"></span>
            </button>
            <button class="btn-ghost mini danger" :disabled="busy" @click="removeTunnel(t)">删除</button>
          </div>
        </div>
      </section>

      <section class="card logs">
        <div class="card-head">
          <span>运行日志</span>
          <div class="head-actions">
            <button class="btn-ghost mini" @click="handleClearLogs">清空</button>
          </div>
        </div>
        <div ref="logBox" class="log-box">
          <div v-if="!logs.length" class="muted">
            暂无日志。打开某条隧道的开关后，这里会按 Tunnel/&lt;名字&gt; 显示它的连接过程。
          </div>
          <div v-for="(line, i) in logs" :key="i" class="log-line">{{ line }}</div>
        </div>
      </section>
    </div>

    <div v-if="createOpen" class="modal" @click.self="createOpen = false">
      <div class="modal-card">
        <div class="modal-title">{{ createMode === 'batch' ? '批量新建隧道' : '新建隧道' }}</div>

        <div class="mode-switch">
          <label :class="{ on: createMode === 'single' }">
            <input type="radio" value="single" v-model="createMode" />
            <span>单条</span>
          </label>
          <label v-if="!isWebType" :class="{ on: createMode === 'batch' }">
            <input type="radio" value="batch" v-model="createMode" />
            <span>批量（一串端口）</span>
          </label>
        </div>

        <label class="field">
          <span>{{ createMode === 'batch' ? '名称前缀' : '隧道名称' }}</span>
          <input
            v-model="form.name"
            :placeholder="createMode === 'batch' ? '例如 mc，将生成 mc_25565' : '例如 mcserver'"
            spellcheck="false"
          />
          <em v-if="createMode === 'batch'" class="muted">
            每条隧道命名为「前缀_端口」，一眼就能看出对应关系
          </em>
        </label>

        <label class="field">
          <span>协议</span>
          <select v-model="form.type">
            <option v-for="p in allowedProtocols" :key="p" :value="p">{{ protocolLabel(p) }}</option>
          </select>
        </label>

        <label v-if="createMode === 'single'" class="field">
          <span>本机端口</span>
          <input v-model.number="form.localPort" type="number" min="1" max="65535" placeholder="例如 Minecraft 填 25565" />
          <em class="muted">你的服务在本机监听的端口</em>
        </label>

        <label v-else class="field">
          <span>本机端口</span>
          <textarea
            v-model="form.portsText"
            rows="3"
            placeholder="25565-25570&#10;或 25565, 25566, 25567"
            spellcheck="false"
          ></textarea>
          <em class="muted">
            支持范围（25565-25570）与逗号、空格、换行分隔，一次最多 {{ MAX_BATCH }} 条。
            公网端口由服务端自动分配
          </em>
        </label>

        <div class="scan-wrap">
          <button class="btn-ghost mini" :disabled="scanning" @click="toggleScan">
            {{ scanning ? '正在扫描本机服务…' : showScan ? '收起服务列表' : '从本机服务中选择' }}
          </button>
          <span v-if="scanErr" class="scan-err">{{ scanErr }}</span>

          <div v-if="showScan && !scanning" class="scan-list">
            <input
              v-model="scanFilter"
              class="scan-filter"
              placeholder="按端口或进程名过滤"
              spellcheck="false"
            />
            <div v-if="!filteredServices.length" class="scan-empty">
              没找到正在监听的服务。请确认你的服务已经启动，然后重新打开这个列表。
            </div>
            <div
              v-for="s in filteredServices"
              :key="s.proto + ':' + s.port"
              class="scan-item"
              :class="{ rec: s.recommended }"
              @click="pickService(s)"
            >
              <span class="mono scan-port">{{ s.port }}</span>
              <span class="scan-proto">{{ s.proto.toUpperCase() }}</span>
              <span class="scan-proc">{{ s.process || '未知进程' }}</span>
              <span v-if="s.recommended" class="scan-badge">像是你的服务</span>
            </div>
          </div>
        </div>

        <label class="field">
          <span>本机地址</span>
          <input v-model="form.localIp" placeholder="127.0.0.1" spellcheck="false" />
          <em class="muted">通常填 127.0.0.1；服务在别的机器上时填它的局域网 IP</em>
        </label>

        <template v-if="isWebType">
          <label class="field">
            <span>二级域名</span>
            <input v-model="form.subdomain" :placeholder="subdomainPlaceholder" spellcheck="false" />
            <em class="muted">
              访问地址将是 <span class="mono">{{ subdomainPreview }}</span>
            </em>
          </label>
          <div class="https-note">
            <b>HTTPS 自动生效。</b>证书由服务端按域名自动签发，你不需要做任何配置。
          </div>
        </template>

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

    <footer class="footer">
      <div class="footer-right">
        <span class="muted mono" v-if="state.version">{{ state.version }}</span>
        <span class="muted mono" v-if="state.config_path">{{ state.config_path }}</span>
        <button class="btn-ghost mini" @click="handleOpenDataDir">打开数据目录</button>
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
  notice: { type: Object, default: null },
  clearLogs: { type: Function, required: true },
  openDataDir: { type: Function, required: true }
})
const emit = defineEmits(['update'])

const busy = ref(false)
const message = ref('')
const messageType = ref('ok')
const logBox = ref()

const createOpen = ref(false)
const showAdvanced = ref(false)
const dialogError = ref('')
const form = ref({
  name: '',
  type: 'tcp',
  localIp: '127.0.0.1',
  localPort: null,
  portsText: '',
  remotePort: null,
  subdomain: ''
})

const isWebType = computed(() => form.value.type === 'http' || form.value.type === 'https')

const subdomainPlaceholder = computed(() => {
  const d = props.state.tunnel_domain
  return d ? `例如 mc（访问地址将是 mc.${d}）` : '例如 mc'
})

const subdomainPreview = computed(() => {
  const s = (form.value.subdomain || '').trim().toLowerCase()
  if (!s) return '（填写后显示）'
  const d = props.state.tunnel_domain
  return d ? `https://${s}.${d}` : `https://${s}`
})

watch(isWebType, (web) => {
  if (web) createMode.value = 'single'
})

const createMode = ref('single')
const MAX_BATCH = 20

function parsePorts(text) {
  const out = []
  const seen = new Set()
  const push = (p) => {
    if (p >= 1 && p <= 65535 && !seen.has(p)) {
      seen.add(p)
      out.push(p)
    }
  }

  for (const chunk of String(text || '').split(/[\s,，、;；]+/)) {
    if (!chunk) continue
    const m = chunk.match(/^(\d+)\s*-\s*(\d+)$/)
    if (m) {
      const a = Number(m[1])
      const b = Number(m[2])
      if (a > b) continue
      for (let p = a; p <= b && out.length < 200; p++) push(p)
      continue
    }
    if (/^\d+$/.test(chunk)) push(Number(chunk))
  }
  return out
}


const showScan = ref(false)
const scanning = ref(false)
const scanErr = ref('')
const scanFilter = ref('')
const services = ref([])

const filteredServices = computed(() => {
  const q = scanFilter.value.trim().toLowerCase()
  if (!q) return services.value.slice(0, 60)
  return services.value
    .filter((s) => String(s.port).includes(q) || (s.process || '').toLowerCase().includes(q))
    .slice(0, 60)
})

async function toggleScan() {
  if (showScan.value) {
    showScan.value = false
    return
  }
  showScan.value = true
  if (!services.value.length) {
    await scanServices()
  }
}

async function scanServices() {
  scanning.value = true
  scanErr.value = ''
  try {
    services.value = (await api.listLocalServices()) || []
  } catch (e) {
    scanErr.value = typeof e === 'string' ? e : e?.message || '无法读取本机服务列表'
  } finally {
    scanning.value = false
  }
}

function pickService(s) {
  if (createMode.value === 'batch') {
    const cur = parsePorts(form.value.portsText)
    if (cur.includes(s.port)) {
      flash(`${s.port} 已经在列表里了`)
      return
    }
    cur.push(s.port)
    form.value.portsText = cur.join(', ')
    if (allowedProtocols.value.includes(s.proto)) {
      form.value.type = s.proto
    }
    flash(`已加入 ${s.port}（当前 ${cur.length} 个端口）`)
    return
  }

  form.value.localPort = s.port

  if (allowedProtocols.value.includes(s.proto)) {
    form.value.type = s.proto
  }

  if (s.addr && s.addr !== '0.0.0.0' && s.addr !== '::') {
    form.value.localIp = s.addr === '::1' ? '127.0.0.1' : s.addr
  }

  showScan.value = false
  flash(`已选择 ${s.process || '服务'}（${s.port}/${s.proto.toUpperCase()}）`)
}

const redeemOpen = ref(false)
const redeemCode = ref('')

const allowedProtocols = computed(() => {
  const raw = props.state.group?.allow_protocols
  if (!raw) return ['tcp', 'udp', 'http', 'https']
  const list = String(raw)
    .split(',')
    .map((s) => s.trim().toLowerCase())
    .filter(Boolean)

  if (props.state.group && props.state.group.https_tunnel_enabled === false) {
    return list.filter((p) => p !== 'https')
  }
  return list
})

const httpsEntry = computed(() => props.state.group?.https_entry || '')

const protocolLabel = (p) => ({ tcp: 'TCP', udp: 'UDP', http: 'HTTP（网站）', https: 'HTTPS（网站）' }[p] || p.toUpperCase())

const protocolText = computed(() => allowedProtocols.value.map((p) => p.toUpperCase()).join(' / '))

const maxTunnels = computed(() => {
  const n = props.state.group?.max_tunnels
  return n && n > 0 ? n : 0
})

const trafficText = computed(() => {
  const used = fmtBytes(props.state.traffic_used)
  const quota = Number(props.state.traffic_quota || 0)
  return quota > 0 ? `${used} / ${fmtBytes(quota)}` : used
})

const groupHint = computed(() => {
  const g = props.state.group
  if (!g) return ''
  const parts = []
  if (g.max_tunnels > 0) parts.push(`最多 ${g.max_tunnels} 条隧道`)
  if (g.bandwidth_limit_str) parts.push(`单隧道限速 ${g.bandwidth_limit_str}`)
  if (parts.length === 0) return ''
  return `当前分组「${g.name || '默认'}」：${parts.join('，')}`
})

const atTunnelLimit = computed(() => {
  const max = props.state.group?.max_tunnels
  if (!max || max <= 0) return false
  return props.state.tunnels.length >= max
})

function openCreate() {
  dialogError.value = ''
  showAdvanced.value = false
  createMode.value = 'single'
  scanFilter.value = ''
  form.value = {
    name: '',
    type: allowedProtocols.value[0] || 'tcp',
    localIp: '127.0.0.1',
    localPort: null,
    portsText: '',
    remotePort: null,
    subdomain: ''
  }
  createOpen.value = true
}

function nameError(name) {
  if (!/^[A-Za-z0-9_]{1,32}$/.test(name)) {
    return '名称仅允许 1-32 位字母、数字或下划线（不支持连字符）'
  }
  if (name.toLowerCase().startsWith('lt')) {
    return '名称不能以 lt 开头（该前缀保留给系统使用）'
  }
  return ''
}

async function submitCreate() {
  dialogError.value = ''
  const f = form.value
  const name = (f.name || '').trim()

  if (!allowedProtocols.value.includes(f.type)) {
    dialogError.value = `当前分组不允许 ${f.type.toUpperCase()} 协议`
    return
  }

  if (createMode.value === 'batch') {
    await submitBatch(name)
    return
  }

  const nerr = nameError(name)
  if (nerr) {
    dialogError.value = nerr
    return
  }

  if (isWebType.value && !(f.subdomain || '').trim()) {
    f.subdomain = name.toLowerCase()
  }

  if (!f.localPort || f.localPort < 1 || f.localPort > 65535) {
    dialogError.value = '请填写 1-65535 之间的本机端口'
    return
  }

  busy.value = true
  try {
    const next = await api.createTunnel(
      f.name.trim(),
      f.type,
      (f.localIp || '127.0.0.1').trim(),
      Number(f.localPort),
      showAdvanced.value ? Number(f.remotePort) || 0 : 0,
      (f.subdomain || '').trim()
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

async function submitBatch(prefix) {
  if (prefix.length > 24) {
    dialogError.value = '批量创建时名称前缀不能超过 24 位（需为端口部分留出位置）'
    return
  }
  const nerr = nameError(prefix)
  if (nerr) {
    dialogError.value = nerr
    return
  }

  const ports = parsePorts(form.value.portsText)
  if (!ports.length) {
    dialogError.value = '请填写至少一个本机端口'
    return
  }
  if (ports.length > MAX_BATCH) {
    dialogError.value = `一次最多创建 ${MAX_BATCH} 条隧道，当前填写了 ${ports.length} 个端口`
    return
  }

  busy.value = true
  try {
    const [res, next] = await api.createTunnelsBatch(
      prefix,
      form.value.type,
      (form.value.localIp || '127.0.0.1').trim(),
      ports
    )
    emit('update', next)
    createOpen.value = false

    const failed = res?.failures || []
    if (failed.length) {
      const detail = failed.map((x) => `${x.local_port}: ${x.reason}`).join('；')
      flash(`${res?.message || '部分创建失败'}｜${detail}`, 'warn')
    } else {
      flash(res?.message || `已创建 ${ports.length} 条隧道`)
    }
  } catch (e) {
    dialogError.value = typeof e === 'string' ? e : e?.message || '创建失败'
  } finally {
    busy.value = false
  }
}

async function toggleTunnel(t) {
  busy.value = true
  try {
    const next = t.running ? await api.stopTunnel(t.id) : await api.startTunnel(t.id)
    emit('update', next)
    flash(t.running ? `隧道「${t.name}」已断开，端口已收回` : `隧道「${t.name}」已连接，正在建立通道…`)
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
    flash(msg || '兑换成功')
  } catch (e) {
    dialogError.value = typeof e === 'string' ? e : e?.message || '兑换失败，请检查兑换码'
  } finally {
    busy.value = false
  }
}



const statusText = computed(() => {
  const tunnels = props.state.tunnels || []
  const connected = tunnels.filter((t) => t.status === 'active' && (t.registered || t.online)).length
  const started = tunnels.filter((t) => t.running).length

  if (connected > 0) {
    if (started > connected) {
      return `已连接 ${connected} 条，${started - connected} 条连接中`
    }
    return `已连接，${connected} 条隧道运行中`
  }
  if (started > 0) return `正在连接（${started} 条隧道）`
  if (props.state.exceeded) return '流量已用尽'
  return '未连接'
})

const syncText = computed(() => {
  if (props.state.sync_err) return `自动同步异常：${props.state.sync_err}`
  if (!props.state.last_sync_at) return '尚未同步'
  const d = new Date(props.state.last_sync_at)
  if (Number.isNaN(d.getTime())) return '已同步'
  const p = (n) => String(n).padStart(2, '0')
  return `每 20 秒自动同步 · 上次 ${p(d.getHours())}:${p(d.getMinutes())}:${p(d.getSeconds())}`
})

watch(
  () => props.notice,
  (n) => {
    if (n?.text) flash(n.text)
  }
)

const dotClass = computed(() => {
  const tunnels = props.state.tunnels || []
  if (tunnels.some((t) => t.status === 'active' && (t.registered || t.online))) return 'on'
  if (tunnels.some((t) => t.running)) return 'warn'
  if (props.state.exceeded) return 'err'
  return 'off'
})

function tagText(t) {
  if (t.status !== 'active') return '已停用'
  if (!t.running) return '未连接'
  if (t.registered || t.online) return '运行中'
  if (t.last_error) return '连接失败'
  const waited = Number(t.pending_seconds || 0)
  if (waited > 0) return `连接中 · ${fmtWaited(waited)}`
  return '连接中'
}

function fmtWaited(sec) {
  if (sec < 60) return `${sec} 秒`
  const m = Math.floor(sec / 60)
  const s = sec % 60
  return s ? `${m} 分 ${s} 秒` : `${m} 分`
}

function tagClass(t) {
  if (t.status !== 'active' || !t.running) return 'tag-info'
  if (t.registered || t.online) return 'tag-success'
  return t.last_error ? 'tag-err' : 'tag-warn'
}

function tagHint(t) {
  if (t.status !== 'active') return '这条隧道已在控制台停用'
  if (!t.running) return '本机没有为这条隧道运行 frpc'
  if (t.registered && !t.online) {
    return '本机 frpc 已报告代理注册成功；服务端状态按采集周期（约 30 秒）更新，可能略滞后'
  }
  if (t.online) return '服务端已确认这条代理在线'
  if (t.last_error) return '最近一次错误：' + t.last_error
  const waited = Number(t.pending_seconds || 0)
  if (waited >= 60) {
    return `已等待 ${fmtWaited(waited)}，仍未见注册成功。请检查服务端地址是否可达、` +
      `本机是否被防火墙拦截，或展开日志查看 frpc 输出`
  }
  return waited > 0 ? `正在连接，已等待 ${fmtWaited(waited)}` : '正在连接'
}

function fmtTime(value) {
  if (!value) return ''
  const d = new Date(value)
  if (Number.isNaN(d.getTime())) return ''
  const p = (n) => String(n).padStart(2, '0')
  return `${p(d.getHours())}:${p(d.getMinutes())}:${p(d.getSeconds())}`
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
    if (next !== undefined) emit('update', next)
    if (successText) flash(successText)
  } catch (e) {
    flash(typeof e === 'string' ? e : e?.message || '操作失败', 'warn')
  } finally {
    busy.value = false
  }
}

const logout = () => run(() => api.logout())

const handleClearLogs = () => run(props.clearLogs, '日志已清空')

const handleOpenDataDir = () => run(props.openDataDir)

async function copy(text) {
  try {
    await navigator.clipboard.writeText(text)
    flash('已复制到剪贴板')
  } catch {
    flash('复制失败，请手动复制', 'warn')
  }
}

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

.dot.warn {
  background: #f59e0b;
  box-shadow: 0 0 0 4px rgba(245, 158, 11, 0.18);
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

.tunnel-err {
  margin-top: 4px;
  font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace;
  font-size: 11.5px;
  line-height: 1.5;
  color: #b91c1c;
  word-break: break-all;
  -webkit-user-select: text;
  user-select: text;
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
  justify-content: flex-end;
  flex-shrink: 0;
  padding: 0 4px;
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

.account {
  display: flex;
  flex-wrap: wrap;
  gap: 10px 26px;
  padding: 12px 18px;
  margin-bottom: 12px;
  flex-shrink: 0;
}

.acc {
  display: flex;
  flex-direction: column;
  gap: 3px;
  min-width: 0;
}

.acc > span {
  font-size: 11.5px;
  color: #9ca3af;
}

.acc > b {
  font-size: 13.5px;
  font-weight: 600;
  color: #0f172a;
  white-space: nowrap;
  overflow: hidden;
  text-overflow: ellipsis;
  -webkit-user-select: text;
  user-select: text;
}

.acc-err {
  color: #b91c1c;
}

.sync-warn {
  color: #b45309;
}


.scan-wrap {
  margin: -6px 0 14px;
}

.scan-err {
  display: block;
  margin-top: 8px;
  font-size: 12.5px;
  color: #b91c1c;
  line-height: 1.6;
}

.scan-list {
  margin-top: 10px;
  border: 1px solid #e2e8f0;
  border-radius: 10px;
  overflow-y: auto;
  max-height: 230px;
  background: #fff;
}

.scan-filter {
  width: 100%;
  border: none;
  border-bottom: 1px solid #e2e8f0;
  padding: 9px 12px;
  font-size: 13px;
  outline: none;
  box-sizing: border-box;
  position: sticky;
  top: 0;
  background: #fff;
}

.scan-item {
  display: flex;
  align-items: center;
  gap: 10px;
  padding: 8px 12px;
  cursor: pointer;
  border-bottom: 1px solid #f1f5f9;
  font-size: 13px;
}

.scan-item:last-child {
  border-bottom: none;
}

.scan-item:hover {
  background: #f8fafc;
}

.scan-item.rec {
  border-left: 2px solid #10b981;
}

.scan-port {
  font-weight: 600;
  color: #0f172a;
  min-width: 56px;
}

.scan-proto {
  flex: 0 0 auto;
  font-size: 11px;
  color: #6b7280;
  background: #f1f5f9;
  border-radius: 5px;
  padding: 1px 6px;
}

.scan-proc {
  flex: 1;
  min-width: 0;
  overflow: hidden;
  text-overflow: ellipsis;
  white-space: nowrap;
  color: #374151;
}

.scan-badge {
  flex: 0 0 auto;
  font-size: 11px;
  color: #047857;
  background: #ecfdf5;
  border-radius: 5px;
  padding: 1px 6px;
}

.scan-empty {
  padding: 14px 12px;
  font-size: 13px;
  color: #6b7280;
  line-height: 1.7;
}


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
.field select,
.field textarea {
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

.field textarea {
  resize: vertical;
  font-family: ui-monospace, Menlo, Consolas, monospace;
  line-height: 1.6;
}

.field input:focus,
.field select:focus,
.field textarea:focus {
  border-color: #2563eb;
}

.https-note {
  margin: -4px 0 14px;
  padding: 9px 12px;
  background: #f0fdf4;
  border: 1px solid #bbf7d0;
  border-radius: 9px;
  font-size: 12.5px;
  line-height: 1.7;
  color: #166534;
}


.mode-switch {
  display: flex;
  gap: 8px;
  margin-bottom: 16px;
}

.mode-switch label {
  flex: 1;
  display: flex;
  align-items: center;
  justify-content: center;
  gap: 6px;
  padding: 8px 10px;
  border: 1px solid #e2e8f0;
  border-radius: 9px;
  font-size: 13px;
  color: #4b5563;
  cursor: pointer;
  user-select: none;
}

.mode-switch label.on {
  border-color: #2563eb;
  background: #eff6ff;
  color: #1d4ed8;
  font-weight: 500;
}

.mode-switch input {
  display: none;
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

.tunnel-addr {
  flex-wrap: wrap;
  justify-content: flex-end;
}

.tunnel-toggle {
  position: relative;
  width: 40px;
  height: 22px;
  padding: 0;
  border: none;
  border-radius: 11px;
  background: #cbd5e1;
  cursor: pointer;
  flex-shrink: 0;
  transition: background 0.18s ease;
}

.tunnel-toggle .knob {
  position: absolute;
  top: 3px;
  left: 3px;
  width: 16px;
  height: 16px;
  border-radius: 50%;
  background: #fff;
  box-shadow: 0 1px 2px rgba(15, 23, 42, 0.25);
  transition: transform 0.18s ease;
}

.tunnel-toggle.on {
  background: #16a34a;
}

.tunnel-toggle.on .knob {
  transform: translateX(18px);
}

.tunnel-toggle:disabled {
  opacity: 0.55;
  cursor: not-allowed;
}
</style>
