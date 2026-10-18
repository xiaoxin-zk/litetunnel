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
        <!-- 这里刻意没有「启动连接」按钮：连接由每条隧道自己的开关驱动，
             开关打开着的隧道在接入时就会自动连上。再放一个全局按钮只会
             制造状态不一致——「开关是开的，但还得再点一次才连上」。 -->
        <button class="btn-ghost" @click="logout">退出登录</button>
      </div>
    </header>

    <!-- 账户信息。连上之后应当一眼看到「我是谁、什么分组、还剩多少」，
         而不是只能从隧道列表里反推。 -->
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
      <!-- 余额与支付开关绑定：没有充值入口时显示它只会造成困惑 -->
      <div v-if="state.payment_enabled" class="acc">
        <span>余额</span>
        <b>¥ {{ ((state.balance_cents || 0) / 100).toFixed(2) }}</b>
      </div>
    </div>

    <div v-if="message" class="banner" :class="messageType">{{ message }}</div>
    <!-- 本地配置损坏：客户端会以「未登录」启动，必须说清原因，
         否则用户只会以为凭据莫名其妙丢了。 -->
    <div v-if="state.config_error" class="banner warn">{{ state.config_error }}</div>
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
              <span class="tag" :class="tagClass(t)" :title="tagHint(t)">{{ tagText(t) }}</span>
            </div>
            <div class="muted">
              本地 <span class="mono">{{ t.local_ip }}:{{ t.local_port }}</span>
              ·
              {{ t.type.toUpperCase() }}
              <template v-if="t.bandwidth_limit_str"> · 限速 {{ t.bandwidth_limit_str }}</template>
            </div>
            <!-- frpc 自己报的错。没有它的话，隧道一直停在「连接中」，
                 而用户无从判断是凭据失效、地址写错还是网络不通。 -->
            <div v-if="t.last_error" class="tunnel-err">
              {{ t.last_error }}
              <template v-if="t.last_error_at"> · {{ fmtTime(t.last_error_at) }}</template>
            </div>
          </div>

          <div class="tunnel-addr">
            <span class="mono">{{ t.public_addr || '—' }}</span>
            <button v-if="t.public_addr" class="btn-ghost mini" @click="copy(t.public_addr)">复制</button>
            <!-- 开关就是「这条隧道要不要连出去」：打开即拉起它自己的 frpc
                 进程，关掉即停掉该进程并让服务端收回端口。 -->
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

      <!-- 日志 -->
      <section class="card logs">
        <div class="card-head">
          <span>运行日志</span>
          <div class="head-actions">
            <button class="btn-ghost mini" @click="clearLogs">清空</button>
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

    <!-- ============ 新建隧道 ============ -->
    <div v-if="createOpen" class="modal" @click.self="createOpen = false">
      <div class="modal-card">
        <div class="modal-title">{{ createMode === 'batch' ? '批量新建隧道' : '新建隧道' }}</div>

        <div class="mode-switch">
          <label :class="{ on: createMode === 'single' }">
            <input type="radio" value="single" v-model="createMode" />
            <span>单条</span>
          </label>
          <!-- 批量创建是按端口展开的，而 HTTP/HTTPS 隧道没有公网端口、
               靠域名区分，展开不了——因此这两类只提供单条创建。 -->
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

        <!-- 从本机监听的服务里点选。
             多数用户并不知道自己的服务跑在哪个端口，让他们去查
             是把程序该解决的问题推给了用户。 -->
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

        <!-- HTTP/HTTPS 类隧道没有公网端口，靠域名区分。
             服务端在域名与二级域名都为空时会直接拒绝，所以这个字段必须给。 -->
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
      <!-- 这里曾经有个「启动客户端后自动连接」勾选框。它已经没有意义：
           连接与否完全由每条隧道自己的开关决定（开关状态存在服务端），
           客户端一打开就会跟上。留着只会让人以为「不勾就不会连」。 -->
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
const form = ref({
  name: '',
  type: 'tcp',
  localIp: '127.0.0.1',
  localPort: null,
  portsText: '',
  remotePort: null,
  subdomain: ''
})

/** 是否为 HTTP/HTTPS 类隧道。这两类没有公网端口，靠域名区分。 */
const isWebType = computed(() => form.value.type === 'http' || form.value.type === 'https')

const subdomainPlaceholder = computed(() => {
  const d = props.state.tunnel_domain
  return d ? `例如 mc（访问地址将是 mc.${d}）` : '例如 mc'
})

/** 实时预览访问地址，让用户填之前就知道会得到什么。 */
const subdomainPreview = computed(() => {
  const s = (form.value.subdomain || '').trim().toLowerCase()
  if (!s) return '（填写后显示）'
  const d = props.state.tunnel_domain
  return d ? `https://${s}.${d}` : `https://${s}`
})

// 切成 HTTP/HTTPS 时强制回到单条模式：批量是按端口展开的，
// 而这两类隧道没有公网端口。
watch(isWebType, (web) => {
  if (web) createMode.value = 'single'
})

// 'single' 单条 | 'batch' 批量（一串连续端口，游戏服常见）
const createMode = ref('single')
// 与服务端 MaxBatchTunnels 保持一致。前端提前告知，避免用户填了
// 40 个端口、点提交才被拒。
const MAX_BATCH = 20

/**
 * 解析批量端口输入：支持范围、逗号、空格、换行。
 *
 * 范围展开要设护栏：用户手滑写成 1-65535 的话，不拦就会生成
 * 一个六万多元素的数组，并且把它发到服务端。
 */
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

// ---- 本机服务探测 ----

const showScan = ref(false)
const scanning = ref(false)
const scanErr = ref('')
const scanFilter = ref('')
const services = ref([])

/** 过滤后的服务列表。
 *
 * 不筛选时也截断：一台跑了一阵的机器上系统服务可能上百条，
 * 全部铺出来反而找不到自己要的那个。 */
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
  // 已经扫过就直接复用：反复扫描会启动 netstat 与 tasklist 两个进程，
  // 在慢机器上有可见的卡顿。
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

/** 选中一个服务，把端口、协议、监听地址一并带入表单。 */
function pickService(s) {
  // 批量模式下是「加入列表」而不是「替换」，否则选第二个服务时
  // 会把第一个覆盖掉——而用户显然是想一次选好几个。
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

  // 协议必须跟着服务走。选到 UDP 服务却建了 TCP 隧道是最典型的踩坑，
  // 而现象是「隧道建好了但连不上」，用户基本不可能自己想到原因。
  if (allowedProtocols.value.includes(s.proto)) {
    form.value.type = s.proto
  }

  // 监听在具体地址（非通配）上的服务，把地址也带过去；
  // 否则会在隧道里填 127.0.0.1，而服务其实绑在局域网 IP 上，照样连不通。
  if (s.addr && s.addr !== '0.0.0.0' && s.addr !== '::') {
    form.value.localIp = s.addr === '::1' ? '127.0.0.1' : s.addr
  }

  showScan.value = false
  flash(`已选择 ${s.process || '服务'}（${s.port}/${s.proto.toUpperCase()}）`)
}

// ---- 兑换码 ----
const redeemOpen = ref(false)
const redeemCode = ref('')

/** 分组允许的协议。服务端没下发分组时按全放行处理（老版本服务端的兼容）。 */
const allowedProtocols = computed(() => {
  const raw = props.state.group?.allow_protocols
  if (!raw) return ['tcp', 'udp', 'http', 'https']
  const list = String(raw)
    .split(',')
    .map((s) => s.trim().toLowerCase())
    .filter(Boolean)

  // HTTPS 隧道与 HTTP 隧道的入口不是同一条：HTTP 走平台的 443（Caddy 终止
  // TLS 后转发），HTTPS 需要平台在独立端口上做 SNI 透传，而那条入口只在
  // 端到端模式下存在。没有入口时就把选项拿掉——留着它，用户只会建出一条
  // 永远打不开的隧道，然后去查自己的证书和防火墙。
  //
  // 只在服务端明确下发 false 时才过滤：老版本服务端没有这个字段，
  // 那时按原来的行为处理，不能因为字段缺失就把选项吃掉。
  if (props.state.group && props.state.group.https_tunnel_enabled === false) {
    return list.filter((p) => p !== 'https')
  }
  return list
})

/** HTTPS 隧道的公网入口（host:port），没有入口时为空。 */
const httpsEntry = computed(() => props.state.group?.https_entry || '')

const protocolLabel = (p) => ({ tcp: 'TCP', udp: 'UDP', http: 'HTTP（网站）', https: 'HTTPS（网站）' }[p] || p.toUpperCase())

/** 可用协议的展示文案。 */
const protocolText = computed(() => allowedProtocols.value.map((p) => p.toUpperCase()).join(' / '))

/** 隧道数上限。0 表示不限，此时不显示分母。 */
const maxTunnels = computed(() => {
  const n = props.state.group?.max_tunnels
  return n && n > 0 ? n : 0
})

/** 流量用量文案：有配额时显示「已用 / 配额」。 */
const trafficText = computed(() => {
  const used = fmtBytes(props.state.traffic_used)
  const quota = Number(props.state.traffic_quota || 0)
  return quota > 0 ? `${used} / ${fmtBytes(quota)}` : used
})

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
  createMode.value = 'single'
  scanFilter.value = ''
  // 协议默认选分组允许的第一个，避免默认值恰好不被允许
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

/** 校验隧道名/名称前缀。
 *
 * 规则必须与服务端 normalizeInput 完全一致：1-32 位、仅字母数字与下划线、
 * 不能以 lt 开头。此前这里允许连字符、长度放到 64，于是用户按提示
 * 填「mc-server」会被服务端拒绝——提示与实际规则不符是最难自己
 * 搞明白的一类问题。 */
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

  // HTTP/HTTPS 必须有二级域名（服务端两者都为空时会直接拒绝）。
  // 没填就用隧道名兜底：隧道名的字符集与二级域名完全一致，
  // 而且这样用户少填一个字段就能建好，比报错让他重填更省事。
  if (isWebType.value && !(f.subdomain || '').trim()) {
    f.subdomain = name.toLowerCase()
  }

  if (!f.localPort || f.localPort < 1 || f.localPort > 65535) {
    dialogError.value = '请填写 1-65535 之间的本机端口'
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

/** 批量创建。prefix 是名称前缀，端口从 portsText 解析。 */
async function submitBatch(prefix) {
  // 前缀上限 24 而不是 32：最终名字是「前缀_端口」，端口部分最多
  // 5 位加分隔符共 6 位，要给它留位置。
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

    // 有失败时必须逐条说明。只说「创建完成」会让用户以为全都建好了，
    // 而他会在一段时间之后才发现少了几条——那时更难回溯。
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
    // 开关同时决定两件事：本机是否拉起这条隧道的 frpc 进程，
    // 以及服务端是否把它算作「启用」（启用会开放端口，停用会收回）。
    // 两者必须一起变，否则会出现「界面显示开着、实际连不上」。
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
  // 顶部文案说的是「连上没有」，所以要用**已注册/在线**的条数，而不是
  // 「进程起没起」：frpc 进程起来了、代理还在握手时，行内标签是「连接中」，
  // 顶部若按进程数显示「已连接」就自相矛盾了。
  const tunnels = props.state.tunnels || []
  const connected = tunnels.filter((t) => t.status === 'active' && (t.registered || t.online)).length
  const started = tunnels.filter((t) => t.running).length

  if (connected > 0) {
    // 进程数多于已连接数时说明还有隧道在握手，一并说明，避免用户以为
    // 「顶部说连上了、为什么行内还在转」。
    if (started > connected) {
      return `已连接 ${connected} 条，${started - connected} 条连接中`
    }
    return `已连接，${connected} 条隧道运行中`
  }
  if (started > 0) return `正在连接（${started} 条隧道）`
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
  // 与顶部文案同源：绿点 = 至少有一条隧道真正连上了；黄点 = 进程起来了
  // 但还在握手；红点 = 流量用尽。只看 state.running 的话，进程刚起来、
  // 代理还没注册时会显示绿灯，与行内的「连接中」矛盾。
  const tunnels = props.state.tunnels || []
  if (tunnels.some((t) => t.status === 'active' && (t.registered || t.online))) return 'on'
  if (tunnels.some((t) => t.running)) return 'warn'
  if (props.state.exceeded) return 'err'
  return 'off'
})

function tagText(t) {
  if (t.status !== 'active') return '已停用'
  // running 是本机视角（进程在不在），online 是服务端视角（frps 有没有
  // 收到这条代理），registered 是本机从 frpc 输出里读到的「代理已注册」。
  // 三者分开说，用户才能区分「我没开」「开了还没通」「已经通了」。
  if (!t.running) return '未连接'
  // registered 与 online 等效，但它**先到**：服务端的 online 要等采集
  // （30 秒一轮）加客户端同步（20 秒一轮），等它的话用户会盯着「连接中」
  // 等一整轮，误以为连不上。frpc 报告成功后标签立即翻转，服务端采集值
  // 继续用于后续校准（掉线、被停用等情况仍以它为准）。
  if (t.registered || t.online) return '运行中'
  // 有错误就不是「还在连」，而是「连不上」。这两者要给不同的提示：
  // 前者让用户等，后者让用户去查（凭据、地址、网络）。
  if (t.last_error) return '连接失败'
  // 带上已等待时长：frpc 活着却迟迟没注册成功时，只写「连接中」用户
  // 分不清是刚起步还是卡了很久。
  const waited = Number(t.pending_seconds || 0)
  if (waited > 0) return `连接中 · ${fmtWaited(waited)}`
  return '连接中'
}

/** 把秒数格式化成「12 秒 / 3 分 5 秒」，用于连接耗时展示。 */
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

/**
 * 状态标签的悬停说明。
 *
 * 主要是解释「本机已注册、服务端状态还没跟上」这一种：标签已经是
 * 「运行中」，而服务端采集值可能还是上一轮的 false，管理员在后台看到
 * 的会略滞后。说清楚就不必去猜哪个才准。
 */
function tagHint(t) {
  if (t.status !== 'active') return '这条隧道已在控制台停用'
  if (!t.running) return '本机没有为这条隧道运行 frpc'
  if (t.registered && !t.online) {
    return '本机 frpc 已报告代理注册成功；服务端状态按采集周期（约 30 秒）更新，可能略滞后'
  }
  if (t.online) return '服务端已确认这条代理在线'
  if (t.last_error) return '最近一次错误：' + t.last_error
  // 长时间没连上又没有报错：给出排查方向，而不是让用户干等。
  // 注意不在这里重启进程——frpc 自己还在重连，打断反而更慢。
  const waited = Number(t.pending_seconds || 0)
  if (waited >= 60) {
    return `已等待 ${fmtWaited(waited)}，仍未见注册成功。请检查服务端地址是否可达、` +
      `本机是否被防火墙拦截，或展开日志查看 frpc 输出`
  }
  return waited > 0 ? `正在连接，已等待 ${fmtWaited(waited)}` : '正在连接'
}

/** 把时间戳格式化成 HH:MM:SS，用于「最后一次失败发生在什么时候」。 */
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
    emit('update', next)
    if (successText) flash(successText)
  } catch (e) {
    flash(typeof e === 'string' ? e : e?.message || '操作失败', 'warn')
  } finally {
    busy.value = false
  }
}

// 曾经有个「立即同步」按钮，现已移除：自动同步每 20 秒跑一次，
// 手动触发最快也只是省下这几秒，却要用户理解「为什么还需要点它」。
// 后端接口保留（api.refresh 仍可用），需要时能随时加回入口。
const logout = () => run(() => api.logout())

function clearLogs() {
  // 交给 App 处理：它同时持有主进程缓冲、页面数组与待合并队列三份状态，
  // 只在这里调 api.clearLogs() 的话，页面上的旧行会留在原地。
  emit('clearlogs')
  flash('日志已清空')
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

/* 进程已启动、代理还在握手：与行内「连接中」的黄色标签保持一致。 */
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

/* frpc 的报错原文。用等宽字体并允许换行：里面常常是英文错误串，
   截断掉关键部分（比如状态码）反而没用。 */
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
  /* 只剩右侧一组内容了，靠右对齐 */
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
/* ---- 账户信息条 ---- */

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

/* 流量超额时用红色点出来——这是最需要用户立刻知道的一件事 */
.acc-err {
  color: #b91c1c;
}

/* 同步异常时用暖色提示，但不用红色报错样式：
   网络抖动是常态，每 20 秒闪一次红色会让人以为坏了。 */
.sync-warn {
  color: #b45309;
}

/* ---- 本机服务选择 ---- */

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
  /* 系统服务可能有上百条，限高避免把对话框撑到屏幕外 */
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

/* HTTPS 自动签发说明。用中性偏正面的样式而不是警告色：
   这是一件好事（用户不用配证书），不该看起来像风险提示。 */
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

/* ---- 单条 / 批量 切换 ---- */

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

/* 隧道地址行最多有四个控件（复制/开关/删除 + 地址），
   窄窗口下允许换行，避免把地址挤没。 */
.tunnel-addr {
  flex-wrap: wrap;
  justify-content: flex-end;
}

/* 隧道开关。用按钮而不是 checkbox：它表达的是一个动作
   （拉起/停掉这条隧道的进程），不是一个会被表单提交的选项。 */
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
