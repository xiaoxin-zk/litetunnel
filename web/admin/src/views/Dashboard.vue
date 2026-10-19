<template>
  <div v-loading="loading && !hasData">
    <div class="lt-card" v-loading="healthLoading && !health">
      <div class="lt-card-title">
        <span>健康检查</span>
        <span class="lt-muted" style="font-size: 12.5px; font-weight: 400">
          {{ health?.generated_at ? '更新于 ' + new Date(health.generated_at).toLocaleTimeString() : '' }}
        </span>
      </div>

      <el-row :gutter="16">
        <el-col :xs="24" :md="6">
          <div class="health-score">
            <div class="health-num" :style="{ color: gradeColor }">{{ health ? health.score : '—' }}</div>
            <div class="health-grade">{{ health?.grade || '未知' }}</div>
            <div class="lt-muted" style="font-size: 12px">算不出的分项不参与加权</div>
          </div>
        </el-col>
        <el-col :xs="24" :md="18">
          <div v-for="c in health?.components || []" :key="c.key" class="health-comp">
            <div class="health-comp-head">
              <span class="health-comp-name">{{ c.name }}</span>
              <span class="lt-muted health-comp-detail">{{ c.detail }}</span>
              <span :style="{ color: compColor(c.status) }">
                {{ c.status === 'unknown' ? '—' : c.score }}
              </span>
            </div>
            <el-progress
              :percentage="c.status === 'unknown' ? 0 : c.score"
              :show-text="false"
              :stroke-width="5"
              :color="compColor(c.status)"
            />
          </div>
        </el-col>
      </el-row>

      <div v-if="health?.todos?.length" class="health-todos">
        <div v-for="t in health.todos" :key="t.key" class="health-todo">
          <el-tag size="small" :type="todoTag(t.level)">{{ todoLabel(t.level) }}</el-tag>
          <b>{{ t.title }}</b>
          <span class="lt-muted health-todo-detail">{{ t.detail }}</span>
          <el-button v-if="t.link" link type="primary" @click="$router.push(t.link)">去处理</el-button>
        </div>
      </div>
      <div v-else-if="health" class="lt-muted" style="margin-top: 10px">
        没有需要处理的项。
      </div>
    </div>

    <div class="lt-card" style="margin-top: 16px">
      <div class="lt-card-title">
        <span>服务器实时状态</span>
        <span class="lt-muted" style="font-size: 12.5px; font-weight: 400">
          {{ rangeText }}
        </span>
      </div>

      <el-row :gutter="16">
        <el-col :xs="12" :sm="8" :md="4" v-for="m in metricCards" :key="m.label">
          <div class="metric">
            <div class="metric-label">{{ m.label }}</div>
            <div class="metric-value" :style="{ color: m.color }">{{ m.value }}</div>
            <div class="metric-sub">{{ m.sub }}</div>
            <el-progress
              v-if="m.percent !== undefined"
              :percentage="m.percent"
              :show-text="false"
              :stroke-width="4"
              :color="m.color"
              style="margin-top: 6px"
            />
          </div>
        </el-col>
      </el-row>
    </div>

    <el-row :gutter="16" style="margin-top: 16px">
      <el-col :xs="24" :md="12">
        <div class="lt-card">
          <div class="lt-card-title">CPU 使用率</div>
          <div ref="cpuRef" class="chart"></div>
        </div>
      </el-col>
      <el-col :xs="24" :md="12">
        <div class="lt-card">
          <div class="lt-card-title">内存使用率</div>
          <div ref="memRef" class="chart"></div>
        </div>
      </el-col>
    </el-row>

    <el-row :gutter="16" style="margin-top: 16px">
      <el-col :xs="24" :md="12">
        <div class="lt-card">
          <div class="lt-card-title">
            <span>网络吞吐</span>
            <span class="lt-muted" style="font-size: 12.5px; font-weight: 400">
              累计 下行 {{ fmtBytes(latest?.net_rx_total) }} · 上行 {{ fmtBytes(latest?.net_tx_total) }}
            </span>
          </div>
          <div ref="netRef" class="chart"></div>
        </div>
      </el-col>
      <el-col :xs="24" :md="12">
        <div class="lt-card">
          <div class="lt-card-title">磁盘 IO</div>
          <div ref="diskRef" class="chart"></div>
        </div>
      </el-col>
    </el-row>

    <div class="lt-card" style="margin-top: 16px">
      <div class="lt-card-title">
        <span>面板进程开销</span>
        <span class="lt-muted" style="font-size: 12.5px; font-weight: 400">
          用于判断「面板是不是自己把机器吃满了」
        </span>
      </div>
      <el-descriptions :column="3" border size="small">
        <el-descriptions-item label="Go 堆占用">
          {{ fmtBytes(metrics.latest?.self?.heap_bytes) }}
        </el-descriptions-item>
        <el-descriptions-item label="常驻内存（RSS）">
          {{ fmtBytes(metrics.latest?.self?.rss_bytes) }}
        </el-descriptions-item>
        <el-descriptions-item label="进程 CPU">
          {{ (metrics.latest?.self?.cpu_percent || 0).toFixed(1) }}%
        </el-descriptions-item>
        <el-descriptions-item label="协程数">
          {{ metrics.latest?.self?.goroutines ?? 0 }}
        </el-descriptions-item>
        <el-descriptions-item label="GC 次数">
          {{ metrics.latest?.self?.gc_count ?? 0 }}
        </el-descriptions-item>
        <el-descriptions-item label="最近 GC 停顿">
          {{ (metrics.latest?.self?.gc_pause_ms || 0).toFixed(2) }} ms
        </el-descriptions-item>
      </el-descriptions>
    </div>

    <div class="lt-card" style="margin-top: 16px">
      <div class="lt-card-title">账号恢复请求（当前实例）</div>
      <el-descriptions :column="3" border size="small">
        <el-descriptions-item label="等待处理 / 容量">{{ metrics.recovery?.queued ?? '未知' }} / {{ metrics.recovery?.capacity ?? '未知' }}</el-descriptions-item>
        <el-descriptions-item label="队满拒绝累计">{{ metrics.recovery?.rejected ?? '未知' }}</el-descriptions-item>
        <el-descriptions-item label="处理失败累计">{{ metrics.recovery?.failed ?? '未知' }}</el-descriptions-item>
      </el-descriptions>
      <div class="lt-muted" style="margin-top: 10px">计数在进程重启后清零。预处理队列尚未持久化，重启或处理失败可能需要用户重新申请；受理不代表邮件已送达。</div>
      <el-alert v-if="metrics.recovery?.failed || metrics.recovery?.rejected" type="warning" :closable="false" title="恢复请求出现拒绝或处理失败，请检查邮件配置、对外地址及服务日志。" style="margin-top: 10px" />
    </div>

    <div class="lt-card" style="margin-top: 16px">
      <div class="lt-card-title">认证审计写入（当前实例）</div>
      <el-descriptions :column="3" border size="small">
        <el-descriptions-item label="写入失败累计">{{ metrics.audit?.failures ?? 0 }}</el-descriptions-item>
        <el-descriptions-item label="最近失败时间">
          {{ metrics.audit?.last_at ? new Date(metrics.audit.last_at).toLocaleString() : '无' }}
        </el-descriptions-item>
        <el-descriptions-item label="最近失败位置">{{ metrics.audit?.last_scope || '无' }}</el-descriptions-item>
      </el-descriptions>
      <div class="lt-muted" style="margin-top: 10px">
        登录、动态口令验证、兑换核销成功时，若审计字段没能写进数据库，认证仍会放行——避免一次数据库抖动把管理员锁在门外。失败次数与最近原因记在这里。
        这些计数是<b>实例级</b>的：只来自当前处理本次请求的进程，重启清零；多实例部署时不能把它们相加当作全局值
        <span v-if="metrics.audit?.instance">（实例 <code>{{ metrics.audit.instance }}</code>）</span>。
      </div>
      <el-alert v-if="metrics.audit?.failures" type="warning" :closable="false"
        :title="`有 ${metrics.audit.failures} 次审计写入失败（最近：${metrics.audit.last_scope || '未知位置'}｜${metrics.audit.last_error || '未记录原因'}），请检查数据库状态：锁表、磁盘空间、目录权限。`"
        style="margin-top: 10px" />
    </div>

    <div class="lt-card" style="margin-top: 16px">
      <div class="lt-card-title">平台业务数据</div>
      <el-row :gutter="16">
        <el-col :xs="12" :sm="8" :md="4" v-for="c in cards" :key="c.label">
          <div class="metric">
            <div class="metric-label">{{ c.label }}</div>
            <div class="metric-value" :style="{ color: c.color }">{{ c.value }}</div>
          </div>
        </el-col>
      </el-row>
    </div>

    <el-row :gutter="16" style="margin-top: 16px">
      <el-col :xs="24" :md="12">
        <div class="lt-card">
          <div class="lt-card-title">运维提示</div>
          <ul class="tips">
            <li>监控数据存在<b>内存环形缓冲</b>里，不会落库、不会无限增长，面板重启后会重新累积。</li>
            <li>用户的流量超额由服务端插件实时拦截，无需人工介入；如需临时放行可在「用户管理」中调整配额。</li>
            <li>分组限速由服务端强制下发（<span class="lt-mono">bandwidthLimitMode = server</span>），客户端改配置无法绕过。</li>
            <li>所有写操作都会写入审计日志，请定期检查「审计与客户端」页面。</li>
          </ul>
        </div>
      </el-col>
      <el-col :xs="24" :md="12">
        <div class="lt-card">
          <div class="lt-card-title">快捷入口</div>
          <div class="quick">
            <el-button type="primary" plain @click="$router.push('/users')">用户管理</el-button>
            <el-button plain @click="$router.push('/groups')">分组权限</el-button>
            <el-button plain @click="$router.push('/redeem')">生成兑换码</el-button>
            <el-button plain @click="$router.push('/firewall')">端口与防火墙</el-button>
          </div>
          <el-divider />
          <div class="lt-muted" style="line-height: 1.9">
            指标采集自宿主机 <span class="lt-mono">/proc</span>（容器内读到的是宿主机全局数据），
            因此这里显示的是<b>整台服务器</b>的状态，而不是容器的 cgroup 配额视角。
          </div>
        </div>
      </el-col>
    </el-row>
  </div>
</template>

<script setup>
import { computed, nextTick, onBeforeUnmount, onMounted, ref } from 'vue'
import * as echarts from 'echarts'
import { healthApi, monitorApi, statsApi } from '../api'
import { formatBytes } from '../utils/format'

const loading = ref(false)
const stats = ref({})
const metrics = ref({})

const health = ref(null)
const healthLoading = ref(false)
let healthTimer = null

const gradeColor = computed(() => {
  const s = health.value?.score ?? 0
  if (s >= 90) return '#059669'
  if (s >= 75) return '#2563eb'
  if (s >= 60) return '#d97706'
  return '#dc2626'
})

function compColor(status) {
  switch (status) {
    case 'critical':
      return '#dc2626'
    case 'warn':
      return '#d97706'
    case 'ok':
      return '#059669'
    default:
      return '#cbd5e1'
  }
}

function todoTag(level) {
  if (level === 'critical') return 'danger'
  if (level === 'warning') return 'warning'
  return 'info'
}

function todoLabel(level) {
  if (level === 'critical') return '严重'
  if (level === 'warning') return '警告'
  return '提示'
}

// 健康分要读证书状态（可能走宿主机 helper），因此单独 60 秒刷新一次，
// 不跟着 5 秒一次的实时指标一起轮询。
async function loadHealth() {
  healthLoading.value = true
  try {
    health.value = await healthApi.get()
  } catch {
    // 辅助信息，失败不影响其他卡片
  } finally {
    healthLoading.value = false
  }
}

const cpuRef = ref()
const memRef = ref()
const netRef = ref()
const diskRef = ref()

const charts = {}
let timer = null

const hasData = computed(() => !!metrics.value.latest)
const series = computed(() => metrics.value.series || [])
const latest = computed(() => metrics.value.latest || {})

const fmtBytes = (v) => formatBytes(v)

function fmtRate(v) {
  if (!v || v <= 0) return '0 B/s'
  return formatBytes(v) + '/s'
}

function fmtUptime(sec) {
  const s = Number(sec || 0)
  if (s <= 0) return '-'
  const d = Math.floor(s / 86400)
  const h = Math.floor((s % 86400) / 3600)
  const m = Math.floor((s % 3600) / 60)
  if (d > 0) return `${d} 天 ${h} 小时`
  if (h > 0) return `${h} 小时 ${m} 分`
  return `${m} 分钟`
}

const rangeText = computed(() => {
  const n = series.value.length
  const iv = metrics.value.sample_interval || 5
  if (!n) return '等待首次采样…'
  const minutes = Math.round((n * iv) / 60)
  return `每 ${iv} 秒采样 · 当前覆盖 ${minutes} 分钟（${n} 个点）`
})

const metricCards = computed(() => {
  const m = latest.value
  const memPercent = m.mem_total ? (m.mem_used / m.mem_total) * 100 : 0
  const diskPercent = m.disk_total ? (m.disk_used / m.disk_total) * 100 : 0
  const cpu = m.cpu_percent || 0

  const list = [
    {
      label: 'CPU 使用率',
      value: cpu.toFixed(1) + '%',
      sub: `${m.cpu_cores || 0} 核`,
      percent: cpu,
      color: cpu >= 80 ? '#dc2626' : cpu >= 60 ? '#d97706' : '#059669'
    },
    {
      label: '内存使用率',
      value: memPercent.toFixed(1) + '%',
      sub: `${fmtBytes(m.mem_used)} / ${fmtBytes(m.mem_total)}`,
      percent: memPercent,
      color: memPercent >= 85 ? '#dc2626' : memPercent >= 70 ? '#d97706' : '#2563eb'
    },
    {
      label: '系统负载',
      value: (m.load1 || 0).toFixed(2),
      sub: `5 分 ${(m.load5 || 0).toFixed(2)} · 15 分 ${(m.load15 || 0).toFixed(2)}`,
      color: (m.load1 || 0) > (m.cpu_cores || 1) ? '#dc2626' : '#7c3aed'
    },
    {
      label: '运行时长',
      value: fmtUptime(m.uptime_seconds),
      sub: '系统已连续运行',
      color: '#0891b2'
    }
  ]

  if (m.disk_total > 0) {
    list.push({
      label: '磁盘',
      value: diskPercent.toFixed(1) + '%',
      sub: `${m.disk_path || '/'} · ${fmtBytes(m.disk_used)} / ${fmtBytes(m.disk_total)}`,
      percent: diskPercent,
      color: diskPercent >= 90 ? '#dc2626' : diskPercent >= 75 ? '#d97706' : '#059669'
    })
  }

  list.push({
    label: '实时网络',
    value: fmtRate(m.net_rx_rate),
    sub: `上行 ${fmtRate(m.net_tx_rate)}`,
    color: '#0f172a'
  })

  return list
})

const cards = computed(() => [
  { label: '用户总数', value: stats.value.user_total ?? 0, color: '#2563eb' },
  { label: '正常用户', value: stats.value.user_active ?? 0, color: '#059669' },
  { label: '隧道总数', value: stats.value.tunnel_total ?? 0, color: '#7c3aed' },
  { label: '启用隧道', value: stats.value.tunnel_active ?? 0, color: '#0891b2' },
  { label: '在线客户端', value: stats.value.online_client ?? 0, color: '#d97706' },
  { label: '累计流量', value: formatBytes(stats.value.traffic_used_total), color: '#0f172a' }
])

function timeAxis() {
  return series.value.map((s) => {
    const d = new Date(s.at)
    const p = (n) => String(n).padStart(2, '0')
    return `${p(d.getHours())}:${p(d.getMinutes())}:${p(d.getSeconds())}`
  })
}

function lineOption({ names, colors, data, unit, max }) {
  return {
    grid: { left: 58, right: 16, top: 34, bottom: 26 },
    tooltip: {
      trigger: 'axis',
      valueFormatter: unit === 'bytes' ? (v) => fmtRate(v) : (v) => `${Number(v).toFixed(1)}%`
    },
    legend: { data: names, right: 0, top: 0, icon: 'roundRect', itemWidth: 12, itemHeight: 8 },
    xAxis: {
      type: 'category',
      data: timeAxis(),
      boundaryGap: false,
      axisLine: { lineStyle: { color: '#e5e7eb' } },
      axisLabel: { color: '#9ca3af', fontSize: 11 }
    },
    yAxis: {
      type: 'value',
      max,
      min: 0,
      splitLine: { lineStyle: { color: '#f1f5f9' } },
      axisLabel: {
        color: '#9ca3af',
        fontSize: 11,
        formatter: unit === 'bytes' ? (v) => fmtBytes(v) : '{value}%'
      }
    },
    series: names.map((name, i) => ({
      name,
      type: 'line',
      smooth: true,
      showSymbol: false,
      symbolSize: 4,
      lineStyle: { width: 2, color: colors[i] },
      itemStyle: { color: colors[i] },
      areaStyle: {
        color: new echarts.graphic.LinearGradient(0, 0, 0, 1, [
          { offset: 0, color: colors[i] + '33' },
          { offset: 1, color: colors[i] + '05' }
        ])
      },
      data: data[i]
    }))
  }
}

function renderCharts() {
  const s = series.value
  if (!s.length) return

  const jobs = [
    [
      'cpu',
      cpuRef.value,
      {
        names: ['CPU'],
        colors: ['#2563eb'],
        data: [s.map((x) => +(x.cpu_percent || 0).toFixed(2))],
        unit: 'percent',
        max: 100
      }
    ],
    [
      'mem',
      memRef.value,
      {
        names: ['内存'],
        colors: ['#7c3aed'],
        data: [
          s.map((x) => +((x.mem_total ? (x.mem_used / x.mem_total) * 100 : 0)).toFixed(2))
        ],
        unit: 'percent',
        max: 100
      }
    ],
    [
      'net',
      netRef.value,
      {
        names: ['下行', '上行'],
        colors: ['#059669', '#d97706'],
        data: [
          s.map((x) => +(x.net_rx_rate || 0).toFixed(0)),
          s.map((x) => +(x.net_tx_rate || 0).toFixed(0))
        ],
        unit: 'bytes'
      }
    ],
    [
      'disk',
      diskRef.value,
      {
        names: ['读', '写'],
        colors: ['#0891b2', '#dc2626'],
        data: [
          s.map((x) => +(x.disk_read_rate || 0).toFixed(0)),
          s.map((x) => +(x.disk_write_rate || 0).toFixed(0))
        ],
        unit: 'bytes'
      }
    ]
  ]

  for (const [key, el, opt] of jobs) {
    if (!el) continue
    if (!charts[key]) charts[key] = echarts.init(el)
    charts[key].setOption(lineOption(opt), true)
  }
}

function resizeCharts() {
  Object.values(charts).forEach((c) => c && c.resize())
}

async function load() {
  loading.value = true
  try {
    const [ov, mt] = await Promise.all([statsApi.overview(), monitorApi.system()])
    stats.value = ov || {}
    metrics.value = mt || {}
    await nextTick()
    renderCharts()
  } finally {
    loading.value = false
  }
}

onMounted(async () => {
  await Promise.all([load(), loadHealth()])
  window.addEventListener('resize', resizeCharts)
  const iv = (metrics.value.sample_interval || 5) * 1000
  timer = setInterval(load, iv)
  healthTimer = setInterval(loadHealth, 60 * 1000)
})

onBeforeUnmount(() => {
  if (timer) clearInterval(timer)
  if (healthTimer) clearInterval(healthTimer)
  window.removeEventListener('resize', resizeCharts)
  Object.values(charts).forEach((c) => c && c.dispose())
})
</script>

<style scoped>
.metric {
  padding: 4px 0 10px;
}

.metric-label {
  font-size: 13px;
  color: #6b7280;
}

.metric-value {
  font-size: 22px;
  font-weight: 700;
  margin-top: 6px;
  line-height: 1.3;
}

.metric-sub {
  font-size: 12px;
  color: #9ca3af;
  margin-top: 2px;
  white-space: nowrap;
  overflow: hidden;
  text-overflow: ellipsis;
}

.chart {
  height: 220px;
  width: 100%;
}

.tips {
  margin: 0;
  padding-left: 18px;
  color: #4b5563;
  line-height: 2;
  font-size: 13.5px;
}

.quick {
  display: flex;
  gap: 10px;
  flex-wrap: wrap;
}

.health-score {
  padding: 6px 0 14px;
}

.health-num {
  font-size: 40px;
  font-weight: 700;
  line-height: 1.1;
}

.health-grade {
  font-size: 13px;
  color: #6b7280;
  margin-bottom: 4px;
}

.health-comp {
  margin-bottom: 10px;
}

.health-comp-head {
  display: flex;
  align-items: center;
  gap: 8px;
  font-size: 12.5px;
  margin-bottom: 4px;
}

.health-comp-name {
  width: 42px;
  color: #374151;
  flex: none;
}

.health-comp-detail {
  flex: 1;
  overflow: hidden;
  text-overflow: ellipsis;
  white-space: nowrap;
}

.health-todos {
  margin-top: 14px;
  border-top: 1px solid #eef1f6;
  padding-top: 10px;
}

.health-todo {
  display: flex;
  align-items: center;
  gap: 8px;
  padding: 5px 0;
  font-size: 13px;
}

.health-todo-detail {
  flex: 1;
  overflow: hidden;
  text-overflow: ellipsis;
  white-space: nowrap;
}
</style>
