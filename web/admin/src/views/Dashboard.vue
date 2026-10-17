<template>
  <div v-loading="loading && !hasData">
    <!-- ============ 系统实时指标 ============ -->
    <div class="lt-card">
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

    <!-- ============ 趋势图 ============ -->
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

    <!-- ============ 面板自身开销 ============ -->
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

    <!-- ============ 业务指标 ============ -->
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
import { monitorApi, statsApi } from '../api'
import { formatBytes } from '../utils/format'

const loading = ref(false)
const stats = ref({})
const metrics = ref({})

const cpuRef = ref()
const memRef = ref()
const netRef = ref()
const diskRef = ref()

// 图表实例。放在普通对象里而不是响应式：echarts 实例内部持有大量
// DOM 引用，被 Vue 代理后既无必要也容易出怪问题。
const charts = {}
let timer = null

const hasData = computed(() => !!metrics.value.latest)
const series = computed(() => metrics.value.series || [])
const latest = computed(() => metrics.value.latest || {})

const fmtBytes = (v) => formatBytes(v)

/** 字节/秒 → 人类可读的速率。 */
function fmtRate(v) {
  if (!v || v <= 0) return '0 B/s'
  return formatBytes(v) + '/s'
}

/** 秒 → 「3 天 4 小时」这种可读形式。 */
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
      // 分级配色：60% 以下绿、80% 以下橙、再高红。
      // 光看数字很难一眼判断「这算不算高」，颜色能。
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
      // 负载除以核数才是「忙不忙」的正确口径：8 核上负载 4 只算半忙。
      color: (m.load1 || 0) > (m.cpu_cores || 1) ? '#dc2626' : '#7c3aed'
    },
    {
      label: '运行时长',
      value: fmtUptime(m.uptime_seconds),
      sub: '系统已连续运行',
      color: '#0891b2'
    }
  ]

  // 磁盘容量读不到时不显示这一项，而不是显示 0 —— 一个假的 0%
  // 会让管理员以为磁盘空着。
  if (m.disk_total > 0) {
    list.push({
      label: '磁盘',
      value: diskPercent.toFixed(1) + '%',
      // 带上挂载路径：容器里 / 是镜像的 overlay，/data 才是数据卷，两者
      // 容量常常不同，不写路径就看不出这个百分比说的是哪块盘。
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

/** 采样点的时间轴标签（HH:MM:SS）。 */
function timeAxis() {
  return series.value.map((s) => {
    const d = new Date(s.at)
    const p = (n) => String(n).padStart(2, '0')
    return `${p(d.getHours())}:${p(d.getMinutes())}:${p(d.getSeconds())}`
  })
}

/**
 * 生成一个共用的折线图配置。
 *
 * 四个图的结构完全一致，只有数据与单位不同。抽成一个构造函数，
 * 比复制四份配置更容易保持一致——尤其是 tooltip 与网格边距这类
 * 一旦不一致就会显得「有一个图长得不一样」的细节。
 */
function lineOption({ names, colors, data, unit, max }) {
  return {
    grid: { left: 58, right: 16, top: 34, bottom: 26 },
    tooltip: {
      trigger: 'axis',
      // 用 valueFormatter 而不是拼字符串：它能同时作用于所有系列，
      // 避免每个系列各写一遍 formatter 而漏掉其中一个。
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
      // 单点时 smooth 线画不出来，用一个小圆点表示「只有一个采样」。
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
        // 内存同样用百分比：绝对值在不同规格的机器上无法横向比较，
        // 而「还剩多少余量」才是管理员关心的。
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
    // notMerge=true：系列数量固定，直接覆盖比合并更省心，
    // 也避免上一次的 tooltip 状态残留。
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
  await load()
  window.addEventListener('resize', resizeCharts)
  // 刷新间隔跟随服务端采样间隔：比它更快只会反复拿到同一个点，
  // 白白增加请求量。
  const iv = (metrics.value.sample_interval || 5) * 1000
  timer = setInterval(load, iv)
})

onBeforeUnmount(() => {
  if (timer) clearInterval(timer)
  window.removeEventListener('resize', resizeCharts)
  // 必须显式 dispose：echarts 实例持有 canvas 与事件监听，
  // 不释放会在反复进出页面时累积内存。
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
</style>
