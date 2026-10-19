<template>
  <div>
    <el-alert
      v-if="silenced"
      type="warning"
      :closable="false"
      show-icon
      style="margin-bottom: 12px"
      :title="`告警静默中：${fmtTime(form.silence_until)} 之前不推送${form.silence_reason ? '（' + form.silence_reason + '）' : ''}`"
    >
      <el-button size="small" @click="stopSilence">结束静默</el-button>
    </el-alert>

    <div class="lt-card" v-loading="loadingConfig">
      <div class="lt-card-title">
        <span>告警设置</span>
        <div>
          <el-button :loading="loadingConfig" @click="loadConfig">重新载入</el-button>
          <el-button type="primary" :loading="saving" @click="save">保存设置</el-button>
        </div>
      </div>

      <el-alert
        type="info"
        :closable="false"
        show-icon
        style="margin-bottom: 16px"
        title="每 5 分钟采样一次，命中阈值才推送；同一事件每 30 分钟提醒一次，恢复时再推一条"
        :description="`样本保留 ${sampleKeepDays} 天，供下方趋势图使用。事件状态落库，进程重启后仍然有效。`"
      />

      <el-form label-width="150px" style="max-width: 780px">
        <el-form-item label="启用告警">
          <el-switch v-model="form.enabled" />
          <span class="hint">关闭后仍会采样，只是不评估阈值、不推送</span>
        </el-form-item>

        <el-form-item label="Webhook 地址">
          <el-input v-model="form.webhook_url" :placeholder="webhookPlaceholder" @input="webhookDirty = true" />
          <div class="row">
            <el-button :loading="testing" :disabled="!webhookConfigured" @click="testWebhook">
              发送测试消息
            </el-button>
            <span class="hint">
              地址里通常带令牌，因此保存后不回显；留空保存表示保持原值，填入新地址则覆盖。
              测试按钮测的是<b>已保存</b>的地址，改完请先保存
            </span>
          </div>
          <div class="hint">
            以 POST + JSON 推送，字段：<span class="lt-mono">event_id / kind / status / level / message / value / threshold / site / at / fired_at</span>；
            <span class="lt-mono">status</span> 为 <span class="lt-mono">firing</span>（触发）、
            <span class="lt-mono">resolved</span>（恢复）或 <span class="lt-mono">test</span>（测试）；返回 2xx 视为推送成功
          </div>
          <div class="hint">
            出站策略：拒绝云厂商元数据与链路本地地址，且不跟随 3xx 跳转；
            内网自建接收端（127.0.0.1 / 192.168.x）可用
          </div>
        </el-form-item>

        <el-form-item label="接口错误率阈值">
          <el-input-number v-model="form.error_rate_pct" :min="0" :max="100" :step="1" />
          <span class="hint">
            %，窗口内 5xx 占比达到该值才告警（请求数少于 {{ form.min_requests }} 次不评估）；0 表示关闭
          </span>
        </el-form-item>

        <el-form-item label="磁盘使用率阈值">
          <el-input-number v-model="form.disk_pct" :min="0" :max="100" :step="1" />
          <span class="hint">%，超过后按 critical 级别推送；0 表示关闭</span>
        </el-form-item>

        <el-form-item label="备份超时告警">
          <el-input-number v-model="form.backup_stale_hours" :min="0" :max="8760" :step="1" />
          <span class="hint">小时，距最近一次成功备份超过该值就提醒；0 表示关闭</span>
        </el-form-item>

        <el-form-item label="持续判定">
          <el-input-number v-model="form.sustained_windows" :min="1" :max="12" :step="1" />
          <span class="hint">
            连续 N 个采样窗口（每窗口 5 分钟）都超标才触发，用来压掉瞬时尖峰；
            恢复不受影响，第一个正常窗口就会收尾
          </span>
        </el-form-item>

        <el-form-item label="临时静默至">
          <div class="row">
            <el-date-picker
              v-model="form.silence_until"
              type="datetime"
              placeholder="选择截止时间"
              style="width: 200px"
            />
            <el-input
              v-model="form.silence_reason"
              placeholder="原因，如：数据库维护"
              style="width: 220px"
            />
            <el-button v-if="silenced" link type="warning" @click="stopSilence">结束静默</el-button>
          </div>
          <span class="hint">
            静默期间不新建告警、不推送（已有事件仍会随条件自动恢复）；截止后问题仍在会重新开一条。
            清空时间并保存即取消静默
          </span>
        </el-form-item>
      </el-form>
    </div>

    <div class="lt-card" style="margin-top: 16px">
      <div class="lt-card-title">
        <span>{{ rangeLabel }}</span>
        <div class="row">
          <el-radio-group v-model="range" size="small" @change="loadSamples">
            <el-radio-button :value="288">24 小时</el-radio-button>
            <el-radio-button :value="1008">3.5 天</el-radio-button>
            <el-radio-button :value="2016">7 天</el-radio-button>
          </el-radio-group>
          <el-button link type="primary" :loading="loadingSample" @click="loadSamples">刷新</el-button>
        </div>
      </div>
      <div ref="chartRef" class="chart"></div>
      <div class="lt-muted" style="margin-top: 8px">
        每个点是一个 5 分钟窗口。只统计 <span class="lt-mono">/api/</span> 接口，错误率只看 5xx；
        静态资源与 <span class="lt-mono">/healthz</span> 不计入分母。
      </div>
    </div>

    <div class="lt-card" style="margin-top: 16px">
      <div class="lt-card-title">
        <span>告警历史</span>
        <div class="row">
          <el-radio-group v-model="statusFilter" size="small">
            <el-radio-button value="">全部</el-radio-button>
            <el-radio-button value="firing">进行中</el-radio-button>
            <el-radio-button value="resolved">已恢复</el-radio-button>
            <el-radio-button value="manual_resolved">手动解决</el-radio-button>
          </el-radio-group>
          <el-button link type="primary" :loading="loadingEvents" @click="loadEvents">刷新</el-button>
        </div>
      </div>
      <el-table :data="visibleEvents" size="small" empty-text="还没有告警">
        <el-table-column label="时间" width="180">
          <template #default="{ row }">{{ fmtTime(row.created_at) }}</template>
        </el-table-column>
        <el-table-column label="类型" width="120">
          <template #default="{ row }">{{ kindLabel(row.kind) }}</template>
        </el-table-column>
        <el-table-column label="级别" width="90">
          <template #default="{ row }">
            <el-tag size="small" :type="row.level === 'critical' ? 'danger' : row.level === 'warning' ? 'warning' : 'info'">
              {{ row.level }}
            </el-tag>
          </template>
        </el-table-column>
        <el-table-column prop="message" label="内容" min-width="300" show-overflow-tooltip />
        <el-table-column label="状态" width="100">
          <template #default="{ row }">
            <el-tag size="small" :type="statusTagType(row.status)">{{ statusLabel(row.status) }}</el-tag>
          </template>
        </el-table-column>
        <el-table-column label="通知" width="110">
          <template #default="{ row }">
            <el-tag size="small" :type="notifyState(row).ok ? 'success' : 'info'">
              {{ notifyState(row).text }}
            </el-tag>
          </template>
        </el-table-column>
        <el-table-column label="操作" width="100" align="right">
          <template #default="{ row }">
            <el-button
              v-if="row.status === 'firing'"
              link
              type="warning"
              :loading="resolving === row.id"
              @click="resolveEvent(row)"
            >
              手动解决
            </el-button>
          </template>
        </el-table-column>
      </el-table>
      <div class="lt-muted" style="margin-top: 10px">
        「进行中」表示条件仍在命中，期间每 30 分钟提醒一次；条件自行回落会自动变成「已恢复」，并推送一条恢复通知（触发通知没送达时不补发）。
        「手动解决」用于已经知道、暂时不想再被提醒的告警：30 分钟内同类问题不再打扰，之后仍在命中才重新开一条。
        历史只保留最近 {{ eventKeepDays }} 天（仍在进行中的不清理）。
      </div>
    </div>
  </div>
</template>

<script setup>
import { computed, nextTick, onBeforeUnmount, onMounted, ref } from 'vue'
import * as echarts from 'echarts'
import { ElMessage, ElMessageBox } from 'element-plus'
import { alertApi } from '../api'

const loadingConfig = ref(false)
const saving = ref(false)
const testing = ref(false)
const loadingSample = ref(false)
const loadingEvents = ref(false)

const SECRET_MASK = '__UNCHANGED__'

const form = ref({
  enabled: false,
  webhook_url: '',
  error_rate_pct: 5,
  disk_pct: 90,
  backup_stale_hours: 48,
  sustained_windows: 1,
  silence_until: null,
  silence_reason: '',
  min_requests: 50
})

const silenced = computed(() => {
  const until = form.value.silence_until
  return !!until && new Date(until).getTime() > Date.now()
})
// 已保存的地址不回显：留空即保持原值，只有用户真的改过输入框才覆盖。
const webhookConfigured = ref(false)
const webhookHost = ref('')
const webhookDirty = ref(false)
const webhookPlaceholder = computed(() => {
  if (!webhookConfigured.value) return 'https://example.com/hook'
  return webhookHost.value ? `已配置（${webhookHost.value}），留空表示不修改` : '已配置，留空表示不修改'
})

const sampleKeepDays = ref(14)
const eventKeepDays = ref(90)

const range = ref(288)
const rangeLabel = computed(
  () => ({ 288: '最近 24 小时趋势', 1008: '最近 3.5 天趋势', 2016: '最近 7 天趋势' })[range.value] || '趋势'
)
const samples = ref([])
const events = ref([])
const statusFilter = ref('')
const resolving = ref(0)
const chartRef = ref()
let chart = null

const visibleEvents = computed(() =>
  statusFilter.value ? events.value.filter((e) => e.status === statusFilter.value) : events.value
)

function statusLabel(status) {
  switch (status) {
    case 'resolved':
      return '已恢复'
    case 'manual_resolved':
      return '手动解决'
    case 'firing':
    case '':
    case undefined:
      return '进行中'
    default:
      return status
  }
}

function statusTagType(status) {
  if (status === 'resolved') return 'success'
  if (status === 'manual_resolved') return 'info'
  return 'danger'
}

// 通知列分两种语义：进行中看触发通知是否送达，已恢复看恢复通知是否送达。
function notifyState(row) {
  if (row.status === 'resolved') {
    return { ok: !!row.resolved_notified, text: row.resolved_notified ? '恢复已通知' : '恢复未通知' }
  }
  if (row.status === 'manual_resolved') {
    return { ok: true, text: '—' }
  }
  return { ok: !!row.delivered, text: row.delivered ? '已推送' : '未送达' }
}

async function resolveEvent(row) {
  try {
    await ElMessageBox.confirm(
      `确认把「${kindLabel(row.kind)}」标记为手动解决？30 分钟内同类告警不会再提醒。`,
      '手动解决告警',
      { type: 'warning', confirmButtonText: '确认解决', cancelButtonText: '取消' }
    )
  } catch {
    return
  }
  resolving.value = row.id
  try {
    await alertApi.resolve(row.id)
    ElMessage.success('已标记为手动解决')
    await loadEvents()
  } finally {
    resolving.value = 0
  }
}

const KIND_LABELS = {
  error_rate: '接口错误率',
  disk: '磁盘水位',
  backup_stale: '备份超时',
  test: '测试'
}

function kindLabel(kind) {
  return KIND_LABELS[kind] || kind
}

function fmtTime(v) {
  if (!v) return '—'
  const d = new Date(v)
  return Number.isNaN(d.getTime()) ? '—' : d.toLocaleString()
}

async function loadConfig() {
  loadingConfig.value = true
  try {
    const res = (await alertApi.settings()) || {}
    webhookConfigured.value = !!res.webhook_configured
    webhookHost.value = res.webhook_host || ''
    webhookDirty.value = false
    sampleKeepDays.value = Number(res.sample_keep_days ?? 14)
    eventKeepDays.value = Number(res.event_keep_days ?? 90)
    const until = res.silence_until ? new Date(res.silence_until) : null
    form.value = {
      enabled: !!res.enabled,
      webhook_url: '',
      error_rate_pct: Number(res.error_rate_pct ?? 0),
      disk_pct: Number(res.disk_pct ?? 0),
      backup_stale_hours: Number(res.backup_stale_hours ?? 0),
      sustained_windows: Number(res.sustained_windows ?? 1),
      silence_until: until && !Number.isNaN(until.getTime()) ? until : null,
      silence_reason: res.silence_reason || '',
      min_requests: Number(res.min_requests ?? 50)
    }
  } finally {
    loadingConfig.value = false
  }
}

async function save() {
  saving.value = true
  try {
    const typed = form.value.webhook_url.trim()
    // 没动输入框 + 原来就有地址 ⇒ 送占位符，后端按「保持原值」处理。
    const webhook = typed || (!webhookDirty.value && webhookConfigured.value ? SECRET_MASK : '')
    await alertApi.saveSettings({
      enabled: form.value.enabled,
      webhook_url: webhook,
      error_rate_pct: form.value.error_rate_pct,
      disk_pct: form.value.disk_pct,
      backup_stale_hours: form.value.backup_stale_hours,
      sustained_windows: form.value.sustained_windows,
      silence_until: form.value.silence_until ? new Date(form.value.silence_until).toISOString() : '',
      silence_reason: form.value.silence_reason || ''
    })
    ElMessage.success('已保存，配置即时生效')
    await loadConfig()
  } finally {
    saving.value = false
  }
}

// 结束静默只提交静默相关字段：部分更新不会碰到阈值与地址。
async function stopSilence() {
  saving.value = true
  try {
    await alertApi.saveSettings({ silence_until: '', silence_reason: '' })
    ElMessage.success('已结束静默，恢复推送')
    await loadConfig()
  } finally {
    saving.value = false
  }
}

async function testWebhook() {
  testing.value = true
  try {
    const res = await alertApi.test()
    ElMessage.success(res?.message || '测试消息已推送')
  } finally {
    testing.value = false
  }
}

// 后端按时间倒序返回，画图前反转成时间正序。
const series = computed(() => [...samples.value].reverse())

function timeAxis() {
  const p = (n) => String(n).padStart(2, '0')
  return series.value.map((s) => {
    const d = new Date(s.at)
    if (Number.isNaN(d.getTime())) return ''
    return `${p(d.getMonth() + 1)}-${p(d.getDate())} ${p(d.getHours())}:${p(d.getMinutes())}`
  })
}

function renderChart() {
  if (!chartRef.value) return
  if (!chart) chart = echarts.init(chartRef.value)

  const s = series.value
  const opt = {
    grid: { left: 52, right: 16, top: 40, bottom: 30 },
    tooltip: { trigger: 'axis' },
    legend: { data: ['错误率', '磁盘使用率'], right: 0, top: 0, icon: 'roundRect', itemWidth: 12, itemHeight: 8 },
    xAxis: {
      type: 'category',
      data: timeAxis(),
      boundaryGap: false,
      axisLine: { lineStyle: { color: '#e5e7eb' } },
      axisLabel: { color: '#9ca3af', fontSize: 11 }
    },
    yAxis: {
      type: 'value',
      min: 0,
      max: 100,
      splitLine: { lineStyle: { color: '#f1f5f9' } },
      axisLabel: { color: '#9ca3af', fontSize: 11, formatter: '{value}%' }
    },
    series: [
      {
        name: '错误率',
        type: 'line',
        smooth: true,
        showSymbol: false,
        lineStyle: { width: 2, color: '#dc2626' },
        itemStyle: { color: '#dc2626' },
        data: s.map((x) => +(x.error_rate || 0).toFixed(2))
      },
      {
        name: '磁盘使用率',
        type: 'line',
        smooth: true,
        showSymbol: false,
        lineStyle: { width: 2, color: '#2563eb' },
        itemStyle: { color: '#2563eb' },
        data: s.map((x) => +(x.disk_used_pct || 0).toFixed(2))
      }
    ]
  }
  chart.setOption(opt, true)
}

async function loadSamples() {
  loadingSample.value = true
  try {
    const res = await alertApi.metrics(range.value)
    samples.value = res?.samples || []
    await nextTick()
    renderChart()
  } finally {
    loadingSample.value = false
  }
}

async function loadEvents() {
  loadingEvents.value = true
  try {
    const res = await alertApi.events(100)
    events.value = res?.events || []
  } finally {
    loadingEvents.value = false
  }
}

function resize() {
  if (chart) chart.resize()
}

onMounted(async () => {
  window.addEventListener('resize', resize)
  await Promise.all([loadConfig(), loadSamples(), loadEvents()])
})

onBeforeUnmount(() => {
  window.removeEventListener('resize', resize)
  if (chart) {
    chart.dispose()
    chart = null
  }
})
</script>

<style scoped>
.chart {
  height: 260px;
  width: 100%;
}

.row {
  display: flex;
  align-items: center;
  gap: 10px;
  flex-wrap: wrap;
}

.hint {
  display: block;
  margin-top: 4px;
  color: #9ca3af;
  font-size: 12px;
  line-height: 1.7;
}
</style>
