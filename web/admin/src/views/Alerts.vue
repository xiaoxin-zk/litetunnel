<template>
  <div>
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
        title="每 5 分钟采样一次，命中阈值才推送；同一类告警 30 分钟内不重复发送"
        :description="`样本保留 ${sampleKeepDays} 天，供下方趋势图使用。冷却按告警类型计算并落库，进程重启后仍然有效。`"
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
            以 POST + JSON 推送，字段：<span class="lt-mono">kind / level / message / value / threshold / site / at</span>；
            返回 2xx 视为推送成功
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
        <el-button link type="primary" :loading="loadingEvents" @click="loadEvents">刷新</el-button>
      </div>
      <el-table :data="events" size="small" empty-text="还没有告警">
        <el-table-column label="时间" width="180">
          <template #default="{ row }">{{ fmtTime(row.created_at) }}</template>
        </el-table-column>
        <el-table-column label="类型" width="130">
          <template #default="{ row }">{{ kindLabel(row.kind) }}</template>
        </el-table-column>
        <el-table-column label="级别" width="100">
          <template #default="{ row }">
            <el-tag size="small" :type="row.level === 'critical' ? 'danger' : row.level === 'warning' ? 'warning' : 'info'">
              {{ row.level }}
            </el-tag>
          </template>
        </el-table-column>
        <el-table-column prop="message" label="内容" min-width="320" show-overflow-tooltip />
        <el-table-column label="推送" width="90">
          <template #default="{ row }">
            <el-tag size="small" :type="row.delivered ? 'success' : 'info'">
              {{ row.delivered ? '成功' : '未送达' }}
            </el-tag>
          </template>
        </el-table-column>
      </el-table>
      <div class="lt-muted" style="margin-top: 10px">
        「未送达」表示 Webhook 请求失败（超时、非 2xx 或地址不可达），可在这里确认接收端是否正常。
        历史只保留最近 {{ eventKeepDays }} 天。
      </div>
    </div>
  </div>
</template>

<script setup>
import { computed, nextTick, onBeforeUnmount, onMounted, ref } from 'vue'
import * as echarts from 'echarts'
import { ElMessage } from 'element-plus'
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
  min_requests: 50
})
// 已保存的地址不回显：留空即保持原值，只有用户真的改过输入框才覆盖。
const webhookConfigured = ref(false)
const webhookDirty = ref(false)
const webhookPlaceholder = computed(() =>
  webhookConfigured.value ? '已配置，留空表示不修改' : 'https://example.com/hook'
)

const sampleKeepDays = ref(14)
const eventKeepDays = ref(90)

const range = ref(288)
const rangeLabel = computed(
  () => ({ 288: '最近 24 小时趋势', 1008: '最近 3.5 天趋势', 2016: '最近 7 天趋势' })[range.value] || '趋势'
)
const samples = ref([])
const events = ref([])
const chartRef = ref()
let chart = null

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
    webhookDirty.value = false
    sampleKeepDays.value = Number(res.sample_keep_days ?? 14)
    eventKeepDays.value = Number(res.event_keep_days ?? 90)
    form.value = {
      enabled: !!res.enabled,
      webhook_url: '',
      error_rate_pct: Number(res.error_rate_pct ?? 0),
      disk_pct: Number(res.disk_pct ?? 0),
      backup_stale_hours: Number(res.backup_stale_hours ?? 0),
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
      backup_stale_hours: form.value.backup_stale_hours
    })
    ElMessage.success('已保存，配置即时生效')
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
