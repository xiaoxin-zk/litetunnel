<template>
  <div v-loading="loading">
    <el-row :gutter="16">
      <el-col :xs="24" :sm="12" :md="6" v-for="card in cards" :key="card.label">
        <div class="lt-card stat">
          <div class="stat-label">{{ card.label }}</div>
          <div class="stat-value" :style="{ color: card.color }">{{ card.value }}</div>
          <div class="stat-sub">{{ card.sub }}</div>
        </div>
      </el-col>
    </el-row>

    <el-row :gutter="16" style="margin-top: 16px">
      <el-col :xs="24" :md="14">
        <div class="lt-card">
          <div class="lt-card-title">
            <span>近 7 天流量</span>
            <span class="lt-muted">单位：MB</span>
          </div>
          <div ref="chartRef" class="chart"></div>
        </div>
      </el-col>

      <el-col :xs="24" :md="10">
        <div class="lt-card">
          <div class="lt-card-title">流量额度</div>
          <el-progress
            :percentage="quotaPercent"
            :status="quotaStatus"
            :stroke-width="14"
            striped
          />
          <div class="quota-row">
            <span>已用 <b>{{ fmtBytes(profile?.traffic_used) }}</b></span>
            <span>配额 <b>{{ quotaText }}</b></span>
          </div>
          <el-alert
            v-if="profile?.traffic_exceeded"
            type="error"
            :closable="false"
            show-icon
            title="流量已用尽，隧道将无法建立新连接"
            description="请在「兑换中心」使用兑换码增加额度，或联系管理员。"
            style="margin-top: 14px"
          />
          <div class="reset-tip lt-muted">
            下次重置：{{ formatTime(profile?.traffic_reset_at) }}
          </div>
          <el-divider />
          <div class="quota-row">
            <span>当前分组</span>
            <el-tag effect="light">{{ profile?.group?.name || '未分组' }}</el-tag>
          </div>
          <div class="quota-row">
            <span>单隧道限速</span>
            <b>{{ profile?.group?.bandwidth_limit_str || '不限速' }}</b>
          </div>
          <div class="quota-row">
            <span>可用协议</span>
            <b>{{ (profile?.group?.allow_protocols || '-').toUpperCase() }}</b>
          </div>
          <div v-if="paymentEnabled" class="quota-row">
            <span>余额</span>
            <b>¥ {{ ((profile?.balance || 0) / 100).toFixed(2) }}</b>
          </div>
        </div>
      </el-col>
    </el-row>
  </div>
</template>

<script setup>
import { computed, nextTick, onMounted, ref, watch } from 'vue'
import * as echarts from 'echarts'
import { statsApi, profileApi, publicApi } from '../api'
import { formatBytes, formatTime } from '../utils/format'

const props = defineProps({ profile: Object })

const loading = ref(false)
const stats = ref({})
const series = ref([])
const chartRef = ref()
const paymentEnabled = ref(false)
let chart = null

const cards = computed(() => {
  const list = [
    {
      label: '隧道总数',
      value: stats.value.tunnel_total ?? 0,
      sub: `在线 ${stats.value.tunnel_online ?? 0} 条`,
      color: '#2563eb'
    },
    {
      label: '已用流量',
      value: fmtBytes(stats.value.traffic_used),
      sub: `配额 ${quotaText.value}`,
      color: stats.value.traffic_exceeded ? '#dc2626' : '#0f172a'
    },
    {
      label: '在线客户端',
      value: stats.value.tunnel_online ?? 0,
      sub: '实时在线隧道数',
      color: '#059669'
    }
  ]
  if (paymentEnabled.value) {
    list.push({
      label: '账户余额',
      value: '¥ ' + ((stats.value.balance || 0) / 100).toFixed(2),
      sub: '可通过兑换码或在线充值获取',
      color: '#7c3aed'
    })
  }
  return list
})

const quotaText = computed(() => {
  const q = stats.value.traffic_quota ?? props.profile?.traffic_quota ?? 0
  return q > 0 ? fmtBytes(q) : '不限量'
})

const quotaPercent = computed(() => {
  const q = stats.value.traffic_quota ?? 0
  const used = stats.value.traffic_used ?? 0
  if (!q) return 0
  return Math.min(100, Math.round((used / q) * 100))
})

const quotaStatus = computed(() => {
  if (stats.value.traffic_exceeded) return 'exception'
  if (quotaPercent.value >= 80) return 'warning'
  return 'success'
})

function fmtBytes(v) {
  return formatBytes(v)
}

function renderChart() {
  if (!chartRef.value) return
  if (!chart) chart = echarts.init(chartRef.value)
  const dates = series.value.map((r) => r.date.slice(5))
  const inData = series.value.map((r) => +(r.in_bytes / 1024 / 1024).toFixed(2))
  const outData = series.value.map((r) => +(r.out_bytes / 1024 / 1024).toFixed(2))
  chart.setOption({
    grid: { left: 44, right: 16, top: 30, bottom: 28 },
    tooltip: { trigger: 'axis' },
    legend: { data: ['下行', '上行'], right: 0, top: 0, icon: 'roundRect' },
    xAxis: { type: 'category', data: dates, boundaryGap: false, axisLine: { lineStyle: { color: '#e5e7eb' } } },
    yAxis: { type: 'value', splitLine: { lineStyle: { color: '#f1f5f9' } } },
    series: [
      {
        name: '下行',
        type: 'line',
        smooth: true,
        showSymbol: false,
        data: inData,
        areaStyle: { opacity: 0.12 },
        lineStyle: { width: 2, color: '#2563eb' },
        itemStyle: { color: '#2563eb' }
      },
      {
        name: '上行',
        type: 'line',
        smooth: true,
        showSymbol: false,
        data: outData,
        areaStyle: { opacity: 0.1 },
        lineStyle: { width: 2, color: '#10b981' },
        itemStyle: { color: '#10b981' }
      }
    ]
  })
}

async function loadSettings() {
  try {
    const s = await publicApi.settings()
    paymentEnabled.value = !!s?.payment_enabled
  } catch {
    paymentEnabled.value = false
  }
}

async function load() {
  loading.value = true
  try {
    const [ov, tr] = await Promise.all([statsApi.overview(), statsApi.traffic(7)])
    stats.value = ov || {}
    series.value = tr || []
    await nextTick()
    renderChart()
  } finally {
    loading.value = false
  }
}

onMounted(async () => {
  await loadSettings()
  await load()
})

watch(() => props.profile, () => load())
window.addEventListener('resize', () => chart?.resize())
</script>

<style scoped>
.stat {
  margin-bottom: 16px;
}

.stat-label {
  font-size: 13px;
  color: #6b7280;
}

.stat-value {
  font-size: 26px;
  font-weight: 700;
  margin: 8px 0 4px;
}

.stat-sub {
  font-size: 12px;
  color: #9ca3af;
}

.chart {
  height: 268px;
}

.quota-row {
  display: flex;
  align-items: center;
  justify-content: space-between;
  margin-top: 12px;
  font-size: 14px;
}

.reset-tip {
  margin-top: 12px;
}
</style>
