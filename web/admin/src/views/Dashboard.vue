<template>
  <div v-loading="loading">
    <el-row :gutter="16">
      <el-col :xs="12" :sm="8" :md="4" v-for="c in cards" :key="c.label">
        <div class="lt-card stat">
          <div class="stat-label">{{ c.label }}</div>
          <div class="stat-value" :style="{ color: c.color }">{{ c.value }}</div>
        </div>
      </el-col>
    </el-row>

    <el-row :gutter="16" style="margin-top: 16px">
      <el-col :xs="24" :md="12">
        <div class="lt-card">
          <div class="lt-card-title">运维提示</div>
          <ul class="tips">
            <li>管理后台默认只监听 <span class="lt-mono">127.0.0.1</span>，请通过本机反代或 VPN 访问，切勿直接暴露公网。</li>
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
            <el-button plain @click="$router.push('/logs')">查看审计</el-button>
          </div>
          <el-divider />
          <div class="lt-muted" style="line-height: 1.9">
            用户控制台与管理后台使用<b>不同端口</b>与<b>不同令牌密钥</b>：<br />
            用户令牌无法访问管理接口，公网端口上也不存在管理路由。
          </div>
        </div>
      </el-col>
    </el-row>
  </div>
</template>

<script setup>
import { computed, onMounted, ref } from 'vue'
import { statsApi } from '../api'
import { formatBytes } from '../utils/format'

const loading = ref(false)
const stats = ref({})

const cards = computed(() => [
  { label: '用户总数', value: stats.value.user_total ?? 0, color: '#2563eb' },
  { label: '正常用户', value: stats.value.user_active ?? 0, color: '#059669' },
  { label: '隧道总数', value: stats.value.tunnel_total ?? 0, color: '#7c3aed' },
  { label: '启用隧道', value: stats.value.tunnel_active ?? 0, color: '#0891b2' },
  { label: '在线客户端', value: stats.value.online_client ?? 0, color: '#d97706' },
  { label: '累计流量', value: formatBytes(stats.value.traffic_used_total), color: '#0f172a' }
])

async function load() {
  loading.value = true
  try {
    stats.value = (await statsApi.overview()) || {}
  } finally {
    loading.value = false
  }
}

onMounted(load)
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
  font-size: 24px;
  font-weight: 700;
  margin-top: 8px;
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
