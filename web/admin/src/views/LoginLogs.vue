<template>
  <div class="lt-card">
    <div class="lt-card-title">
      <span>登录日志</span>
      <el-button link :icon="Refresh" @click="load">刷新</el-button>
    </div>

    <div class="filters">
      <el-select v-model="query.kind" placeholder="主体" clearable style="width: 130px">
        <el-option label="用户" value="user" />
        <el-option label="管理员" value="admin" />
      </el-select>
      <el-select v-model="query.result" placeholder="结果" clearable style="width: 160px">
        <el-option v-for="r in results" :key="r.value" :label="r.label" :value="r.value" />
      </el-select>
      <el-input v-model="query.username" placeholder="按账号筛选" clearable style="width: 200px" @keyup.enter="reload" />
      <el-button :icon="Search" @click="reload">查询</el-button>
    </div>

    <el-alert
      type="info"
      :closable="false"
      show-icon
      style="margin-bottom: 14px"
      title="失败记录同样会被记录，这是识别暴力破解与撞库的主要依据"
      description="日志保留 180 天（满足等保 2.0 对安全审计记录留存不少于 6 个月的要求），到期自动清理。"
    />

    <el-table :data="list" v-loading="loading" stripe size="small">
      <el-table-column label="时间" width="170">
        <template #default="{ row }">{{ formatTime(row.created_at) }}</template>
      </el-table-column>
      <el-table-column label="主体" width="90">
        <template #default="{ row }">
          <el-tag size="small" :type="row.kind === 'admin' ? 'danger' : 'primary'" effect="plain">
            {{ row.kind === 'admin' ? '管理员' : '用户' }}
          </el-tag>
        </template>
      </el-table-column>
      <el-table-column label="账号" prop="username" min-width="130" />
      <el-table-column label="来源" width="90">
        <template #default="{ row }">{{ row.source === 'client' ? '客户端' : '网页' }}</template>
      </el-table-column>
      <el-table-column label="结果" width="120">
        <template #default="{ row }">
          <el-tag size="small" :type="resultType(row.result)">{{ resultLabel(row.result) }}</el-tag>
        </template>
      </el-table-column>
      <el-table-column label="IP" width="150">
        <template #default="{ row }"><span class="lt-mono">{{ row.ip || '-' }}</span></template>
      </el-table-column>
      <el-table-column label="详情" prop="detail" min-width="180" show-overflow-tooltip />
      <el-table-column label="User-Agent" prop="user_agent" min-width="200" show-overflow-tooltip />
      <template #empty><el-empty description="暂无登录记录" /></template>
    </el-table>

    <el-pagination
      v-if="total > query.page_size"
      layout="total, prev, pager, next"
      :total="total"
      :page-size="query.page_size"
      :current-page="query.page"
      @current-change="onPage"
      style="margin-top: 14px; justify-content: flex-end"
    />
  </div>
</template>

<script setup>
import { onMounted, reactive, ref } from 'vue'
import { Refresh, Search } from '@element-plus/icons-vue'
import { logApi } from '../api'
import { formatTime } from '../utils/format'

const list = ref([])
const total = ref(0)
const loading = ref(false)
const query = reactive({ kind: '', result: '', username: '', page: 1, page_size: 20 })

const results = [
  { label: '登录成功', value: 'success' },
  { label: '密码错误', value: 'bad_credentials' },
  { label: '账号已禁用', value: 'disabled' },
  { label: '账号被锁定', value: 'locked' },
  { label: '动态口令错误', value: 'totp_failed' },
  { label: '账号已注销', value: 'account_deleted' }
]

const resultLabels = {}
results.forEach((r) => {
  resultLabels[r.value] = r.label
})

function resultLabel(r) {
  return resultLabels[r] || r
}

function resultType(r) {
  switch (r) {
    case 'success':
      return 'success'
    case 'locked':
      return 'warning'
    case 'disabled':
    case 'totp_failed':
    case 'bad_credentials':
      return 'danger'
    default:
      return 'info'
  }
}

async function load() {
  loading.value = true
  try {
    const data = await logApi.logins({ ...query })
    list.value = data?.list || []
    total.value = data?.total || 0
  } finally {
    loading.value = false
  }
}

function reload() {
  query.page = 1
  load()
}

function onPage(p) {
  query.page = p
  load()
}

onMounted(load)
</script>

<style scoped>
.filters {
  display: flex;
  gap: 10px;
  flex-wrap: wrap;
  margin-bottom: 14px;
}
</style>
