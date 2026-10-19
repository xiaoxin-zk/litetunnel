<template>
  <div class="backup-page">
    <div class="lt-card">
      <div class="lt-card-title">
        <span>备份策略</span>
        <el-button :loading="creating" type="primary" @click="createBackup">立即备份</el-button>
      </div>

      <el-alert
        v-if="!supported"
        type="warning"
        :closable="false"
        show-icon
        title="当前使用 PostgreSQL，面板不做在线备份"
      >
        <div>
          请用 pg_dump 定期导出，例如：
          <code>pg_dump -Fc -f litetunnel-$(date +%F).dump "$LT_DB_DSN"</code>
        </div>
      </el-alert>

      <template v-else>
        <div class="strategy">
          <div class="strategy-item">
            <span class="label">自动备份</span>
            <el-switch v-model="autoBackup" />
            <span class="hint">维护任务每 24 小时补一份，关闭后只能手动备份</span>
          </div>
          <div class="strategy-item">
            <span class="label">保留份数</span>
            <el-input-number v-model="retention" :min="1" :max="60" />
            <span class="hint">只轮转普通备份，恢复前的安全备份不会被删</span>
          </div>
          <el-button :loading="saving" @click="saveStrategy">保存策略</el-button>
        </div>

        <div class="path-hint">
          备份目录：<span class="lt-mono">{{ dir || '—' }}</span>
          <span class="hint">（容器部署时请确认它位于挂载的数据卷内）</span>
        </div>
      </template>
    </div>

    <div class="lt-card" style="margin-top: 16px">
      <div class="lt-card-title">
        <span>备份文件</span>
        <el-button link type="primary" :loading="loading" @click="load">刷新</el-button>
      </div>

      <el-table :data="items" size="small" empty-text="还没有备份">
        <el-table-column prop="name" label="文件名" min-width="240">
          <template #default="{ row }">
            <span class="lt-mono">{{ row.name }}</span>
            <el-tag v-if="row.pre_restore" size="small" type="info" style="margin-left: 8px">
              恢复前快照
            </el-tag>
          </template>
        </el-table-column>
        <el-table-column label="大小" width="110">
          <template #default="{ row }">{{ fmtSize(row.size) }}</template>
        </el-table-column>
        <el-table-column label="创建时间" width="180">
          <template #default="{ row }">{{ fmtTime(row.created_at) }}</template>
        </el-table-column>
        <el-table-column label="操作" width="190" align="right">
          <template #default="{ row }">
            <el-button link type="primary" @click="download(row)">下载</el-button>
            <el-button link type="warning" @click="restore(row)">恢复</el-button>
            <el-button link type="danger" @click="remove(row)">删除</el-button>
          </template>
        </el-table-column>
      </el-table>

      <div class="lt-muted" style="margin-top: 12px; line-height: 1.8">
        恢复会先用当前数据库做一份「恢复前快照」，再覆盖数据库文件并重启面板；
        重启期间（约 3-5 秒）后台不可用，数据目录里的其它文件不受影响。
      </div>
    </div>
  </div>
</template>

<script setup>
import { onMounted, ref } from 'vue'
import { ElMessage, ElMessageBox } from 'element-plus'
import { backupApi, settingsApi, TOKEN_KEY } from '../api'

const loading = ref(false)
const creating = ref(false)
const saving = ref(false)
const items = ref([])
const dir = ref('')
const supported = ref(true)
const autoBackup = ref(true)
const retention = ref(7)

function fmtSize(n) {
  if (!n) return '—'
  if (n < 1024 * 1024) return `${(n / 1024).toFixed(1)} KB`
  return `${(n / 1024 / 1024).toFixed(2)} MB`
}

function fmtTime(v) {
  if (!v) return '—'
  const d = new Date(v)
  return Number.isNaN(d.getTime()) ? '—' : d.toLocaleString()
}

async function load() {
  loading.value = true
  try {
    const res = await backupApi.list()
    items.value = res?.items || []
    dir.value = res?.dir || ''
    supported.value = res?.supported !== false
  } finally {
    loading.value = false
  }
}

async function loadStrategy() {
  const data = await settingsApi.get()
  autoBackup.value = String(data['backup.auto_enabled'] ?? 'true') === 'true'
  retention.value = Number(data['backup.retention'] || 7)
}

async function saveStrategy() {
  saving.value = true
  try {
    await settingsApi.update({
      'backup.auto_enabled': autoBackup.value ? 'true' : 'false',
      'backup.retention': String(retention.value || 7)
    })
    ElMessage.success('备份策略已保存')
  } finally {
    saving.value = false
  }
}

async function createBackup() {
  creating.value = true
  try {
    const res = await backupApi.create()
    ElMessage.success(`已创建 ${res?.name || '备份'}`)
    await load()
  } finally {
    creating.value = false
  }
}

async function download(row) {
  const res = await fetch(`/api/admin/backups/${encodeURIComponent(row.name)}/download`, {
    headers: { Authorization: `Bearer ${localStorage.getItem(TOKEN_KEY) || ''}` }
  })
  if (!res.ok) {
    ElMessage.error('下载失败，请重试')
    return
  }
  const blob = await res.blob()
  const url = URL.createObjectURL(blob)
  const a = document.createElement('a')
  a.href = url
  a.download = row.name
  a.click()
  URL.revokeObjectURL(url)
}

async function restore(row) {
  await ElMessageBox.confirm(
    `将用「${row.name}」覆盖当前数据库，并重启面板。当前库会先自动存一份恢复前快照。确认继续？`,
    '恢复备份',
    { type: 'warning', confirmButtonText: '恢复并重启', cancelButtonText: '取消' }
  )
  await backupApi.restore(row.name)
  ElMessage.success('已恢复，面板正在重启，稍后刷新页面')
  setTimeout(() => window.location.reload(), 6000)
}

async function remove(row) {
  await ElMessageBox.confirm(`删除备份「${row.name}」？此操作不可恢复。`, '删除备份', {
    type: 'warning',
    confirmButtonText: '删除',
    cancelButtonText: '取消'
  })
  await backupApi.remove(row.name)
  ElMessage.success('已删除')
  await load()
}

onMounted(async () => {
  await Promise.all([load(), loadStrategy().catch(() => {})])
})
</script>

<style scoped>
.backup-page {
  padding-bottom: 8px;
}

.strategy {
  display: flex;
  flex-wrap: wrap;
  align-items: center;
  gap: 28px;
}

.strategy-item {
  display: flex;
  align-items: center;
  gap: 10px;
}

.strategy-item .label {
  color: #2b2440;
  font-weight: 600;
  font-size: 13.5px;
}

.hint {
  color: #6f6689;
  font-size: 12.5px;
}

.path-hint {
  margin-top: 16px;
  padding: 10px 14px;
  border-radius: 12px;
  background: linear-gradient(120deg, #f7f4ff, #eefaf7);
  color: #554d70;
  font-size: 12.5px;
}
</style>
