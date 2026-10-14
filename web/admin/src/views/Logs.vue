<template>
  <div class="lt-card">
    <div class="lt-card-title">审计与客户端</div>

    <el-tabs v-model="tab" @tab-change="onTabChange">
      <el-tab-pane label="操作审计" name="audit">
        <div class="filters">
          <el-input v-model="auditQuery.action" placeholder="按动作筛选，如 user.delete" clearable style="width: 260px" @keyup.enter="loadAudit" />
          <el-button :icon="Search" @click="loadAudit">查询</el-button>
        </div>
        <el-table :data="audits" v-loading="loading" stripe size="small">
          <el-table-column label="时间" width="170">
            <template #default="{ row }">{{ formatTime(row.created_at) }}</template>
          </el-table-column>
          <el-table-column label="管理员" prop="admin_name" width="120">
            <template #default="{ row }">{{ row.admin_name || '系统' }}</template>
          </el-table-column>
          <el-table-column label="动作" prop="action" width="180">
            <template #default="{ row }"><span class="lt-mono">{{ row.action }}</span></template>
          </el-table-column>
          <el-table-column label="对象" width="140">
            <template #default="{ row }">{{ row.target }} {{ row.target_id }}</template>
          </el-table-column>
          <el-table-column label="详情" prop="detail" min-width="220" show-overflow-tooltip />
          <el-table-column label="来源 IP" prop="ip" width="150" />
          <template #empty><el-empty description="暂无审计记录" /></template>
        </el-table>
        <el-pagination
          v-if="auditTotal > auditQuery.page_size"
          layout="total, prev, pager, next"
          :total="auditTotal"
          :page-size="auditQuery.page_size"
          :current-page="auditQuery.page"
          @current-change="onAuditPage"
          style="margin-top: 14px; justify-content: flex-end"
        />
      </el-tab-pane>

      <el-tab-pane label="客户端会话" name="clients">
        <el-table :data="clients" v-loading="loading" stripe size="small">
          <el-table-column label="用户 ID" prop="user_id" width="90" />
          <el-table-column label="运行标识" prop="run_id" min-width="200">
            <template #default="{ row }"><span class="lt-mono">{{ row.run_id }}</span></template>
          </el-table-column>
          <el-table-column label="来源地址" prop="addr" width="170" />
          <el-table-column label="系统" width="160">
            <template #default="{ row }">{{ row.os }} / {{ row.arch }}</template>
          </el-table-column>
          <el-table-column label="客户端版本" prop="version" width="120" />
          <el-table-column label="在线" width="90">
            <template #default="{ row }">
              <el-tag size="small" :type="row.online ? 'success' : 'info'">{{ row.online ? '在线' : '离线' }}</el-tag>
            </template>
          </el-table-column>
          <el-table-column label="最后心跳" width="170">
            <template #default="{ row }">{{ formatTime(row.last_seen_at) }}</template>
          </el-table-column>
          <template #empty><el-empty description="暂无客户端会话" /></template>
        </el-table>
        <el-pagination
          v-if="clientTotal > clientQuery.page_size"
          layout="total, prev, pager, next"
          :total="clientTotal"
          :page-size="clientQuery.page_size"
          :current-page="clientQuery.page"
          @current-change="onClientPage"
          style="margin-top: 14px; justify-content: flex-end"
        />
      </el-tab-pane>
    </el-tabs>
  </div>
</template>

<script setup>
import { onMounted, reactive, ref } from 'vue'
import { Search } from '@element-plus/icons-vue'
import { logApi } from '../api'
import { formatTime } from '../utils/format'

const tab = ref('audit')
const loading = ref(false)

const audits = ref([])
const auditTotal = ref(0)
const auditQuery = reactive({ action: '', page: 1, page_size: 20 })

const clients = ref([])
const clientTotal = ref(0)
const clientQuery = reactive({ page: 1, page_size: 20 })

async function loadAudit() {
  loading.value = true
  try {
    const data = await logApi.audit({ ...auditQuery })
    audits.value = data?.list || []
    auditTotal.value = data?.total || 0
  } finally {
    loading.value = false
  }
}

async function loadClients() {
  loading.value = true
  try {
    const data = await logApi.clients({ ...clientQuery })
    clients.value = data?.list || []
    clientTotal.value = data?.total || 0
  } finally {
    loading.value = false
  }
}

function onAuditPage(p) {
  auditQuery.page = p
  loadAudit()
}

function onClientPage(p) {
  clientQuery.page = p
  loadClients()
}

function onTabChange(name) {
  if (name === 'audit') loadAudit()
  else loadClients()
}

onMounted(loadAudit)
</script>

<style scoped>
.filters {
  display: flex;
  gap: 10px;
  margin-bottom: 14px;
}
</style>
