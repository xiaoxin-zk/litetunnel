<template>
  <div class="lt-card">
    <div class="lt-card-title">隧道管理</div>

    <div class="filters">
      <el-input v-model="query.keyword" placeholder="搜索隧道名称" clearable style="width: 220px" @keyup.enter="load" />
      <el-select v-model="query.status" placeholder="状态" clearable style="width: 130px">
        <el-option label="启用" value="active" />
        <el-option label="停用" value="disabled" />
      </el-select>
      <el-input v-model="query.user_id" placeholder="用户 ID" clearable style="width: 130px" @keyup.enter="load" />
      <el-button :icon="Search" @click="load">查询</el-button>
    </div>

    <el-table :data="list" v-loading="loading" stripe>
      <el-table-column label="ID" prop="id" width="70" />
      <el-table-column label="所属用户" prop="user_id" width="90" />
      <el-table-column label="名称" prop="name" min-width="130" />
      <el-table-column label="类型" width="90">
        <template #default="{ row }">
          <el-tag size="small" effect="plain">{{ row.type.toUpperCase() }}</el-tag>
        </template>
      </el-table-column>
      <el-table-column label="本地地址" min-width="150">
        <template #default="{ row }">
          <span class="lt-mono">{{ row.local_ip }}:{{ row.local_port }}</span>
        </template>
      </el-table-column>
      <el-table-column label="公网入口" min-width="160">
        <template #default="{ row }">
          <span class="lt-mono">
            {{ row.remote_port ? ':' + row.remote_port : row.domain || (row.subdomain ? row.subdomain + '.*' : '-') }}
          </span>
        </template>
      </el-table-column>
      <el-table-column label="状态" width="110">
        <template #default="{ row }">
          <el-tag v-if="row.status !== 'active'" type="info" size="small">已停用</el-tag>
          <el-tag v-else-if="row.online" type="success" size="small">在线</el-tag>
          <el-tag v-else type="warning" size="small">离线</el-tag>
        </template>
      </el-table-column>
      <el-table-column label="已用流量" width="110">
        <template #default="{ row }">{{ fmtBytes(row.traffic_used) }}</template>
      </el-table-column>
      <el-table-column label="操作" width="150" fixed="right">
        <template #default="{ row }">
          <el-button link :type="row.status === 'active' ? 'warning' : 'success'" @click="toggle(row)">
            {{ row.status === 'active' ? '停用' : '启用' }}
          </el-button>
          <el-button link type="danger" @click="remove(row)">删除</el-button>
        </template>
      </el-table-column>
      <template #empty><el-empty description="暂无隧道" /></template>
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
import { ElMessage, ElMessageBox } from 'element-plus'
import { Search } from '@element-plus/icons-vue'
import { tunnelApi } from '../api'
import { formatBytes } from '../utils/format'

const list = ref([])
const total = ref(0)
const loading = ref(false)
const query = reactive({ keyword: '', status: '', user_id: '', page: 1, page_size: 20 })

function fmtBytes(v) {
  return formatBytes(v)
}

async function load() {
  loading.value = true
  try {
    const params = { ...query }
    if (!params.user_id) delete params.user_id
    const data = await tunnelApi.list(params)
    list.value = data?.list || []
    total.value = data?.total || 0
  } finally {
    loading.value = false
  }
}

function onPage(p) {
  query.page = p
  load()
}

async function toggle(row) {
  const next = row.status === 'active' ? 'disabled' : 'active'
  await tunnelApi.setStatus(row.id, next)
  ElMessage.success('已更新')
  await load()
}

async function remove(row) {
  await ElMessageBox.confirm(`确定删除隧道「${row.name}」吗？`, '删除确认', { type: 'warning' })
  await tunnelApi.remove(row.id)
  ElMessage.success('已删除')
  await load()
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
