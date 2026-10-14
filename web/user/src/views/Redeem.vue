<template>
  <div>
    <el-row :gutter="16">
      <el-col :xs="24" :md="10">
        <div class="lt-card">
          <div class="lt-card-title">兑换码</div>
          <el-input
            v-model="code"
            size="large"
            placeholder="请输入兑换码，如 LT-XXXX-XXXX-XXXX"
            class="lt-mono"
            @keyup.enter="submit"
          >
            <template #prefix><el-icon><Ticket /></el-icon></template>
          </el-input>
          <el-button type="primary" size="large" style="width: 100%; margin-top: 14px" :loading="loading" @click="submit">
            立即兑换
          </el-button>
          <div class="lt-muted" style="margin-top: 12px; line-height: 1.7">
            兑换码可增加流量额度、提升分组、充值余额或延长有效期。<br />
            兑换成功后隧道限速与配额会立即生效。
          </div>
        </div>
      </el-col>

      <el-col :xs="24" :md="14">
        <div class="lt-card">
          <div class="lt-card-title">
            <span>兑换记录</span>
            <el-button link :icon="Refresh" @click="load">刷新</el-button>
          </div>
          <el-table :data="records" v-loading="tableLoading" stripe size="small">
            <el-table-column label="兑换码" prop="code" min-width="180">
              <template #default="{ row }"><span class="lt-mono">{{ row.code }}</span></template>
            </el-table-column>
            <el-table-column label="类型" width="100">
              <template #default="{ row }">{{ typeLabel(row.type) }}</template>
            </el-table-column>
            <el-table-column label="结果" width="90">
              <template #default="{ row }">
                <el-tag size="small" :type="row.result === 'success' ? 'success' : 'danger'">
                  {{ row.result === 'success' ? '成功' : '失败' }}
                </el-tag>
              </template>
            </el-table-column>
            <el-table-column label="时间" width="160">
              <template #default="{ row }">{{ formatTime(row.created_at) }}</template>
            </el-table-column>
            <template #empty><el-empty description="暂无兑换记录" /></template>
          </el-table>
          <el-pagination
            v-if="total > pageSize"
            layout="prev, pager, next"
            :total="total"
            :page-size="pageSize"
            :current-page="page"
            @current-change="onPage"
            style="margin-top: 12px; justify-content: flex-end"
          />
        </div>
      </el-col>
    </el-row>
  </div>
</template>

<script setup>
import { onMounted, ref } from 'vue'
import { ElMessage } from 'element-plus'
import { Ticket, Refresh } from '@element-plus/icons-vue'
import { redeemApi } from '../api'
import { formatTime } from '../utils/format'

const emit = defineEmits(['refresh-profile'])

const code = ref('')
const loading = ref(false)
const tableLoading = ref(false)
const records = ref([])
const total = ref(0)
const page = ref(1)
const pageSize = ref(10)

const typeLabels = {
  traffic: '流量',
  group: '分组',
  balance: '余额',
  duration: '时长'
}

function typeLabel(t) {
  return typeLabels[t] || t || '-'
}

async function submit() {
  const value = code.value.trim()
  if (!value) {
    ElMessage.warning('请输入兑换码')
    return
  }
  loading.value = true
  try {
    const res = await redeemApi.submit(value)
    ElMessage.success(res?.message || '兑换成功')
    code.value = ''
    await load()
    emit('refresh-profile')
  } finally {
    loading.value = false
  }
}

async function load() {
  tableLoading.value = true
  try {
    const data = await redeemApi.records({ page: page.value, page_size: pageSize.value })
    records.value = data?.list || []
    total.value = data?.total || 0
  } finally {
    tableLoading.value = false
  }
}

function onPage(p) {
  page.value = p
  load()
}

onMounted(load)
</script>
