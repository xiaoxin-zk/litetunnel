<template>
  <div>
    <div class="lt-card">
      <div class="lt-card-title">
        <span>兑换码</span>
        <el-button type="primary" :icon="Plus" @click="openGenerate">批量生成</el-button>
      </div>

      <div class="filters">
        <el-input v-model="query.keyword" placeholder="搜索兑换码" clearable style="width: 220px" @keyup.enter="load" />
        <el-select v-model="query.status" placeholder="状态" clearable style="width: 140px">
          <el-option label="未使用" value="unused" />
          <el-option label="已用完" value="used_up" />
          <el-option label="已禁用" value="disabled" />
        </el-select>
        <el-input v-model="query.batch_no" placeholder="批次号" clearable style="width: 180px" @keyup.enter="load" />
        <el-button :icon="Search" @click="load">查询</el-button>
      </div>

      <el-table :data="list" v-loading="loading" stripe>
        <el-table-column label="兑换码" min-width="200">
          <template #default="{ row }">
            <span class="lt-mono">{{ row.code }}</span>
            <el-button link :icon="CopyDocument" @click="copy(row.code)" />
          </template>
        </el-table-column>
        <el-table-column label="类型" width="90">
          <template #default="{ row }">
            <el-tag size="small" effect="plain">{{ typeLabel(row.type) }}</el-tag>
          </template>
        </el-table-column>
        <el-table-column label="面值" width="130">
          <template #default="{ row }">{{ valueText(row) }}</template>
        </el-table-column>
        <el-table-column label="使用情况" width="110">
          <template #default="{ row }">{{ row.used_count }} / {{ row.max_uses }}</template>
        </el-table-column>
        <el-table-column label="状态" width="100">
          <template #default="{ row }">
            <el-tag size="small" :type="statusType(row.status)">{{ statusLabel(row.status) }}</el-tag>
          </template>
        </el-table-column>
        <el-table-column label="批次" prop="batch_no" width="150" />
        <el-table-column label="过期时间" width="160">
          <template #default="{ row }">{{ row.expire_at ? formatTime(row.expire_at) : '长期有效' }}</template>
        </el-table-column>
        <el-table-column label="操作" width="150" fixed="right">
          <template #default="{ row }">
            <el-button link :type="row.status === 'disabled' ? 'success' : 'warning'" @click="toggle(row)">
              {{ row.status === 'disabled' ? '启用' : '禁用' }}
            </el-button>
            <el-button link type="danger" @click="remove(row)">删除</el-button>
          </template>
        </el-table-column>
        <template #empty><el-empty description="暂无兑换码" /></template>
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

    <el-dialog v-model="visible" title="批量生成兑换码" width="520px">
      <el-form :model="form" label-width="110px">
        <el-form-item label="类型">
          <el-radio-group v-model="form.type">
            <el-radio-button value="traffic">流量</el-radio-button>
            <el-radio-button value="group">升级分组</el-radio-button>
            <el-radio-button value="balance">余额</el-radio-button>
            <el-radio-button value="duration">时长</el-radio-button>
          </el-radio-group>
        </el-form-item>

        <el-form-item v-if="form.type === 'traffic'" label="流量额度">
          <el-input-number v-model="form.gb" :min="1" :step="10" controls-position="right" />
          <span class="lt-muted" style="margin-left: 8px">GB</span>
        </el-form-item>

        <el-form-item v-if="form.type === 'group'" label="目标分组">
          <el-select v-model="form.group_id" style="width: 100%">
            <el-option v-for="g in groups" :key="g.id" :label="g.name" :value="g.id" />
          </el-select>
        </el-form-item>

        <el-form-item v-if="form.type === 'balance'" label="充值金额">
          <el-input-number v-model="form.yuan" :min="0.01" :step="1" :precision="2" controls-position="right" />
          <span class="lt-muted" style="margin-left: 8px">元</span>
        </el-form-item>

        <el-form-item v-if="form.type === 'duration'" label="延长天数">
          <el-input-number v-model="form.days" :min="1" controls-position="right" />
          <span class="lt-muted" style="margin-left: 8px">天</span>
        </el-form-item>

        <el-form-item label="生成数量">
          <el-input-number v-model="form.count" :min="1" :max="500" controls-position="right" />
        </el-form-item>
        <el-form-item label="每码可用次数">
          <el-input-number v-model="form.max_uses" :min="1" controls-position="right" />
        </el-form-item>
        <el-form-item label="过期时间">
          <el-date-picker v-model="form.expire_at" type="datetime" placeholder="留空表示长期有效" style="width: 100%" />
        </el-form-item>
        <el-form-item label="备注">
          <el-input v-model="form.remark" />
        </el-form-item>
      </el-form>
      <template #footer>
        <el-button @click="visible = false">取消</el-button>
        <el-button type="primary" :loading="saving" @click="generate">生成</el-button>
      </template>
    </el-dialog>

    <el-dialog v-model="resultVisible" title="生成成功" width="560px">
      <el-alert type="success" :closable="false" :title="`批次 ${result.batch_no}，共 ${result.count} 个兑换码`" style="margin-bottom: 12px" />
      <el-input v-model="resultText" type="textarea" :rows="10" readonly class="lt-mono" />
      <template #footer>
        <el-button @click="copyAll">复制全部</el-button>
        <el-button type="primary" @click="resultVisible = false">完成</el-button>
      </template>
    </el-dialog>
  </div>
</template>

<script setup>
import { computed, onMounted, reactive, ref } from 'vue'
import { ElMessage, ElMessageBox } from 'element-plus'
import { Plus, Search, CopyDocument } from '@element-plus/icons-vue'
import { redeemApi, groupApi } from '../api'
import { formatBytes, formatTime, copyText } from '../utils/format'

const list = ref([])
const groups = ref([])
const total = ref(0)
const loading = ref(false)
const saving = ref(false)
const visible = ref(false)
const resultVisible = ref(false)
const result = ref({ batch_no: '', count: 0, codes: [] })

const query = reactive({ keyword: '', status: '', batch_no: '', page: 1, page_size: 20 })

const form = reactive({
  type: 'traffic',
  gb: 50,
  group_id: '',
  yuan: 10,
  days: 30,
  count: 10,
  max_uses: 1,
  expire_at: null,
  remark: ''
})

const resultText = computed(() => (result.value.codes || []).join('\n'))

const typeLabels = { traffic: '流量', group: '分组', balance: '余额', duration: '时长' }
const statusLabels = { unused: '未使用', used_up: '已用完', disabled: '已禁用' }
const statusTypes = { unused: 'success', used_up: 'info', disabled: 'warning' }

function typeLabel(t) {
  return typeLabels[t] || t
}
function statusLabel(s) {
  return statusLabels[s] || s
}
function statusType(s) {
  return statusTypes[s] || 'info'
}

function valueText(row) {
  switch (row.type) {
    case 'traffic':
      return formatBytes(row.value)
    case 'balance':
      return '¥ ' + (row.value / 100).toFixed(2)
    case 'duration':
      return row.value + ' 天'
    case 'group':
      return '升级分组 #' + row.value
    default:
      return String(row.value)
  }
}

async function load() {
  loading.value = true
  try {
    const data = await redeemApi.list({ ...query })
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

function openGenerate() {
  visible.value = true
}

async function generate() {
  const payload = {
    type: form.type,
    count: form.count,
    max_uses: form.max_uses,
    expire_at: form.expire_at ? new Date(form.expire_at).toISOString() : null,
    remark: form.remark,
    value: 0,
    group_id: 0
  }
  if (form.type === 'traffic') payload.value = Math.round(form.gb * 1024 * 1024 * 1024)
  if (form.type === 'balance') payload.value = Math.round(form.yuan * 100)
  if (form.type === 'duration') payload.value = form.days
  if (form.type === 'group') {
    if (!form.group_id) {
      ElMessage.warning('请选择目标分组')
      return
    }
    payload.group_id = form.group_id
  }

  saving.value = true
  try {
    const data = await redeemApi.generate(payload)
    result.value = data
    visible.value = false
    resultVisible.value = true
    await load()
  } finally {
    saving.value = false
  }
}

async function toggle(row) {
  const next = row.status === 'disabled' ? 'unused' : 'disabled'
  await redeemApi.setStatus(row.id, next)
  ElMessage.success('已更新')
  await load()
}

async function remove(row) {
  await ElMessageBox.confirm(`确定删除兑换码 ${row.code} 吗？`, '删除确认', { type: 'warning' })
  await redeemApi.remove(row.id)
  ElMessage.success('已删除')
  await load()
}

async function copy(text) {
  const ok = await copyText(text)
  ElMessage[ok ? 'success' : 'error'](ok ? '已复制' : '复制失败')
}

async function copyAll() {
  await copy(resultText.value)
}

onMounted(async () => {
  groups.value = (await groupApi.list()) || []
  await load()
})
</script>

<style scoped>
.filters {
  display: flex;
  gap: 10px;
  flex-wrap: wrap;
  margin-bottom: 14px;
}
</style>
