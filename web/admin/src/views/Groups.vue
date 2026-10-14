<template>
  <div class="lt-card">
    <div class="lt-card-title">
      <span>分组权限</span>
      <el-button type="primary" :icon="Plus" @click="openCreate">新建分组</el-button>
    </div>

    <el-alert
      type="info"
      :closable="false"
      show-icon
      style="margin-bottom: 14px"
      title="分组决定用户的隧道数、端口数、流量配额与限速。限速由服务端插件强制下发，客户端无法绕过。"
    />

    <el-table :data="list" v-loading="loading" stripe>
      <el-table-column label="名称" prop="name" min-width="120">
        <template #default="{ row }">
          {{ row.name }}
          <el-tag v-if="row.is_default" size="small" type="success" effect="plain" style="margin-left: 6px">默认</el-tag>
        </template>
      </el-table-column>
      <el-table-column label="隧道数上限" width="110">
        <template #default="{ row }">{{ row.max_tunnels || '不限' }}</template>
      </el-table-column>
      <el-table-column label="端口数上限" width="110">
        <template #default="{ row }">{{ row.max_ports || '不限' }}</template>
      </el-table-column>
      <el-table-column label="月流量" width="110">
        <template #default="{ row }">{{ row.traffic_quota ? fmtBytes(row.traffic_quota) : '不限' }}</template>
      </el-table-column>
      <el-table-column label="单隧道限速" width="130">
        <template #default="{ row }">{{ bandwidthText(row.bandwidth_limit) }}</template>
      </el-table-column>
      <el-table-column label="协议" width="150">
        <template #default="{ row }">
          <el-tag v-for="p in row.allow_protocols.split(',')" :key="p" size="small" effect="plain" style="margin-right: 4px">
            {{ p.toUpperCase() }}
          </el-tag>
        </template>
      </el-table-column>
      <el-table-column label="自定义域名" width="110">
        <template #default="{ row }">{{ row.allow_custom_domain ? '允许' : '禁止' }}</template>
      </el-table-column>
      <el-table-column label="描述" prop="description" min-width="160" show-overflow-tooltip />
      <el-table-column label="操作" width="130" fixed="right">
        <template #default="{ row }">
          <el-button link type="primary" @click="openEdit(row)">编辑</el-button>
          <el-button link type="danger" :disabled="row.is_default" @click="remove(row)">删除</el-button>
        </template>
      </el-table-column>
    </el-table>

    <el-dialog v-model="visible" :title="editing ? '编辑分组' : '新建分组'" width="560px">
      <el-form :model="form" :rules="rules" ref="formRef" label-width="120px">
        <el-form-item label="分组名称" prop="name">
          <el-input v-model="form.name" placeholder="如：标准版" />
        </el-form-item>
        <el-form-item label="描述">
          <el-input v-model="form.description" />
        </el-form-item>
        <el-form-item label="隧道数上限">
          <el-input-number v-model="form.max_tunnels" :min="0" controls-position="right" />
          <span class="lt-muted" style="margin-left: 8px">0 表示不限</span>
        </el-form-item>
        <el-form-item label="端口数上限">
          <el-input-number v-model="form.max_ports" :min="0" controls-position="right" />
        </el-form-item>
        <el-form-item label="月流量配额">
          <el-input-number v-model="form.quota_gb" :min="0" :step="10" controls-position="right" />
          <span class="lt-muted" style="margin-left: 8px">GB，0 表示不限</span>
        </el-form-item>
        <el-form-item label="单隧道限速">
          <el-input-number v-model="form.limit_mbps" :min="0" :step="1" controls-position="right" />
          <span class="lt-muted" style="margin-left: 8px">Mbps，0 表示不限</span>
        </el-form-item>
        <el-form-item label="允许协议">
          <el-checkbox-group v-model="form.protocols">
            <el-checkbox value="tcp">TCP</el-checkbox>
            <el-checkbox value="udp">UDP</el-checkbox>
            <el-checkbox value="http">HTTP</el-checkbox>
            <el-checkbox value="https">HTTPS</el-checkbox>
          </el-checkbox-group>
        </el-form-item>
        <el-form-item label="允许自定义域名">
          <el-switch v-model="form.allow_custom_domain" />
        </el-form-item>
        <el-form-item label="优先级">
          <el-input-number v-model="form.priority" :min="0" controls-position="right" />
          <span class="lt-muted" style="margin-left: 8px">越大越靠前</span>
        </el-form-item>
      </el-form>
      <template #footer>
        <el-button @click="visible = false">取消</el-button>
        <el-button type="primary" :loading="saving" @click="save">保存</el-button>
      </template>
    </el-dialog>
  </div>
</template>

<script setup>
import { onMounted, reactive, ref } from 'vue'
import { ElMessage, ElMessageBox } from 'element-plus'
import { Plus } from '@element-plus/icons-vue'
import { groupApi } from '../api'
import { formatBytes } from '../utils/format'

const list = ref([])
const loading = ref(false)
const saving = ref(false)
const visible = ref(false)
const editing = ref(null)
const formRef = ref()

const form = reactive({
  name: '',
  description: '',
  max_tunnels: 2,
  max_ports: 2,
  quota_gb: 20,
  limit_mbps: 4,
  protocols: ['tcp', 'udp'],
  allow_custom_domain: false,
  priority: 0
})

const rules = {
  name: [{ required: true, message: '请输入分组名称', trigger: 'blur' }]
}

function fmtBytes(v) {
  return formatBytes(v)
}

function bandwidthText(bits) {
  if (!bits) return '不限'
  return `${(bits / 1024 / 1024).toFixed(0)} Mbps`
}

async function load() {
  loading.value = true
  try {
    list.value = (await groupApi.list()) || []
  } finally {
    loading.value = false
  }
}

function openCreate() {
  editing.value = null
  Object.assign(form, {
    name: '',
    description: '',
    max_tunnels: 2,
    max_ports: 2,
    quota_gb: 20,
    limit_mbps: 4,
    protocols: ['tcp', 'udp'],
    allow_custom_domain: false,
    priority: 0
  })
  visible.value = true
}

function openEdit(row) {
  editing.value = row
  Object.assign(form, {
    name: row.name,
    description: row.description || '',
    max_tunnels: row.max_tunnels,
    max_ports: row.max_ports,
    quota_gb: row.traffic_quota ? +(row.traffic_quota / 1024 / 1024 / 1024).toFixed(2) : 0,
    limit_mbps: row.bandwidth_limit ? +(row.bandwidth_limit / 1024 / 1024).toFixed(2) : 0,
    protocols: (row.allow_protocols || '').split(',').filter(Boolean),
    allow_custom_domain: row.allow_custom_domain,
    priority: row.priority
  })
  visible.value = true
}

async function save() {
  await formRef.value.validate()
  if (!form.protocols.length) {
    ElMessage.warning('至少需要允许一种协议')
    return
  }
  const payload = {
    name: form.name,
    description: form.description,
    max_tunnels: form.max_tunnels,
    max_ports: form.max_ports,
    traffic_quota: Math.round(form.quota_gb * 1024 * 1024 * 1024),
    bandwidth_limit: Math.round(form.limit_mbps * 1024 * 1024),
    allow_protocols: form.protocols.join(','),
    allow_custom_domain: form.allow_custom_domain,
    allow_privileged_port: false,
    priority: form.priority
  }
  saving.value = true
  try {
    if (editing.value) {
      await groupApi.update(editing.value.id, payload)
    } else {
      await groupApi.create(payload)
    }
    ElMessage.success('已保存')
    visible.value = false
    await load()
  } finally {
    saving.value = false
  }
}

async function remove(row) {
  await ElMessageBox.confirm(`确定删除分组「${row.name}」吗？`, '删除确认', { type: 'warning' })
  await groupApi.remove(row.id)
  ElMessage.success('已删除')
  await load()
}

onMounted(load)
</script>
