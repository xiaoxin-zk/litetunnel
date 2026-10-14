<template>
  <div>
    <div class="lt-card">
      <div class="lt-card-title">
        <span>用户管理</span>
        <el-button type="primary" :icon="Plus" @click="openCreate">新建用户</el-button>
      </div>

      <div class="filters">
        <el-input v-model="query.keyword" placeholder="搜索用户名 / 邮箱 / 备注" clearable style="width: 240px" @keyup.enter="load" />
        <el-select v-model="query.status" placeholder="状态" clearable style="width: 130px">
          <el-option label="正常" value="active" />
          <el-option label="已禁用" value="disabled" />
          <el-option label="已封禁" value="banned" />
        </el-select>
        <el-select v-model="query.group_id" placeholder="分组" clearable style="width: 150px">
          <el-option v-for="g in groups" :key="g.id" :label="g.name" :value="g.id" />
        </el-select>
        <el-button :icon="Search" @click="load">查询</el-button>
        <el-button :icon="Refresh" @click="resetQuery">重置</el-button>
      </div>

      <el-table :data="list" v-loading="loading" stripe>
        <el-table-column label="ID" prop="id" width="70" />
        <el-table-column label="用户名" prop="username" min-width="120">
          <template #default="{ row }">
            <span>{{ row.username }}</span>
            <el-tag v-if="row.remark" size="small" effect="plain" style="margin-left: 6px">{{ row.remark }}</el-tag>
          </template>
        </el-table-column>
        <el-table-column label="分组" width="110">
          <template #default="{ row }">
            <el-tag size="small" effect="light">{{ row.group_name || '未分组' }}</el-tag>
          </template>
        </el-table-column>
        <el-table-column label="状态" width="90">
          <template #default="{ row }">
            <el-tag size="small" :type="statusType(row.status)">{{ statusLabel(row.status) }}</el-tag>
          </template>
        </el-table-column>
        <el-table-column label="流量" min-width="200">
          <template #default="{ row }">
            <div class="traffic">
              <el-progress
                :percentage="percent(row)"
                :status="row.effective_quota && row.traffic_used >= row.effective_quota ? 'exception' : undefined"
                :stroke-width="8"
                :show-text="false"
              />
              <span class="lt-muted">
                {{ fmtBytes(row.traffic_used) }} /
                {{ row.effective_quota ? fmtBytes(row.effective_quota) : '不限' }}
              </span>
            </div>
          </template>
        </el-table-column>
        <el-table-column label="最近登录" width="160">
          <template #default="{ row }">{{ formatTime(row.last_login_at) }}</template>
        </el-table-column>
        <el-table-column label="操作" width="330" fixed="right">
          <template #default="{ row }">
            <el-button link type="primary" @click="openEdit(row)">编辑</el-button>
            <el-button link type="primary" @click="openQuota(row)">配额</el-button>
            <el-button link type="primary" @click="openGroup(row)">分组</el-button>
            <el-button link type="warning" @click="openPassword(row)">改密</el-button>
            <el-button link :type="row.status === 'active' ? 'warning' : 'success'" @click="toggleStatus(row)">
              {{ row.status === 'active' ? '禁用' : '启用' }}
            </el-button>
            <el-button link type="danger" @click="remove(row)">删除</el-button>
          </template>
        </el-table-column>
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

    <!-- 新建用户 -->
    <el-dialog v-model="createVisible" title="新建用户" width="480px">
      <el-form :model="createForm" :rules="createRules" ref="createRef" label-width="90px">
        <el-form-item label="用户名" prop="username">
          <el-input v-model="createForm.username" placeholder="3-32 位字母、数字或下划线" />
        </el-form-item>
        <el-form-item label="初始密码" prop="password">
          <el-input v-model="createForm.password" show-password placeholder="至少 8 位" />
        </el-form-item>
        <el-form-item label="邮箱">
          <el-input v-model="createForm.email" />
        </el-form-item>
        <el-form-item label="分组">
          <el-select v-model="createForm.group_id" placeholder="选择分组" style="width: 100%">
            <el-option v-for="g in groups" :key="g.id" :label="g.name" :value="g.id" />
          </el-select>
        </el-form-item>
        <el-form-item label="备注">
          <el-input v-model="createForm.remark" placeholder="选填，用于标记用途" />
        </el-form-item>
      </el-form>
      <template #footer>
        <el-button @click="createVisible = false">取消</el-button>
        <el-button type="primary" :loading="saving" @click="doCreate">创建</el-button>
      </template>
    </el-dialog>

    <!-- 编辑用户 -->
    <el-dialog v-model="editVisible" title="编辑用户" width="460px">
      <el-form :model="editForm" label-width="90px">
        <el-form-item label="用户名">
          <el-input :model-value="current?.username" disabled />
        </el-form-item>
        <el-form-item label="昵称">
          <el-input v-model="editForm.nickname" />
        </el-form-item>
        <el-form-item label="邮箱">
          <el-input v-model="editForm.email" />
        </el-form-item>
        <el-form-item label="备注">
          <el-input v-model="editForm.remark" />
        </el-form-item>
      </el-form>
      <template #footer>
        <el-button @click="editVisible = false">取消</el-button>
        <el-button type="primary" :loading="saving" @click="doEdit">保存</el-button>
      </template>
    </el-dialog>

    <!-- 流量配额 -->
    <el-dialog v-model="quotaVisible" title="流量限制" width="480px">
      <el-form label-width="110px">
        <el-form-item label="当前已用">
          <span>{{ fmtBytes(current?.traffic_used) }}</span>
        </el-form-item>
        <el-form-item label="配额模式">
          <el-radio-group v-model="quotaForm.mode">
            <el-radio value="group">跟随分组（{{ groupQuotaText }}）</el-radio>
            <el-radio value="custom">自定义</el-radio>
          </el-radio-group>
        </el-form-item>
        <el-form-item v-if="quotaForm.mode === 'custom'" label="自定义配额">
          <el-input-number v-model="quotaForm.gb" :min="0" :step="10" controls-position="right" />
          <span class="lt-muted" style="margin-left: 8px">GB（0 表示不限）</span>
        </el-form-item>
      </el-form>
      <template #footer>
        <el-button @click="quotaVisible = false">取消</el-button>
        <el-button @click="doResetTraffic">清零已用流量</el-button>
        <el-button type="primary" :loading="saving" @click="doSetQuota">保存</el-button>
      </template>
    </el-dialog>

    <!-- 分组 -->
    <el-dialog v-model="groupVisible" title="分组权限" width="440px">
      <el-form label-width="90px">
        <el-form-item label="用户名">
          <span>{{ current?.username }}</span>
        </el-form-item>
        <el-form-item label="目标分组">
          <el-select v-model="groupForm.group_id" style="width: 100%">
            <el-option v-for="g in groups" :key="g.id" :label="g.name" :value="g.id" />
          </el-select>
        </el-form-item>
        <el-form-item label="到期时间">
          <el-date-picker
            v-model="groupForm.expire_at"
            type="datetime"
            placeholder="留空表示长期有效"
            style="width: 100%"
          />
        </el-form-item>
      </el-form>
      <template #footer>
        <el-button @click="groupVisible = false">取消</el-button>
        <el-button type="primary" :loading="saving" @click="doSetGroup">保存</el-button>
      </template>
    </el-dialog>

    <!-- 重置密码 -->
    <el-dialog v-model="passwordVisible" title="重置密码" width="420px">
      <el-form label-width="90px">
        <el-form-item label="用户名">
          <span>{{ current?.username }}</span>
        </el-form-item>
        <el-form-item label="新密码">
          <el-input v-model="passwordForm.password" show-password placeholder="至少 8 位" />
        </el-form-item>
      </el-form>
      <template #footer>
        <el-button @click="passwordVisible = false">取消</el-button>
        <el-button type="primary" :loading="saving" @click="doResetPassword">重置</el-button>
      </template>
    </el-dialog>
  </div>
</template>

<script setup>
import { onMounted, reactive, ref } from 'vue'
import { ElMessage, ElMessageBox } from 'element-plus'
import { Plus, Search, Refresh } from '@element-plus/icons-vue'
import { userApi, groupApi } from '../api'
import { formatBytes, formatTime } from '../utils/format'

const list = ref([])
const groups = ref([])
const total = ref(0)
const loading = ref(false)
const saving = ref(false)
const current = ref(null)

const query = reactive({ keyword: '', status: '', group_id: '', page: 1, page_size: 20 })

const createVisible = ref(false)
const editVisible = ref(false)
const quotaVisible = ref(false)
const groupVisible = ref(false)
const passwordVisible = ref(false)

const createRef = ref()
const createForm = reactive({ username: '', password: '', email: '', group_id: '', remark: '' })
const editForm = reactive({ nickname: '', email: '', remark: '' })
const quotaForm = reactive({ mode: 'group', gb: 0 })
const groupForm = reactive({ group_id: '', expire_at: null })
const passwordForm = reactive({ password: '' })

const createRules = {
  username: [
    { required: true, message: '请输入用户名', trigger: 'blur' },
    { pattern: /^[A-Za-z0-9_]{3,32}$/, message: '仅允许 3-32 位字母、数字或下划线', trigger: 'blur' }
  ],
  password: [
    { required: true, message: '请输入密码', trigger: 'blur' },
    { min: 8, message: '密码至少 8 位', trigger: 'blur' }
  ]
}

const statusLabels = { active: '正常', disabled: '已禁用', banned: '已封禁' }
const statusTypes = { active: 'success', disabled: 'warning', banned: 'danger' }

function statusLabel(s) {
  return statusLabels[s] || s
}
function statusType(s) {
  return statusTypes[s] || 'info'
}
function fmtBytes(v) {
  return formatBytes(v)
}
function percent(row) {
  if (!row.effective_quota) return 0
  return Math.min(100, Math.round((row.traffic_used / row.effective_quota) * 100))
}

const groupQuotaText = ref('')

async function load() {
  loading.value = true
  try {
    const data = await userApi.list({ ...query })
    list.value = data?.list || []
    total.value = data?.total || 0
  } finally {
    loading.value = false
  }
}

async function loadGroups() {
  groups.value = (await groupApi.list()) || []
}

function resetQuery() {
  Object.assign(query, { keyword: '', status: '', group_id: '', page: 1 })
  load()
}

function onPage(p) {
  query.page = p
  load()
}

function openCreate() {
  Object.assign(createForm, { username: '', password: '', email: '', group_id: '', remark: '' })
  createVisible.value = true
}

async function doCreate() {
  await createRef.value.validate()
  saving.value = true
  try {
    await userApi.create({ ...createForm, group_id: createForm.group_id || 0 })
    ElMessage.success('用户已创建')
    createVisible.value = false
    await load()
  } finally {
    saving.value = false
  }
}

function openEdit(row) {
  current.value = row
  Object.assign(editForm, {
    nickname: row.nickname || '',
    email: row.email || '',
    remark: row.remark || ''
  })
  editVisible.value = true
}

async function doEdit() {
  saving.value = true
  try {
    await userApi.update(current.value.id, { ...editForm })
    ElMessage.success('已保存')
    editVisible.value = false
    await load()
  } finally {
    saving.value = false
  }
}

function openQuota(row) {
  current.value = row
  quotaForm.mode = row.traffic_quota > 0 ? 'custom' : 'group'
  quotaForm.gb = row.traffic_quota > 0 ? +(row.traffic_quota / 1024 / 1024 / 1024).toFixed(2) : 0
  const g = groups.value.find((x) => x.id === row.group_id)
  groupQuotaText.value = g?.traffic_quota ? formatBytes(g.traffic_quota) : '不限'
  quotaVisible.value = true
}

async function doSetQuota() {
  saving.value = true
  try {
    const quota = quotaForm.mode === 'group' ? 0 : Math.round(quotaForm.gb * 1024 * 1024 * 1024)
    await userApi.setQuota(current.value.id, quota)
    ElMessage.success('配额已更新')
    quotaVisible.value = false
    await load()
  } finally {
    saving.value = false
  }
}

async function doResetTraffic() {
  await userApi.resetTraffic(current.value.id)
  ElMessage.success('已清零')
  quotaVisible.value = false
  await load()
}

function openGroup(row) {
  current.value = row
  groupForm.group_id = row.group_id
  groupForm.expire_at = row.group_expire_at ? new Date(row.group_expire_at) : null
  groupVisible.value = true
}

async function doSetGroup() {
  if (!groupForm.group_id) {
    ElMessage.warning('请选择分组')
    return
  }
  saving.value = true
  try {
    await userApi.setGroup(current.value.id, {
      group_id: groupForm.group_id,
      expire_at: groupForm.expire_at ? new Date(groupForm.expire_at).toISOString() : null
    })
    ElMessage.success('分组已更新')
    groupVisible.value = false
    await load()
  } finally {
    saving.value = false
  }
}

function openPassword(row) {
  current.value = row
  passwordForm.password = ''
  passwordVisible.value = true
}

async function doResetPassword() {
  if ((passwordForm.password || '').length < 8) {
    ElMessage.warning('密码至少 8 位')
    return
  }
  saving.value = true
  try {
    await userApi.resetPassword(current.value.id, passwordForm.password)
    ElMessage.success('密码已重置')
    passwordVisible.value = false
  } finally {
    saving.value = false
  }
}

async function toggleStatus(row) {
  const next = row.status === 'active' ? 'disabled' : 'active'
  await userApi.setStatus(row.id, next)
  ElMessage.success(next === 'active' ? '已启用' : '已禁用')
  await load()
}

async function remove(row) {
  await ElMessageBox.confirm(
    `删除用户「${row.username}」将同时删除其全部隧道与流量记录，且不可恢复。确定继续？`,
    '危险操作',
    { type: 'warning', confirmButtonText: '确认删除', cancelButtonText: '取消' }
  )
  await userApi.remove(row.id)
  ElMessage.success('用户已删除')
  await load()
}

onMounted(async () => {
  await Promise.all([loadGroups(), load()])
})
</script>

<style scoped>
.filters {
  display: flex;
  gap: 10px;
  flex-wrap: wrap;
  margin-bottom: 14px;
}

.traffic {
  display: flex;
  flex-direction: column;
  gap: 4px;
}
</style>
