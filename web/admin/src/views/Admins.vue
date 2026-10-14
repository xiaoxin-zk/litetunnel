<template>
  <div class="lt-card">
    <div class="lt-card-title">
      <span>管理员管理</span>
      <el-button type="primary" :icon="Plus" @click="openCreate">新建管理员</el-button>
    </div>

    <el-alert
      type="info"
      :closable="false"
      show-icon
      style="margin-bottom: 14px"
      title="角色说明"
      description="超级管理员：全部权限，含管理员账号管理；运营：可执行业务写操作，但不能管理管理员；审计只读：仅可查看数据。系统始终保留至少一个启用的超级管理员。"
    />

    <el-table :data="list" v-loading="loading" stripe>
      <el-table-column label="ID" prop="id" width="70" />
      <el-table-column label="账号" prop="username" min-width="130" />
      <el-table-column label="昵称" prop="nickname" min-width="120" />
      <el-table-column label="角色" width="120">
        <template #default="{ row }">
          <el-tag size="small" :type="roleType(row.role)" effect="light">{{ roleLabel(row.role) }}</el-tag>
        </template>
      </el-table-column>
      <el-table-column label="状态" width="90">
        <template #default="{ row }">
          <el-tag size="small" :type="row.status === 'active' ? 'success' : 'info'">
            {{ row.status === 'active' ? '正常' : '已禁用' }}
          </el-tag>
        </template>
      </el-table-column>
      <el-table-column label="双因素" width="90">
        <template #default="{ row }">
          <el-tag size="small" :type="row.totp_enabled ? 'success' : 'danger'">
            {{ row.totp_enabled ? '已启用' : '未启用' }}
          </el-tag>
        </template>
      </el-table-column>
      <el-table-column label="最近登录" width="160">
        <template #default="{ row }">{{ formatTime(row.last_login_at) }}</template>
      </el-table-column>
      <el-table-column label="登录 IP" width="140">
        <template #default="{ row }"><span class="lt-mono">{{ row.last_login_ip || '-' }}</span></template>
      </el-table-column>
      <el-table-column label="操作" width="260" fixed="right">
        <template #default="{ row }">
          <el-button link type="primary" @click="openEdit(row)">编辑</el-button>
          <el-button link type="primary" @click="openPassword(row)">改密</el-button>
          <el-button v-if="row.totp_enabled" link type="warning" @click="clearTOTP(row)">重置2FA</el-button>
          <el-button
            link
            type="danger"
            :disabled="row.id === currentAdminId"
            @click="remove(row)"
          >
            删除
          </el-button>
        </template>
      </el-table-column>
      <template #empty><el-empty description="暂无管理员" /></template>
    </el-table>

    <!-- 新建 -->
    <el-dialog v-model="createVisible" title="新建管理员" width="480px">
      <el-form :model="createForm" :rules="createRules" ref="createRef" label-width="100px">
        <el-form-item label="登录账号" prop="username">
          <el-input v-model="createForm.username" placeholder="3-32 位字母、数字或下划线" />
        </el-form-item>
        <el-form-item label="初始密码" prop="password">
          <el-input v-model="createForm.password" show-password placeholder="至少 12 位" />
        </el-form-item>
        <el-form-item label="昵称">
          <el-input v-model="createForm.nickname" placeholder="选填" />
        </el-form-item>
        <el-form-item label="角色">
          <el-select v-model="createForm.role" style="width: 100%">
            <el-option label="运营（可写，不可管理管理员）" value="operator" />
            <el-option label="审计只读" value="auditor" />
            <el-option label="超级管理员" value="super" />
          </el-select>
        </el-form-item>
      </el-form>
      <template #footer>
        <el-button @click="createVisible = false">取消</el-button>
        <el-button type="primary" :loading="saving" @click="doCreate">创建</el-button>
      </template>
    </el-dialog>

    <!-- 编辑 -->
    <el-dialog v-model="editVisible" title="编辑管理员" width="460px">
      <el-form :model="editForm" label-width="100px">
        <el-form-item label="登录账号">
          <el-input :model-value="current?.username" disabled />
        </el-form-item>
        <el-form-item label="昵称">
          <el-input v-model="editForm.nickname" />
        </el-form-item>
        <el-form-item label="角色">
          <el-select v-model="editForm.role" :disabled="current?.id === currentAdminId" style="width: 100%">
            <el-option label="运营" value="operator" />
            <el-option label="审计只读" value="auditor" />
            <el-option label="超级管理员" value="super" />
          </el-select>
        </el-form-item>
        <el-form-item label="状态">
          <el-radio-group v-model="editForm.status" :disabled="current?.id === currentAdminId">
            <el-radio value="active">正常</el-radio>
            <el-radio value="disabled">禁用</el-radio>
          </el-radio-group>
        </el-form-item>
      </el-form>
      <el-alert
        v-if="current?.id === currentAdminId"
        type="info"
        :closable="false"
        show-icon
        title="不能修改自己的角色或状态"
        description="这是为了避免把自己锁在后台之外。"
        style="margin-top: 8px"
      />
      <template #footer>
        <el-button @click="editVisible = false">取消</el-button>
        <el-button type="primary" :loading="saving" @click="doEdit">保存</el-button>
      </template>
    </el-dialog>

    <!-- 改密 -->
    <el-dialog v-model="passwordVisible" title="重置登录密码" width="440px">
      <el-form label-width="100px">
        <el-form-item label="登录账号">
          <span>{{ current?.username }}</span>
        </el-form-item>
        <el-form-item label="新密码">
          <el-input v-model="newPassword" show-password placeholder="至少 12 位" />
        </el-form-item>
      </el-form>
      <el-alert
        type="warning"
        :closable="false"
        show-icon
        title="该账号所有会话将立即下线"
        description="密码变更后令牌版本自增，旧令牌即使未过期也会被拒绝。"
        style="margin-top: 8px"
      />
      <template #footer>
        <el-button @click="passwordVisible = false">取消</el-button>
        <el-button type="primary" :loading="saving" @click="doSetPassword">重置</el-button>
      </template>
    </el-dialog>
  </div>
</template>

<script setup>
import { onMounted, reactive, ref } from 'vue'
import { ElMessage, ElMessageBox } from 'element-plus'
import { Plus } from '@element-plus/icons-vue'
import { adminApi, authApi } from '../api'
import { formatTime } from '../utils/format'

const list = ref([])
const loading = ref(false)
const saving = ref(false)
const current = ref(null)
const currentAdminId = ref(0)

const createVisible = ref(false)
const editVisible = ref(false)
const passwordVisible = ref(false)
const newPassword = ref('')

const createRef = ref()
const createForm = reactive({ username: '', password: '', nickname: '', role: 'operator' })
const editForm = reactive({ nickname: '', role: 'operator', status: 'active' })

const createRules = {
  username: [
    { required: true, message: '请输入登录账号', trigger: 'blur' },
    { pattern: /^[A-Za-z0-9_]{3,32}$/, message: '仅允许 3-32 位字母、数字或下划线', trigger: 'blur' }
  ],
  password: [
    { required: true, message: '请输入初始密码', trigger: 'blur' },
    { min: 12, message: '管理员密码至少 12 位', trigger: 'blur' }
  ]
}

const roleLabels = { super: '超级管理员', operator: '运营', auditor: '审计只读' }
const roleTypes = { super: 'danger', operator: 'primary', auditor: 'info' }

function roleLabel(r) {
  return roleLabels[r] || r
}
function roleType(r) {
  return roleTypes[r] || 'info'
}

async function load() {
  loading.value = true
  try {
    list.value = (await adminApi.list()) || []
  } finally {
    loading.value = false
  }
}

function openCreate() {
  Object.assign(createForm, { username: '', password: '', nickname: '', role: 'operator' })
  createVisible.value = true
}

async function doCreate() {
  await createRef.value.validate()
  saving.value = true
  try {
    await adminApi.create({ ...createForm })
    ElMessage.success('管理员已创建')
    createVisible.value = false
    await load()
  } finally {
    saving.value = false
  }
}

function openEdit(row) {
  current.value = row
  Object.assign(editForm, { nickname: row.nickname || '', role: row.role, status: row.status })
  editVisible.value = true
}

async function doEdit() {
  saving.value = true
  try {
    await adminApi.update(current.value.id, { ...editForm })
    ElMessage.success('已保存')
    editVisible.value = false
    await load()
  } finally {
    saving.value = false
  }
}

function openPassword(row) {
  current.value = row
  newPassword.value = ''
  passwordVisible.value = true
}

async function doSetPassword() {
  if ((newPassword.value || '').length < 12) {
    ElMessage.warning('管理员密码至少 12 位')
    return
  }
  saving.value = true
  try {
    await adminApi.setPassword(current.value.id, newPassword.value)
    ElMessage.success('密码已重置')
    passwordVisible.value = false
  } finally {
    saving.value = false
  }
}

async function clearTOTP(row) {
  await ElMessageBox.confirm(
    `确定清除「${row.username}」的双因素绑定吗？清除后该账号仅凭密码即可登录。`,
    '清除双因素认证',
    { type: 'warning', confirmButtonText: '确认清除', cancelButtonText: '取消' }
  )
  await adminApi.clearTOTP(row.id)
  ElMessage.success('已清除')
  await load()
}

async function remove(row) {
  await ElMessageBox.confirm(
    `确定删除管理员「${row.username}」吗？该操作不可恢复。`,
    '删除确认',
    { type: 'warning', confirmButtonText: '确认删除', cancelButtonText: '取消' }
  )
  await adminApi.remove(row.id)
  ElMessage.success('已删除')
  await load()
}

onMounted(async () => {
  const me = await authApi.profile()
  currentAdminId.value = me?.id || 0
  await load()
})
</script>
