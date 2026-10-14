<template>
  <div>
    <el-row :gutter="16">
      <el-col :xs="24" :md="13">
        <div class="lt-card">
          <div class="lt-card-title">账号资料</div>

          <el-form :model="form" :rules="rules" ref="formRef" label-width="96px">
            <el-form-item label="用户名" prop="username">
              <el-input v-model="form.username" placeholder="3-32 位字母、数字或下划线" />
              <div class="lt-muted hint">
                修改用户名不会影响已连接的客户端，但登录账号会随之变更。
              </div>
            </el-form-item>

            <el-form-item label="昵称" prop="nickname">
              <el-input v-model="form.nickname" placeholder="用于界面显示，可留空" />
            </el-form-item>

            <el-form-item label="邮箱" prop="email">
              <el-input v-model="form.email" placeholder="选填，用于后续找回账号" />
              <div class="lt-muted hint">
                平台暂未开通邮件发送，邮箱仅作为联系方式留存。
              </div>
            </el-form-item>

            <el-button type="primary" :loading="saving" @click="submitProfile">保存资料</el-button>
          </el-form>
        </div>
      </el-col>

      <el-col :xs="24" :md="11">
        <div class="lt-card">
          <div class="lt-card-title">修改密码</div>
          <el-form :model="pwd" :rules="pwdRules" ref="pwdRef" label-width="90px">
            <el-form-item label="原密码" prop="old_password">
              <el-input v-model="pwd.old_password" type="password" show-password />
            </el-form-item>
            <el-form-item label="新密码" prop="new_password">
              <el-input v-model="pwd.new_password" type="password" show-password placeholder="至少 8 位" />
            </el-form-item>
            <el-form-item label="确认密码" prop="confirm">
              <el-input v-model="pwd.confirm" type="password" show-password />
            </el-form-item>
            <el-button type="primary" :loading="changingPwd" @click="submitPassword">保存并重新登录</el-button>
          </el-form>
        </div>

        <div class="lt-card" style="margin-top: 16px">
          <div class="lt-card-title">账号状态</div>
          <el-descriptions :column="1" border size="small">
            <el-descriptions-item label="当前分组">{{ profile?.group?.name || '未分组' }}</el-descriptions-item>
            <el-descriptions-item label="分组到期">
              {{ profile?.group_expire_at ? formatTime(profile.group_expire_at) : '长期有效' }}
            </el-descriptions-item>
            <el-descriptions-item label="账户余额">
              ¥ {{ ((profile?.balance || 0) / 100).toFixed(2) }}
            </el-descriptions-item>
            <el-descriptions-item label="注册时间">{{ formatTime(profile?.created_at) }}</el-descriptions-item>
            <el-descriptions-item label="上次登录">{{ formatTime(profile?.last_login_at) }}</el-descriptions-item>
          </el-descriptions>
        </div>
      </el-col>
    </el-row>

    <div class="lt-card danger-zone">
      <div class="lt-card-title" style="color: #b91c1c">危险操作</div>
      <div class="danger-row">
        <div>
          <div class="danger-title">注销账号</div>
          <div class="lt-muted">
            将永久删除你的账号、全部隧道与流量记录，且不可恢复。
            兑换记录与登录日志会作为审计数据保留。
          </div>
        </div>
        <el-button type="danger" plain @click="deleteVisible = true">注销账号</el-button>
      </div>
    </div>

    <el-dialog v-model="deleteVisible" title="确认注销账号" width="440px" :close-on-click-modal="false">
      <el-alert
        type="error"
        :closable="false"
        show-icon
        title="此操作不可恢复"
        description="账号、隧道与流量记录将被永久删除。请输入登录密码以确认。"
        style="margin-bottom: 16px"
      />
      <el-input v-model="deletePassword" type="password" show-password placeholder="输入登录密码" />
      <template #footer>
        <el-button @click="deleteVisible = false">取消</el-button>
        <el-button type="danger" :loading="deleting" @click="confirmDelete">确认注销</el-button>
      </template>
    </el-dialog>
  </div>
</template>

<script setup>
import { inject, reactive, ref, watch } from 'vue'
import { useRouter } from 'vue-router'
import { ElMessage } from 'element-plus'
import { profileApi, TOKEN_KEY } from '../api'
import { formatTime } from '../utils/format'

const props = defineProps({ profile: Object })
const router = useRouter()
const reloadProfile = inject('reloadProfile', null)

const formRef = ref()
const pwdRef = ref()
const saving = ref(false)
const changingPwd = ref(false)

const deleteVisible = ref(false)
const deletePassword = ref('')
const deleting = ref(false)

const form = reactive({ username: '', nickname: '', email: '' })
const pwd = reactive({ old_password: '', new_password: '', confirm: '' })

const rules = {
  username: [
    { required: true, message: '请输入用户名', trigger: 'blur' },
    { pattern: /^[A-Za-z0-9_]{3,32}$/, message: '仅允许 3-32 位字母、数字或下划线', trigger: 'blur' }
  ],
  email: [
    {
      validator: (_r, value, cb) => {
        if (!value) return cb()
        if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(value)) return cb(new Error('邮箱格式不正确'))
        cb()
      },
      trigger: 'blur'
    }
  ]
}

const pwdRules = {
  old_password: [{ required: true, message: '请输入原密码', trigger: 'blur' }],
  new_password: [
    { required: true, message: '请输入新密码', trigger: 'blur' },
    { min: 8, message: '密码至少 8 位', trigger: 'blur' }
  ],
  confirm: [
    {
      validator: (_r, value, cb) => {
        if (value !== pwd.new_password) cb(new Error('两次输入的密码不一致'))
        else cb()
      },
      trigger: 'blur'
    }
  ]
}

// 资料加载完成后回填表单。
watch(
  () => props.profile,
  (p) => {
    if (!p) return
    form.username = p.username || ''
    form.nickname = p.nickname || ''
    form.email = p.email || ''
  },
  { immediate: true }
)

async function submitProfile() {
  await formRef.value.validate()
  saving.value = true
  try {
    await profileApi.update({
      username: form.username,
      nickname: form.nickname,
      email: form.email
    })
    ElMessage.success('资料已保存')
    if (reloadProfile) await reloadProfile()
  } finally {
    saving.value = false
  }
}

async function submitPassword() {
  await pwdRef.value.validate()
  changingPwd.value = true
  try {
    await profileApi.changePassword({
      old_password: pwd.old_password,
      new_password: pwd.new_password
    })
    ElMessage.success('密码已修改，请重新登录')
    localStorage.removeItem(TOKEN_KEY)
    router.push('/login')
  } finally {
    changingPwd.value = false
  }
}

async function confirmDelete() {
  if (!deletePassword.value) {
    ElMessage.warning('请输入登录密码')
    return
  }
  deleting.value = true
  try {
    await profileApi.deleteAccount(deletePassword.value)
    ElMessage.success('账号已注销')
    localStorage.removeItem(TOKEN_KEY)
    router.push('/login')
  } finally {
    deleting.value = false
  }
}
</script>

<style scoped>
.hint {
  margin-top: 4px;
  line-height: 1.6;
}

.danger-zone {
  margin-top: 16px;
  border: 1px solid #fee2e2;
}

.danger-row {
  display: flex;
  align-items: center;
  justify-content: space-between;
  gap: 20px;
}

.danger-title {
  font-weight: 600;
  margin-bottom: 4px;
}
</style>
