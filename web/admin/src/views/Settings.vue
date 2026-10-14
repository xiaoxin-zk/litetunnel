<template>
  <div>
    <el-row :gutter="16">
      <el-col :xs="24" :md="12">
        <div class="lt-card">
          <div class="lt-card-title">管理员信息</div>
          <el-descriptions :column="1" border>
            <el-descriptions-item label="账号">{{ admin?.username || '-' }}</el-descriptions-item>
            <el-descriptions-item label="昵称">{{ admin?.nickname || '-' }}</el-descriptions-item>
            <el-descriptions-item label="角色">{{ roleLabel }}</el-descriptions-item>
            <el-descriptions-item label="上次登录">{{ formatTime(admin?.last_login_at) }}</el-descriptions-item>
            <el-descriptions-item label="上次登录 IP">
              <span class="lt-mono">{{ admin?.last_login_ip || '-' }}</span>
            </el-descriptions-item>
          </el-descriptions>

          <el-alert
            type="info"
            :closable="false"
            show-icon
            style="margin-top: 16px"
            title="管理员账号无法在界面中自助创建"
            description="账号在服务首次启动时按 .env 中的 LT_BOOTSTRAP_ADMIN_USER / LT_BOOTSTRAP_ADMIN_PASSWORD 播种。如需新增或重置，请修改 .env 后清空 lt_admins 表重启，或直接操作数据库。"
          />
        </div>
      </el-col>

      <el-col :xs="24" :md="12">
        <div class="lt-card">
          <div class="lt-card-title">修改登录密码</div>
          <el-form :model="form" :rules="rules" ref="formRef" label-width="90px">
            <el-form-item label="原密码" prop="old_password">
              <el-input v-model="form.old_password" type="password" show-password />
            </el-form-item>
            <el-form-item label="新密码" prop="new_password">
              <el-input v-model="form.new_password" type="password" show-password placeholder="至少 12 位" />
            </el-form-item>
            <el-form-item label="确认密码" prop="confirm">
              <el-input v-model="form.confirm" type="password" show-password />
            </el-form-item>
            <el-button type="primary" :loading="saving" @click="submit">保存并重新登录</el-button>
          </el-form>

          <el-divider />

          <div class="lt-muted" style="line-height: 1.9">
            管理员口令是平台的最高权限入口，策略比普通用户更严格：<br />
            长度不少于 12 位，且不允许与原密码相同。<br />
            修改后当前令牌立即失效，需要重新登录。
          </div>
        </div>
      </el-col>
    </el-row>
  </div>
</template>

<script setup>
import { computed, onMounted, reactive, ref } from 'vue'
import { useRouter } from 'vue-router'
import { ElMessage } from 'element-plus'
import { authApi, TOKEN_KEY } from '../api'
import { formatTime } from '../utils/format'

const router = useRouter()
const admin = ref(null)
const formRef = ref()
const saving = ref(false)
const form = reactive({ old_password: '', new_password: '', confirm: '' })

const roleLabels = { super: '超级管理员', operator: '运营', auditor: '审计只读' }
const roleLabel = computed(() => roleLabels[admin.value?.role] || admin.value?.role || '-')

const rules = {
  old_password: [{ required: true, message: '请输入原密码', trigger: 'blur' }],
  new_password: [
    { required: true, message: '请输入新密码', trigger: 'blur' },
    { min: 12, message: '管理员密码至少 12 位', trigger: 'blur' }
  ],
  confirm: [
    {
      validator: (_r, value, cb) => {
        if (value !== form.new_password) cb(new Error('两次输入的密码不一致'))
        else cb()
      },
      trigger: 'blur'
    }
  ]
}

async function submit() {
  await formRef.value.validate()
  saving.value = true
  try {
    await authApi.changePassword({
      old_password: form.old_password,
      new_password: form.new_password
    })
    ElMessage.success('密码已修改，请重新登录')
    localStorage.removeItem(TOKEN_KEY)
    router.push('/login')
  } finally {
    saving.value = false
  }
}

onMounted(async () => {
  admin.value = await authApi.profile()
})
</script>
