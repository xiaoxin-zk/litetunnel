<template>
  <div>
    <el-row :gutter="16">
      <el-col :xs="24" :md="12">
        <div class="lt-card">
          <div class="lt-card-title">账号信息</div>
          <el-descriptions :column="1" border>
            <el-descriptions-item label="用户名">{{ profile?.username || '-' }}</el-descriptions-item>
            <el-descriptions-item label="昵称">{{ profile?.nickname || '-' }}</el-descriptions-item>
            <el-descriptions-item label="邮箱">{{ profile?.email || '未填写' }}</el-descriptions-item>
            <el-descriptions-item label="当前分组">{{ profile?.group?.name || '未分组' }}</el-descriptions-item>
            <el-descriptions-item label="分组到期">
              {{ profile?.group_expire_at ? formatTime(profile.group_expire_at) : '长期有效' }}
            </el-descriptions-item>
            <el-descriptions-item label="注册时间">{{ formatTime(profile?.created_at) }}</el-descriptions-item>
            <el-descriptions-item label="上次登录">{{ formatTime(profile?.last_login_at) }}</el-descriptions-item>
          </el-descriptions>
        </div>
      </el-col>

      <el-col :xs="24" :md="12">
        <div class="lt-card">
          <div class="lt-card-title">修改密码</div>
          <el-form :model="form" :rules="rules" ref="formRef" label-width="90px">
            <el-form-item label="原密码" prop="old_password">
              <el-input v-model="form.old_password" type="password" show-password />
            </el-form-item>
            <el-form-item label="新密码" prop="new_password">
              <el-input v-model="form.new_password" type="password" show-password placeholder="至少 8 位" />
            </el-form-item>
            <el-form-item label="确认密码" prop="confirm">
              <el-input v-model="form.confirm" type="password" show-password />
            </el-form-item>
            <el-button type="primary" :loading="saving" @click="submit">保存修改</el-button>
          </el-form>
        </div>
      </el-col>
    </el-row>
  </div>
</template>

<script setup>
import { reactive, ref } from 'vue'
import { useRouter } from 'vue-router'
import { ElMessage } from 'element-plus'
import { profileApi, TOKEN_KEY } from '../api'
import { formatTime } from '../utils/format'

const props = defineProps({ profile: Object })
const router = useRouter()

const formRef = ref()
const saving = ref(false)
const form = reactive({ old_password: '', new_password: '', confirm: '' })

const rules = {
  old_password: [{ required: true, message: '请输入原密码', trigger: 'blur' }],
  new_password: [
    { required: true, message: '请输入新密码', trigger: 'blur' },
    { min: 8, message: '密码至少 8 位', trigger: 'blur' }
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
    await profileApi.changePassword({
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
</script>
