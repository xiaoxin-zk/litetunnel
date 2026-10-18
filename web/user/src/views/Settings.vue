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
              <!-- 启用邮件后邮箱只读：换地址要走「验证新邮箱」的流程，
                   否则拿到被盗会话的人可以先把邮箱改成自己的，再用找回密码接管账号 -->
              <el-input v-model="form.email" :disabled="mailEnabled" placeholder="选填，用于后续找回账号" />
              <div class="lt-muted hint">
                <template v-if="mailEnabled">邮箱用于找回密码。更换需要验证新地址，请点右侧「更换邮箱」。</template>
                <template v-else>平台暂未开通邮件发送，邮箱仅作为联系方式留存。</template>
              </div>
            </el-form-item>

            <el-form-item>
              <el-button type="primary" :loading="saving" @click="submitProfile">保存资料</el-button>
              <el-button v-if="mailEnabled" @click="openEmailChange">更换邮箱</el-button>
            </el-form-item>
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
            <!-- 余额只在站点启用支付后展示：没有充值入口时它没有任何操作意义 -->
            <el-descriptions-item v-if="paymentEnabled" label="账户余额">
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

    <el-dialog v-model="emailVisible" title="更换邮箱" width="460px" :close-on-click-modal="false">
      <el-alert
        type="info"
        :closable="false"
        show-icon
        title="需要两步：先验证新地址"
        description="验证码会发到新邮箱。邮箱是找回密码的唯一凭据，所以必须确认这个地址确实属于你。"
        style="margin-bottom: 16px"
      />
      <el-form label-width="90px">
        <el-form-item label="新邮箱">
          <el-input v-model="emailForm.email" placeholder="新的邮箱地址" />
        </el-form-item>
        <el-form-item label="登录密码">
          <el-input v-model="emailForm.password" type="password" show-password placeholder="确认是本人操作" />
        </el-form-item>
        <el-form-item label="验证码">
          <el-input v-model="emailForm.code" maxlength="6" placeholder="6 位验证码">
            <template #append>
              <el-button :disabled="emailCountdown > 0 || sendingEmail" :loading="sendingEmail" @click="sendEmailCode">
                {{ emailCountdown > 0 ? `${emailCountdown}s` : '发送验证码' }}
              </el-button>
            </template>
          </el-input>
        </el-form-item>
      </el-form>
      <template #footer>
        <el-button @click="emailVisible = false">取消</el-button>
        <el-button type="primary" :loading="confirmingEmail" @click="confirmEmailChange">确认更换</el-button>
      </template>
    </el-dialog>

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
import { inject, onMounted, reactive, ref, watch } from 'vue'
import { useRouter } from 'vue-router'
import { ElMessage } from 'element-plus'
import { profileApi, publicApi, TOKEN_KEY } from '../api'
import { formatTime } from '../utils/format'
import { useCountdown } from '../composables/useCountdown'

const props = defineProps({ profile: Object })
const router = useRouter()
// 站点是否启用支付。未启用时不展示余额（没有充值入口，显示它只会造成困惑）。
const paymentEnabled = ref(false)
// 站点是否启用邮件。启用后邮箱能用来找回密码，因此**不能**直接改，
// 必须走「验证新地址」的流程（服务端同样会拒绝直接改）。
const mailEnabled = ref(false)

onMounted(async () => {
  try {
    const s = await publicApi.settings()
    paymentEnabled.value = !!s?.payment_enabled
    mailEnabled.value = !!s?.mail_enabled
  } catch {
    paymentEnabled.value = false
    mailEnabled.value = false
  }
})
const reloadProfile = inject('reloadProfile', null)

const formRef = ref()
const pwdRef = ref()
const saving = ref(false)
const changingPwd = ref(false)

const deleteVisible = ref(false)
const deletePassword = ref('')
const deleting = ref(false)

// 更换邮箱（两步：发码到新地址 → 带码换绑）。
const emailVisible = ref(false)
const emailForm = reactive({ email: '', password: '', code: '' })
// 倒计时在组件卸载时自动清理（见 useCountdown）。
const { countdown: emailCountdown, start: startEmailCountdown, stop: stopEmailCountdown } = useCountdown()
const sendingEmail = ref(false)
const confirmingEmail = ref(false)

function openEmailChange() {
  emailForm.email = ''
  emailForm.password = ''
  emailForm.code = ''
  stopEmailCountdown()
  emailCountdown.value = 0
  emailVisible.value = true
}

async function sendEmailCode() {
  const email = emailForm.email.trim()
  if (!email) return ElMessage.warning('请先填写新邮箱')
  if (!emailForm.password) return ElMessage.warning('请填写登录密码以确认是本人操作')
  sendingEmail.value = true
  try {
    await profileApi.requestEmailChange({ email, password: emailForm.password })
    ElMessage.success('验证码已发送到新邮箱，请查收')
    startEmailCountdown()
  } catch (e) {
    ElMessage.error(e?.message || '发送失败，请稍后重试')
  } finally {
    sendingEmail.value = false
  }
}

async function confirmEmailChange() {
  const email = emailForm.email.trim()
  const code = emailForm.code.trim()
  if (!email) return ElMessage.warning('请填写新邮箱')
  if (!code) return ElMessage.warning('请填写验证码')
  confirmingEmail.value = true
  try {
    await profileApi.confirmEmailChange({ email, code })
    ElMessage.success('邮箱已更换')
    emailVisible.value = false
    if (reloadProfile) await reloadProfile()
  } catch (e) {
    ElMessage.error(e?.message || '更换失败，请检查验证码')
  } finally {
    confirmingEmail.value = false
  }
}

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
