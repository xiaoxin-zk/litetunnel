<template>
  <div>
    <el-alert
      v-if="admin && !admin.totp_enabled"
      type="warning"
      :closable="false"
      show-icon
      style="margin-bottom: 16px"
      title="尚未启用双因素认证"
      description="管理后台是公网可达的最高权限入口。仅凭密码一道防线风险很高，建议立即在下方启用双因素认证。"
    />

    <el-row :gutter="16">
      <el-col :xs="24" :md="10">
        <div class="lt-card">
          <div class="lt-card-title">管理员信息</div>
          <el-descriptions :column="1" border>
            <el-descriptions-item label="账号">{{ admin?.username || '-' }}</el-descriptions-item>
            <el-descriptions-item label="昵称">{{ admin?.nickname || '-' }}</el-descriptions-item>
            <el-descriptions-item label="角色">{{ roleLabel }}</el-descriptions-item>
            <el-descriptions-item label="双因素">
              <el-tag size="small" :type="admin?.totp_enabled ? 'success' : 'danger'">
                {{ admin?.totp_enabled ? '已启用' : '未启用' }}
              </el-tag>
            </el-descriptions-item>
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
            description="账号在服务首次启动时按 .env 中的 LT_BOOTSTRAP_ADMIN_USER / LT_BOOTSTRAP_ADMIN_PASSWORD 播种。如需新增或重置，请清空 lt_admins 表后重启。"
          />
        </div>
      </el-col>

      <el-col :xs="24" :md="14">
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
        </div>

        <div class="lt-card" style="margin-top: 16px">
          <div class="lt-card-title">修改登录账号</div>

          <el-alert
            type="info"
            :closable="false"
            show-icon
            style="margin-bottom: 14px"
            title="建议把初始账号名改掉"
            description="初始账号名来自部署配置（默认 admin），是公开可猜的。攻击者据此可对管理员账号做定向爆破或定向锁定。改成不可预测的名字能显著降低这类攻击的性价比。"
          />

          <el-form :model="profile" :rules="profileRules" ref="profileRef" label-width="90px">
            <el-form-item label="登录账号" prop="username">
              <el-input v-model="profile.username" placeholder="3-32 位字母、数字或下划线" />
            </el-form-item>
            <el-form-item label="昵称">
              <el-input v-model="profile.nickname" placeholder="用于界面展示，可留空" />
            </el-form-item>
            <el-button type="primary" :loading="profileSaving" @click="submitProfile">保存</el-button>
          </el-form>
        </div>

        <div class="lt-card" style="margin-top: 16px">
          <div class="lt-card-title">
            <span>双因素认证（TOTP）</span>
            <el-tag size="small" :type="admin?.totp_enabled ? 'success' : 'info'">
              {{ admin?.totp_enabled ? '已启用' : '未启用' }}
            </el-tag>
          </div>

          <p class="lt-muted" style="line-height: 1.9; margin-top: 0">
            启用后，登录除密码外还需输入认证器 App 中的 6 位动态口令。
            支持 Google Authenticator、Microsoft Authenticator、1Password、Authy 等任意 TOTP 应用。
          </p>

          <div v-if="!admin?.totp_enabled">
            <el-button type="primary" :loading="totpLoading" @click="startSetup">启用双因素认证</el-button>
          </div>
          <div v-else>
            <el-button :loading="totpLoading" @click="rebindVisible = true">换绑新设备</el-button>
            <el-button type="danger" plain :loading="totpLoading" @click="disableVisible = true">
              关闭双因素认证
            </el-button>
            <p class="lt-muted" style="line-height: 1.9; margin: 12px 0 0">
              换绑需要先用当前设备的口令验证，再用新设备确认。中途放弃（关掉页面、输错）
              不会影响现有绑定，第二因素始终有效。
            </p>
          </div>
        </div>
      </el-col>
    </el-row>

    <!-- 绑定对话框 -->
    <el-dialog
      v-model="setupVisible"
      :title="rebinding ? '换绑认证器' : '绑定认证器'"
      width="480px"
      :close-on-click-modal="false"
    >
      <el-steps :active="1" align-center style="margin-bottom: 18px">
        <el-step title="扫码" description="用认证器 App 扫描" />
        <el-step title="验证" description="输入一次动态口令" />
      </el-steps>

      <div class="qr-wrap">
        <img v-if="qrDataUrl" :src="qrDataUrl" alt="TOTP QR" class="qr" />
        <el-skeleton v-else :rows="4" animated />
      </div>

      <div class="secret-box">
        <div class="lt-muted">无法扫码时手动输入密钥：</div>
        <div class="secret">
          <span class="lt-mono">{{ setupSecret }}</span>
          <el-button link :icon="CopyDocument" @click="copySecret">复制</el-button>
        </div>
      </div>

      <el-input
        v-model="setupCode"
        maxlength="6"
        size="large"
        placeholder="输入 App 显示的 6 位口令"
        style="margin-top: 16px"
        @keyup.enter="confirmEnable"
      />

      <template #footer>
        <el-button @click="setupVisible = false">取消</el-button>
        <el-button type="primary" :loading="totpLoading" @click="confirmEnable">完成绑定</el-button>
      </template>
    </el-dialog>

    <!-- 换绑第一步：先证明持有当前设备 -->
    <el-dialog v-model="rebindVisible" title="换绑认证器" width="440px">
      <el-alert
        type="info"
        :closable="false"
        show-icon
        title="先验证当前设备"
        description="输入当前认证器显示的动态口令，然后扫码绑定新设备。中途放弃不会影响现有绑定。"
        style="margin-bottom: 16px"
      />
      <el-input
        v-model="rebindCode"
        maxlength="6"
        size="large"
        placeholder="当前设备显示的 6 位口令"
        @keyup.enter="confirmRebind"
      />
      <template #footer>
        <el-button @click="rebindVisible = false">取消</el-button>
        <el-button type="primary" :loading="totpLoading" @click="confirmRebind">下一步</el-button>
      </template>
    </el-dialog>

    <!-- 关闭对话框 -->
    <el-dialog v-model="disableVisible" title="关闭双因素认证" width="420px">
      <el-alert
        type="warning"
        :closable="false"
        show-icon
        title="这会让账号重新只剩密码一道防线"
        description="请确认你确实不再需要第二因素，然后输入登录密码以完成关闭。"
        style="margin-bottom: 16px"
      />
      <el-input v-model="disablePassword" type="password" show-password placeholder="输入登录密码" />
      <template #footer>
        <el-button @click="disableVisible = false">取消</el-button>
        <el-button type="danger" :loading="totpLoading" @click="confirmDisable">确认关闭</el-button>
      </template>
    </el-dialog>
  </div>
</template>

<script setup>
import { computed, onMounted, reactive, ref } from 'vue'
import { useRouter } from 'vue-router'
import { ElMessage } from 'element-plus'
import { CopyDocument } from '@element-plus/icons-vue'
import QRCode from 'qrcode'
import { authApi, TOKEN_KEY } from '../api'
import { formatTime, copyText } from '../utils/format'

const router = useRouter()
const admin = ref(null)
const formRef = ref()
const saving = ref(false)
const totpLoading = ref(false)

const form = reactive({ old_password: '', new_password: '', confirm: '' })

const profileRef = ref()
const profileSaving = ref(false)
const profile = reactive({ username: '', nickname: '' })

const profileRules = {
  username: [
    { required: true, message: '请输入登录账号', trigger: 'blur' },
    { pattern: /^[A-Za-z0-9_]{3,32}$/, message: '仅允许 3-32 位字母、数字或下划线', trigger: 'blur' }
  ]
}

const setupVisible = ref(false)
const setupSecret = ref('')
const setupCode = ref('')
const qrDataUrl = ref('')

const disableVisible = ref(false)
const disablePassword = ref('')

// 换绑流程：先验证当前设备（rebindCode），再走与首次绑定相同的扫码确认。
// rebinding 只用于文案区分——服务端两处的语义不同（换绑不动现有绑定，
// 确认之后才切换），提示语要让用户知道这一点。
const rebindVisible = ref(false)
const rebindCode = ref('')
const rebinding = ref(false)

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

async function load() {
  admin.value = await authApi.profile()
  profile.username = admin.value?.username || ''
  profile.nickname = admin.value?.nickname || ''
}

async function submitProfile() {
  await profileRef.value.validate()
  profileSaving.value = true
  try {
    await authApi.updateProfile({
      username: profile.username.trim(),
      nickname: profile.nickname.trim()
    })
    ElMessage.success('已保存')
    await load()
  } finally {
    profileSaving.value = false
  }
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

async function startSetup() {
  totpLoading.value = true
  try {
    const data = await authApi.totpSetup()
    rebinding.value = false
    setupSecret.value = data.secret
    setupCode.value = ''
    // 在本地渲染二维码，密钥不经过任何第三方服务。
    qrDataUrl.value = await QRCode.toDataURL(data.otpauth_url, { width: 220, margin: 1 })
    setupVisible.value = true
  } finally {
    totpLoading.value = false
  }
}

// confirmRebind 换绑第一步：用当前设备的口令换取一把新密钥。
//
// 服务端此时只把新密钥**暂存**起来，现有绑定不受影响——所以这一步失败、
// 或者后面扫码那步被放弃，账号仍然处于双因素保护之下。
async function confirmRebind() {
  const code = rebindCode.value.trim()
  if (code.length !== 6) {
    ElMessage.warning('请输入 6 位动态口令')
    return
  }
  totpLoading.value = true
  try {
    const data = await authApi.totpSetup(code)
    rebinding.value = true
    setupSecret.value = data.secret
    setupCode.value = ''
    qrDataUrl.value = await QRCode.toDataURL(data.otpauth_url, { width: 220, margin: 1 })
    rebindVisible.value = false
    rebindCode.value = ''
    setupVisible.value = true
  } finally {
    totpLoading.value = false
  }
}

async function confirmEnable() {
  const code = setupCode.value.trim()
  if (code.length !== 6) {
    ElMessage.warning('请输入 6 位动态口令')
    return
  }
  totpLoading.value = true
  try {
    await authApi.totpEnable(code)
    // 先取下来再重置：重置之后文案会走错分支。
    const wasRebinding = rebinding.value
    setupVisible.value = false
    rebinding.value = false
    // 服务端在启用 / 换绑成功后会撤销该账号的既有会话（第二因素变了，旧会话
    // 不再可信），所以这里直接引导重新登录。不这样的话，用户刚点完「完成绑定」
    // 就会被下一次请求的 401 甩出去，只会以为是出了故障。
    ElMessage.success(
      wasRebinding
        ? '已换绑到新设备，请用新设备的口令重新登录'
        : '双因素认证已启用，请重新登录并输入动态口令'
    )
    localStorage.removeItem(TOKEN_KEY)
    router.push('/login')
  } finally {
    totpLoading.value = false
  }
}

async function confirmDisable() {
  if (!disablePassword.value) {
    ElMessage.warning('请输入登录密码')
    return
  }
  totpLoading.value = true
  try {
    await authApi.totpDisable(disablePassword.value)
    disableVisible.value = false
    disablePassword.value = ''
    // 同 confirmEnable：第二因素变了，服务端会撤销既有会话，这里直接引导重登。
    ElMessage.success('双因素认证已关闭，请重新登录')
    localStorage.removeItem(TOKEN_KEY)
    router.push('/login')
  } finally {
    totpLoading.value = false
  }
}

async function copySecret() {
  const ok = await copyText(setupSecret.value)
  ElMessage[ok ? 'success' : 'error'](ok ? '已复制' : '复制失败，请手动输入')
}

onMounted(load)
</script>

<style scoped>
.qr-wrap {
  display: flex;
  justify-content: center;
  padding: 10px 0;
}

.qr {
  width: 200px;
  height: 200px;
  border: 1px solid #eef1f6;
  border-radius: 12px;
  padding: 6px;
  background: #fff;
}

.secret-box {
  margin-top: 12px;
  background: #f8fafc;
  border-radius: 10px;
  padding: 10px 12px;
}

.secret {
  display: flex;
  align-items: center;
  justify-content: space-between;
  gap: 10px;
  margin-top: 4px;
  word-break: break-all;
  font-size: 13px;
}
</style>
