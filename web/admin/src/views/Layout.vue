<template>
  <el-container class="layout">
    <el-aside width="212px" class="aside">
      <div class="brand">
        <div class="logo">LT</div>
        <div>
          <div class="brand-title">LiteTunnel</div>
          <div class="brand-sub">管理后台</div>
        </div>
      </div>
      <el-menu :default-active="active" router class="menu">
        <el-menu-item index="/dashboard"><el-icon><DataBoard /></el-icon><span>系统概览</span></el-menu-item>
        <el-menu-item index="/users"><el-icon><UserFilled /></el-icon><span>用户管理</span></el-menu-item>
        <el-menu-item index="/groups"><el-icon><Grid /></el-icon><span>分组权限</span></el-menu-item>
        <el-menu-item index="/tunnels"><el-icon><Connection /></el-icon><span>隧道管理</span></el-menu-item>
        <el-menu-item index="/redeem"><el-icon><Ticket /></el-icon><span>兑换码</span></el-menu-item>
        <el-menu-item index="/logs"><el-icon><Document /></el-icon><span>审计与客户端</span></el-menu-item>
        <el-menu-item index="/login-logs"><el-icon><Key /></el-icon><span>登录日志</span></el-menu-item>
        <el-menu-item index="/admins"><el-icon><Avatar /></el-icon><span>管理员管理</span></el-menu-item>
        <el-menu-item index="/domain"><el-icon><Link /></el-icon><span>域名与证书</span></el-menu-item>
        <el-menu-item index="/firewall"><el-icon><Lock /></el-icon><span>端口与防火墙</span></el-menu-item>
        <el-menu-item index="/client-dist"><el-icon><Download /></el-icon><span>客户端分发</span></el-menu-item>
        <el-menu-item index="/system"><el-icon><Tools /></el-icon><span>系统设置</span></el-menu-item>
        <el-menu-item index="/settings"><el-icon><Setting /></el-icon><span>账号设置</span></el-menu-item>
      </el-menu>

      <div class="aside-foot">
        <el-badge :is-dot="hasUpdate" :hidden="!hasUpdate">
          <el-button link class="ver-btn" @click="openUpdate">
            {{ displayVersion }}
          </el-button>
        </el-badge>
      </div>
    </el-aside>

    <el-container>
      <el-header class="header">
        <span class="page-title">{{ route.meta?.title || '' }}</span>
        <div class="header-right">
          <el-tag type="info" effect="plain" round>
            {{ admin?.nickname || admin?.username || '管理员' }}
            <span v-if="admin?.role"> · {{ roleLabel }}</span>
          </el-tag>
          <el-button link @click="logout">退出登录</el-button>
        </div>
      </el-header>
      <el-main class="main">
        <el-alert
          v-if="staleBuild"
          type="warning"
          :closable="false"
          show-icon
          style="margin-bottom: 12px"
          title="面板已更新：当前页面仍是旧版资源，刷新后可看到新界面"
        >
          <el-button size="small" @click="reloadPage">立即刷新</el-button>
        </el-alert>
        <router-view />
      </el-main>
    </el-container>

    <el-dialog v-model="updateVisible" title="版本更新" width="660px">
      <div v-loading="checking" class="update-body">
        <div class="ver-line">
          <span>当前版本 <b>{{ info?.current ? 'v' + info.current : '未知' }}</b></span>
          <span v-if="info?.latest">最新发布 <b>v{{ info.latest }}</b></span>
          <el-tag v-if="info?.has_update" type="warning" size="small">有新版本</el-tag>
          <el-tag v-else-if="info && !info.warning" type="success" size="small">已是最新</el-tag>
        </div>

        <el-alert
          v-if="info?.warning"
          :title="info.warning"
          type="warning"
          :closable="false"
          show-icon
          style="margin-bottom: 12px"
        />

        <template v-if="info?.has_update">
          <el-alert
            type="info"
            :closable="false"
            show-icon
            title="面板随容器镜像发布：换镜像 tag 并重启容器即完成升级，浏览器刷新后生效"
            style="margin-bottom: 12px"
          />
          <div class="hint">在服务器上执行：</div>
          <pre class="cmd">{{ info.deploy_hint }}</pre>
          <el-button size="small" @click="copyHint">复制命令</el-button>
          <el-button v-if="info.release_url" link type="primary" @click="openRelease">打开发布页</el-button>
        </template>

        <template v-if="info?.notes">
          <el-divider content-position="left">更新说明</el-divider>
          <pre class="notes">{{ info.notes }}</pre>
        </template>
      </div>
      <template #footer>
        <el-button :loading="checking" @click="check(true)">重新检查</el-button>
        <el-button type="primary" @click="updateVisible = false">关闭</el-button>
      </template>
    </el-dialog>
  </el-container>
</template>

<script setup>
import { computed, onMounted, ref } from 'vue'
import { useRoute, useRouter } from 'vue-router'
import { ElMessage } from 'element-plus'
import { authApi, systemApi, TOKEN_KEY } from '../api'

const route = useRoute()
const router = useRouter()
const admin = ref(null)

const info = ref(null)
const version = ref('')
const updateVisible = ref(false)
const checking = ref(false)
const hasUpdate = computed(() => !!info.value?.has_update)
const displayVersion = computed(() => {
  const v = info.value?.current || version.value
  return v ? 'v' + v : '版本'
})

// index.html 里注入的构建版本；开发模式下是未替换的占位符，不参与比较。
const assetVersion =
  document.querySelector('meta[name="lt-version"]')?.getAttribute('content') || ''
const staleBuild = computed(
  () => assetVersion && assetVersion !== '__LT_VERSION__' && version.value
    ? assetVersion !== version.value
    : false
)

function reloadPage() {
  window.location.reload()
}

async function check(force) {
  checking.value = true
  try {
    info.value = await systemApi.update(force)
  } catch {
    // 审计只读角色没有检查权限，静默忽略，不影响页面使用
  } finally {
    checking.value = false
  }
}

async function openUpdate() {
  updateVisible.value = true
  if (!info.value) await check(false)
}

async function copyHint() {
  try {
    await navigator.clipboard.writeText(info.value?.deploy_hint || '')
    ElMessage.success('已复制升级命令')
  } catch {
    ElMessage.warning('复制失败，请手动选中复制')
  }
}

function openRelease() {
  if (info.value?.release_url) window.open(info.value.release_url, '_blank', 'noopener')
}

const active = computed(() => route.path)
const roleLabels = { super: '超级管理员', operator: '运营', auditor: '审计只读' }
const roleLabel = computed(() => roleLabels[admin.value?.role] || admin.value?.role || '')

function logout() {
  localStorage.removeItem(TOKEN_KEY)
  router.push('/login')
}

onMounted(async () => {
  const profile = await authApi.profile()
  admin.value = profile
  version.value = profile?.version || ''
  await check(false)
})
</script>

<style scoped>
.layout {
  height: 100vh;
}

.aside {
  background: #0b1220;
  display: flex;
  flex-direction: column;
}

.aside-foot {
  margin-top: auto;
  padding: 12px 16px 18px;
  border-top: 1px solid rgba(255, 255, 255, 0.06);
}

.ver-btn {
  color: #94a3b8;
  font-size: 12px;
}

.ver-btn:hover {
  color: #e2e8f0;
}

.update-body {
  min-height: 80px;
}

.ver-line {
  display: flex;
  align-items: center;
  gap: 14px;
  margin-bottom: 14px;
  color: #4b5563;
  font-size: 13px;
}

.hint {
  color: #6b7280;
  font-size: 12.5px;
  margin-bottom: 6px;
}

.cmd {
  margin: 0 0 10px;
  padding: 10px 12px;
  border-radius: 8px;
  background: #0b1220;
  color: #e2e8f0;
  font-family: ui-monospace, Consolas, monospace;
  font-size: 12px;
  line-height: 1.7;
  white-space: pre-wrap;
  word-break: break-all;
}

.notes {
  margin: 0;
  padding: 10px 12px;
  border-radius: 8px;
  background: #f8fafc;
  color: #374151;
  font-size: 12.5px;
  line-height: 1.8;
  white-space: pre-wrap;
  max-height: 260px;
  overflow: auto;
}

.brand {
  display: flex;
  align-items: center;
  gap: 10px;
  padding: 18px 16px 14px;
  color: #fff;
}

.logo {
  width: 32px;
  height: 32px;
  border-radius: 9px;
  background: linear-gradient(135deg, #334155, #64748b);
  display: flex;
  align-items: center;
  justify-content: center;
  font-size: 13px;
  font-weight: 700;
}

.brand-title {
  font-size: 14px;
  font-weight: 600;
}

.brand-sub {
  font-size: 11px;
  color: #94a3b8;
}

.menu {
  border-right: none;
  background: transparent;
  --el-menu-bg-color: transparent;
  --el-menu-text-color: #cbd5e1;
  --el-menu-hover-bg-color: rgba(255, 255, 255, 0.06);
  --el-menu-active-color: #ffffff;
}

.menu :deep(.el-menu-item) {
  margin: 2px 10px;
  border-radius: 8px;
  height: 44px;
}

.menu :deep(.el-menu-item.is-active) {
  background: rgba(51, 65, 85, 0.95) !important;
}

.header {
  background: #fff;
  display: flex;
  align-items: center;
  justify-content: space-between;
  border-bottom: 1px solid #eef1f6;
  height: 60px;
}

.page-title {
  font-size: 16px;
  font-weight: 600;
}

.header-right {
  display: flex;
  align-items: center;
  gap: 12px;
}

.main {
  padding: 20px 22px 40px;
  overflow-y: auto;
}
</style>
