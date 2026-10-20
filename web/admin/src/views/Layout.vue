<template>
  <el-container class="layout">
    <el-aside width="212px" class="aside">
      <div class="brand">
        <div class="logo">LT</div>
        <div class="brand-text">
          <div class="brand-title">LiteTunnel</div>
          <!-- 版本号挂在品牌下方，点击就地展开更新面板（不是弹窗） -->
          <el-popover
            placement="right-start"
            :width="330"
            trigger="click"
            popper-class="lt-update-pop"
            @show="check(false)"
          >
            <template #reference>
              <button
                class="ver-chip"
                :title="hasUpdate ? `发现新版本 v${info?.latest || ''}，点击查看` : '管理后台 · 点击查看版本与更新'"
              >
                <span v-if="hasUpdate" class="update-dot"></span>
                {{ displayVersion }}
              </button>
            </template>

            <div v-loading="checking" class="up-panel">
              <div class="up-head">
                <span class="up-label">当前版本</span>
                <el-button link size="small" :loading="checking" @click="check(true)">
                  重新检查
                </el-button>
              </div>

              <div class="up-ver">{{ info?.current ? 'v' + info.current : displayVersion }}</div>
              <div class="up-state">
                <template v-if="info?.has_update">
                  发现新版本 <b>v{{ info.latest }}</b>
                </template>
                <template v-else-if="info && !info.warning">已是最新版本</template>
                <template v-else-if="!info">点击「重新检查」获取最新版本</template>
              </div>

              <el-alert
                v-if="info?.warning"
                :title="info.warning"
                type="warning"
                :closable="false"
                show-icon
                style="margin: 10px 0 0"
              />

              <template v-if="info?.has_update">
                <template v-if="info.can_self_update && info.install_mode === 'docker'">
                  <p class="up-tip">一键更新：面板会拉取新镜像并重建自己的容器，数据目录不受影响，全程约 1-2 分钟，期间页面会短暂断开。</p>
                  <el-button
                    type="primary"
                    size="small"
                    class="up-btn"
                    :loading="dockerApplying"
                    @click="dockerUpdate"
                  >
                    一键更新
                  </el-button>
                  <p v-if="dockerApplying" class="up-state">正在升级，请勿关闭页面…</p>
                </template>
                <template v-else-if="info.can_self_update">
                  <p class="up-tip">点击更新会下载并替换面板二进制，数据目录不受影响；完成后点重启，几秒内恢复。</p>
                  <el-button
                    type="primary"
                    size="small"
                    class="up-btn"
                    :loading="applying"
                    @click="applyUpdate"
                  >
                    立即更新
                  </el-button>
                </template>
                <template v-else-if="info.install_mode === 'docker'">
                  <p class="up-tip">容器部署，但未挂载 docker.sock，暂时只能命令行升级。想在这里一键更新，给 panel 服务加一条挂载即可：</p>
                  <pre class="up-cmd">volumes:
  - ./data/panel:/data
  - /var/run/docker.sock:/var/run/docker.sock</pre>
                  <el-button size="small" class="up-btn" @click="copyMount">复制挂载配置</el-button>
                  <p class="up-state">或直接复制下面的命令，在服务器上执行：</p>
                  <pre class="up-cmd">{{ info.deploy_hint }}</pre>
                  <el-button size="small" class="up-btn" @click="copyHint">复制命令</el-button>
                </template>

                <div v-if="appliedVersion" class="up-ok">
                  新版本 v{{ appliedVersion }} 已就绪，重启后生效
                </div>
                <el-button
                  v-if="appliedVersion"
                  type="success"
                  size="small"
                  class="up-btn"
                  :loading="restarting"
                  @click="restartPanel"
                >
                  立即重启
                </el-button>
                <el-button
                  v-if="info.release_url"
                  link
                  type="primary"
                  size="small"
                  class="up-link"
                  @click="openRelease"
                >
                  打开发布页
                </el-button>
              </template>
            </div>
          </el-popover>
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
        <el-menu-item index="/backups"><el-icon><FolderOpened /></el-icon><span>备份与恢复</span></el-menu-item>
        <el-menu-item index="/alerts"><el-icon><Bell /></el-icon><span>告警与监控</span></el-menu-item>
        <el-menu-item index="/system"><el-icon><Tools /></el-icon><span>系统设置</span></el-menu-item>
        <el-menu-item index="/settings"><el-icon><Setting /></el-icon><span>账号设置</span></el-menu-item>
      </el-menu>

    </el-aside>

    <el-container>
      <el-header class="header">
        <span class="page-title">{{ route.meta?.title || '' }}</span>
        <div class="header-right">
          <el-tooltip :content="isDark ? '切换到浅色' : '切换到深色'" placement="bottom">
            <el-button circle text class="theme-toggle" @click="toggleTheme">
              <el-icon :size="17">
                <Sunny v-if="isDark" />
                <Moon v-else />
              </el-icon>
            </el-button>
          </el-tooltip>
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

  </el-container>
</template>

<script setup>
import { computed, onBeforeUnmount, onMounted, ref } from 'vue'
import { useRoute, useRouter } from 'vue-router'
import { ElMessage } from 'element-plus'
import { authApi, systemApi, TOKEN_KEY } from '../api'
import { copyText } from '../utils/format'
import { currentTheme, onThemeChange, toggleTheme } from '../utils/theme'

const route = useRoute()
const router = useRouter()
const admin = ref(null)

const isDark = ref(currentTheme() === 'dark')
const offTheme = onThemeChange((theme) => {
  isDark.value = theme === 'dark'
})
onBeforeUnmount(offTheme)

const info = ref(null)
const version = ref('')
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

async function copyHint() {
  if (await copyText(info.value?.deploy_hint || '')) {
    ElMessage.success('已复制升级命令')
    return
  }
  ElMessage.warning('复制失败，请手动选中复制')
}

const sockMountHint = `volumes:
  - ./data/panel:/data
  - /var/run/docker.sock:/var/run/docker.sock`

async function copyMount() {
  if (await copyText(sockMountHint)) {
    ElMessage.success('已复制挂载配置，粘贴到 deploy/docker-compose.yml 的 panel 服务后重新 up -d')
    return
  }
  ElMessage.warning('复制失败，请手动选中复制')
}

function openRelease() {
  if (info.value?.release_url) window.open(info.value.release_url, '_blank', 'noopener')
}

const applying = ref(false)
const appliedVersion = ref('')
const restarting = ref(false)
const dockerApplying = ref(false)

// 容器一键更新：请求返回时新容器已在启动，旧容器几秒后销毁。
// 中间会出现短暂连不上（旧容器停 → 新容器起来），轮询 profile 直到
// 版本号变化再整页刷新，加载新版本的前端资源。
async function dockerUpdate() {
  dockerApplying.value = true
  const oldVersion = info.value?.current || version.value
  try {
    const res = await systemApi.applyDocker()
    ElMessage.success(res?.message || '正在升级，面板即将切换到新版本')
    const target = res?.version || info.value?.latest || ''
    for (let i = 0; i < 60; i++) {
      await new Promise((r) => setTimeout(r, 3000))
      try {
        const p = await authApi.profile()
        if (p?.version && p.version !== oldVersion) {
          ElMessage.success(`面板已更新到 v${p.version}`)
          window.location.reload()
          return
        }
      } catch {
        // 新旧容器切换的空窗期，继续等
      }
    }
    ElMessage.warning(`更新命令已执行（目标 v${target}），但未检测到版本变化，请稍后刷新页面或查看容器日志`)
  } catch {
    // 拦截器已经提示具体原因
  } finally {
    dockerApplying.value = false
  }
}

async function applyUpdate() {
  applying.value = true
  try {
    const res = await systemApi.applyUpdate()
    appliedVersion.value = res?.version || info.value?.latest || ''
    ElMessage.success('新版本已替换，点「立即重启」生效')
  } catch {
    // 拦截器已经提示具体原因
  } finally {
    applying.value = false
  }
}

function restartPanel() {
  restarting.value = true
  // 进程会在响应之后 exec 自身，这里只负责等它回来并刷新页面。
  systemApi.restart().catch(() => {})
  let tries = 0
  const timer = setInterval(async () => {
    tries += 1
    try {
      const res = await fetch('/healthz', { cache: 'no-store' })
      if (res.ok) {
        clearInterval(timer)
        window.location.reload()
        return
      }
    } catch {
      // 重启窗口内连不上是正常的
    }
    if (tries > 60) {
      clearInterval(timer)
      restarting.value = false
      ElMessage.warning('等待重启超时，请手动刷新页面或检查服务状态')
    }
  }, 2000)
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
/* 只保留结构与尺寸，颜色全部交给 styles/theme.css（深色模式才不用改这里） */
.layout {
  height: 100vh;
}

.aside {
  display: flex;
  flex-direction: column;
}

.brand-text {
  display: flex;
  flex-direction: column;
  align-items: flex-start;
  gap: 3px;
  min-width: 0;
}

/* 版本号做成小胶囊，点开是下拉面板 */
.ver-chip {
  display: inline-flex;
  align-items: center;
  gap: 5px;
  padding: 1px 8px;
  border: 1px solid var(--lt-line);
  border-radius: 999px;
  background: var(--lt-surface);
  color: var(--lt-ink-soft);
  font-size: 11px;
  line-height: 1.6;
  cursor: pointer;
  transition: color 0.15s ease, border-color 0.15s ease, background 0.15s ease;
}

.ver-chip:hover {
  color: var(--lt-primary-strong);
  border-color: var(--lt-primary);
}

.update-dot {
  width: 6px;
  height: 6px;
  border-radius: 50%;
  background: var(--lt-danger);
  box-shadow: 0 0 0 3px color-mix(in srgb, var(--lt-danger) 20%, transparent);
}

.up-panel {
  min-height: 60px;
}

.up-head {
  display: flex;
  align-items: center;
  justify-content: space-between;
  margin-bottom: 6px;
}

.up-label {
  font-size: 12px;
  color: var(--lt-ink-soft);
}

.up-ver {
  font-size: 22px;
  font-weight: 700;
  color: var(--lt-ink);
  line-height: 1.2;
}

.up-state {
  margin-top: 4px;
  font-size: 12.5px;
  color: var(--lt-ink-2);
}

.up-tip {
  margin: 10px 0 8px;
  font-size: 12px;
  line-height: 1.7;
  color: var(--lt-ink-soft);
}

.up-btn {
  width: 100%;
  margin-top: 8px;
}

.up-link {
  margin-top: 6px;
}

.up-cmd {
  margin: 0 0 8px;
  padding: 8px 10px;
  border-radius: 8px;
  background: var(--lt-surface-2);
  color: var(--lt-ink-2);
  font-family: ui-monospace, Consolas, monospace;
  font-size: 11.5px;
  line-height: 1.7;
  white-space: pre-wrap;
  word-break: break-all;
}

.up-ok {
  margin-top: 8px;
  font-size: 12px;
  color: var(--lt-success);
}

.brand {
  display: flex;
  align-items: center;
  gap: 10px;
  padding: 18px 16px 14px;
}

.logo {
  width: 32px;
  height: 32px;
  border-radius: 9px;
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
}

.menu {
  border-right: none;
  background: transparent;
}

.menu :deep(.el-menu-item) {
  height: 44px;
}

.header {
  display: flex;
  align-items: center;
  justify-content: space-between;
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
