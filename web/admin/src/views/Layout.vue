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
        <el-menu-item index="/firewall"><el-icon><Lock /></el-icon><span>端口与防火墙</span></el-menu-item>
        <el-menu-item index="/system"><el-icon><Tools /></el-icon><span>系统设置</span></el-menu-item>
        <el-menu-item index="/settings"><el-icon><Setting /></el-icon><span>账号设置</span></el-menu-item>
      </el-menu>
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
        <router-view />
      </el-main>
    </el-container>
  </el-container>
</template>

<script setup>
import { computed, onMounted, ref } from 'vue'
import { useRoute, useRouter } from 'vue-router'
import { authApi, TOKEN_KEY } from '../api'

const route = useRoute()
const router = useRouter()
const admin = ref(null)

const active = computed(() => route.path)
const roleLabels = { super: '超级管理员', operator: '运营', auditor: '审计只读' }
const roleLabel = computed(() => roleLabels[admin.value?.role] || admin.value?.role || '')

function logout() {
  localStorage.removeItem(TOKEN_KEY)
  router.push('/login')
}

onMounted(async () => {
  admin.value = await authApi.profile()
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
