<template>
  <el-container class="layout">
    <el-aside width="216px" class="aside">
      <div class="brand">
        <div class="logo">LT</div>
        <span>LiteTunnel</span>
      </div>
      <el-menu :default-active="active" router class="menu">
        <el-menu-item index="/dashboard"><el-icon><Odometer /></el-icon><span>概览</span></el-menu-item>
        <el-menu-item index="/tunnels"><el-icon><Connection /></el-icon><span>隧道管理</span></el-menu-item>
        <el-menu-item index="/downloads"><el-icon><Download /></el-icon><span>客户端</span></el-menu-item>
        <el-menu-item index="/redeem"><el-icon><Ticket /></el-icon><span>兑换中心</span></el-menu-item>
        <el-menu-item index="/apikey"><el-icon><Key /></el-icon><span>API Key</span></el-menu-item>
        <el-menu-item index="/settings"><el-icon><Setting /></el-icon><span>账号设置</span></el-menu-item>
      </el-menu>
    </el-aside>

    <el-container>
      <el-header class="header">
        <div class="header-left">
          <span class="page-title">{{ pageTitle }}</span>
        </div>
        <div class="header-right">
          <el-tag v-if="profile" :type="profile.traffic_exceeded ? 'danger' : 'success'" effect="light" round>
            {{ profile.traffic_exceeded ? '流量已用尽' : '状态正常' }}
          </el-tag>
          <el-dropdown @command="onCommand">
            <span class="user">
              <el-avatar :size="30" class="avatar">{{ initials }}</el-avatar>
              <span>{{ profile?.nickname || profile?.username || '用户' }}</span>
              <el-icon><ArrowDown /></el-icon>
            </span>
            <template #dropdown>
              <el-dropdown-menu>
                <el-dropdown-item command="settings">账号设置</el-dropdown-item>
                <el-dropdown-item command="logout" divided>退出登录</el-dropdown-item>
              </el-dropdown-menu>
            </template>
          </el-dropdown>
        </div>
      </el-header>

      <el-main class="main">
        <router-view v-slot="{ Component }">
          <component :is="Component" :profile="profile" @refresh-profile="loadProfile" />
        </router-view>
      </el-main>
    </el-container>
  </el-container>
</template>

<script setup>
import { computed, onMounted, provide, ref } from 'vue'
import { useRoute, useRouter } from 'vue-router'
import { profileApi, authApi, TOKEN_KEY } from '../api'

const route = useRoute()
const router = useRouter()
const profile = ref(null)

const active = computed(() => route.path)
const pageTitle = computed(() => route.meta?.title || String(route.name || ''))

const initials = computed(() => {
  const name = profile.value?.nickname || profile.value?.username || 'U'
  return name.slice(0, 1).toUpperCase()
})

async function loadProfile() {
  profile.value = await profileApi.get()
}

async function onCommand(cmd) {
  if (cmd === 'logout') {
    try {
      await authApi.logout()
    } catch {
      // 登出失败不影响本地清理
    }
    localStorage.removeItem(TOKEN_KEY)
    router.push('/login')
    return
  }
  if (cmd === 'settings') router.push('/settings')
}

provide('reloadProfile', loadProfile)
onMounted(loadProfile)
</script>

<style scoped>
.layout {
  height: 100vh;
}

.aside {
  background: #0f172a;
  color: #cbd5e1;
  display: flex;
  flex-direction: column;
}

.brand {
  display: flex;
  align-items: center;
  gap: 10px;
  padding: 20px 18px 14px;
  font-weight: 600;
  color: #fff;
  font-size: 15px;
}

.logo {
  width: 32px;
  height: 32px;
  border-radius: 9px;
  background: linear-gradient(135deg, #2563eb, #6366f1);
  display: flex;
  align-items: center;
  justify-content: center;
  font-size: 13px;
  font-weight: 700;
}

.menu {
  border-right: none;
  background: transparent;
  --el-menu-bg-color: transparent;
  --el-menu-text-color: #cbd5e1;
  --el-menu-hover-bg-color: rgba(255, 255, 255, 0.06);
  --el-menu-active-color: #ffffff;
}

.menu :deep(.el-menu-item.is-active) {
  background: rgba(37, 99, 235, 0.9) !important;
  border-radius: 8px;
  margin: 0 10px;
}

.menu :deep(.el-menu-item) {
  margin: 2px 10px;
  border-radius: 8px;
  height: 44px;
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
  gap: 14px;
}

.user {
  display: flex;
  align-items: center;
  gap: 8px;
  cursor: pointer;
  outline: none;
}

.avatar {
  background: linear-gradient(135deg, #2563eb, #6366f1);
  font-size: 13px;
}

.main {
  padding: 20px 22px 40px;
  overflow-y: auto;
}
</style>
