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
          <el-tooltip :content="isDark ? '切换到浅色' : '切换到深色'" placement="bottom">
            <el-button circle text class="theme-toggle" @click="toggleTheme">
              <el-icon :size="17">
                <Sunny v-if="isDark" />
                <Moon v-else />
              </el-icon>
            </el-button>
          </el-tooltip>
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
import { computed, onBeforeUnmount, onMounted, provide, ref } from 'vue'
import { useRoute, useRouter } from 'vue-router'
import { profileApi, authApi, TOKEN_KEY } from '../api'
import { currentTheme, onThemeChange, toggleTheme } from '../utils/theme'

const route = useRoute()
const router = useRouter()
const profile = ref(null)

const isDark = ref(currentTheme() === 'dark')
const offTheme = onThemeChange((theme) => {
  isDark.value = theme === 'dark'
})
onBeforeUnmount(offTheme)

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
/* 只保留结构，颜色交给 styles/theme.css */
.layout {
  height: 100vh;
}

.aside {
  display: flex;
  flex-direction: column;
}

.brand {
  display: flex;
  align-items: center;
  gap: 10px;
  padding: 20px 18px 14px;
  font-weight: 600;
  font-size: 15px;
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
  gap: 14px;
}

.user {
  display: flex;
  align-items: center;
  gap: 8px;
  cursor: pointer;
  outline: none;
  color: var(--lt-ink-2);
}

.avatar {
  background: linear-gradient(135deg, var(--lt-primary), var(--lt-primary-strong));
  color: #fff;
  font-size: 13px;
}

.main {
  padding: 20px 22px 40px;
  overflow-y: auto;
}
</style>
