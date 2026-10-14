import { createRouter, createWebHistory } from 'vue-router'

const routes = [
  {
    path: '/login',
    name: 'login',
    component: () => import('../views/Login.vue'),
    meta: { public: true }
  },
  {
    path: '/',
    component: () => import('../views/Layout.vue'),
    children: [
      { path: '', redirect: '/dashboard' },
      { path: 'dashboard', name: 'dashboard', meta: { title: '系统概览' }, component: () => import('../views/Dashboard.vue') },
      { path: 'users', name: 'users', meta: { title: '用户管理' }, component: () => import('../views/Users.vue') },
      { path: 'groups', name: 'groups', meta: { title: '分组权限' }, component: () => import('../views/Groups.vue') },
      { path: 'tunnels', name: 'tunnels', meta: { title: '隧道管理' }, component: () => import('../views/Tunnels.vue') },
      { path: 'redeem', name: 'redeem', meta: { title: '兑换码' }, component: () => import('../views/RedeemCodes.vue') },
      { path: 'logs', name: 'logs', meta: { title: '审计与客户端' }, component: () => import('../views/Logs.vue') },
      { path: 'settings', name: 'settings', meta: { title: '账号设置' }, component: () => import('../views/Settings.vue') }
    ]
  },
  { path: '/:pathMatch(.*)*', redirect: '/dashboard' }
]

// 与 vite.config.js 的 base 保持一致：管理后台挂在 /admin 下。
const ADMIN_BASE = '/admin'

const router = createRouter({
  history: createWebHistory(ADMIN_BASE),
  routes
})

router.beforeEach((to) => {
  const token = localStorage.getItem('lt_admin_token')
  if (!to.meta.public && !token) {
    return { path: '/login' }
  }
  if (to.meta.public && token) {
    return { path: '/dashboard' }
  }
  return true
})

export default router
