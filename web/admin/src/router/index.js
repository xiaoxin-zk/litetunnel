import { createRouter, createWebHashHistory } from 'vue-router'

const routes = [
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
      { path: 'login-logs', name: 'login-logs', meta: { title: '登录日志' }, component: () => import('../views/LoginLogs.vue') },
      { path: 'admins', name: 'admins', meta: { title: '管理员管理' }, component: () => import('../views/Admins.vue') },
      { path: 'domain', name: 'domain', meta: { title: '域名与证书' }, component: () => import('../views/DomainTLS.vue') },
      { path: 'firewall', name: 'firewall', meta: { title: '端口与防火墙' }, component: () => import('../views/Firewall.vue') },
      { path: 'client-dist', name: 'client-dist', meta: { title: '客户端分发' }, component: () => import('../views/ClientDist.vue') },
      { path: 'system', name: 'system', meta: { title: '系统设置' }, component: () => import('../views/SystemSettings.vue') },
      { path: 'settings', name: 'settings', meta: { title: '账号设置' }, component: () => import('../views/Settings.vue') }
    ]
  },
  { path: '/:pathMatch(.*)*', redirect: '/dashboard' }
]

const router = createRouter({
  history: createWebHashHistory(),
  routes
})

router.beforeEach(() => {
  if (!localStorage.getItem('lt_admin_token')) {
    window.location.href = '/login'
    return false
  }
  return true
})

export default router
