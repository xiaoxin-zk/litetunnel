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
      { path: 'dashboard', name: 'dashboard', meta: { title: '概览' }, component: () => import('../views/Dashboard.vue') },
      { path: 'tunnels', name: 'tunnels', meta: { title: '隧道管理' }, component: () => import('../views/Tunnels.vue') },
      { path: 'redeem', name: 'redeem', meta: { title: '兑换中心' }, component: () => import('../views/Redeem.vue') },
      { path: 'apikey', name: 'apikey', meta: { title: 'API Key' }, component: () => import('../views/ApiKey.vue') },
      { path: 'downloads', name: 'downloads', meta: { title: '客户端下载' }, component: () => import('../views/Downloads.vue') },
      { path: 'settings', name: 'settings', meta: { title: '账号设置' }, component: () => import('../views/Settings.vue') }
    ]
  },
  { path: '/:pathMatch(.*)*', redirect: '/dashboard' }
]

const router = createRouter({
  history: createWebHistory(),
  routes
})

router.beforeEach((to) => {
  const token = localStorage.getItem('lt_user_token')
  if (!to.meta.public && !token) {
    return { path: '/login' }
  }
  if (to.meta.public && token) {
    return { path: '/dashboard' }
  }
  return true
})

export default router
