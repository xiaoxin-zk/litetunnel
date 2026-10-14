import { defineConfig } from 'vite'
import vue from '@vitejs/plugin-vue'

// 管理后台与用户控制台共用同一个公网端口，因此构建时必须以 /admin/ 作为 base，
// 否则两套 SPA 的 /assets 会互相覆盖。
// 该值必须与 server/internal/router 中的 router.AdminPath 保持一致。
const ADMIN_BASE = '/admin/'

// 开发期通过 VITE_API_BASE 指定后端地址，源码中不写死任何部署地址。
const apiBase = process.env.VITE_API_BASE || 'http://127.0.0.1:7848'

export default defineConfig({
  plugins: [vue()],
  base: ADMIN_BASE,
  server: {
    port: 5175,
    proxy: {
      '/api': {
        target: apiBase,
        changeOrigin: true
      }
    }
  },
  build: {
    outDir: 'dist',
    chunkSizeWarningLimit: 1200
  }
})
