import { defineConfig } from 'vite'
import vue from '@vitejs/plugin-vue'

// 管理后台默认对接本机管理端口，源码中不写死任何部署地址。
const apiBase = process.env.VITE_API_BASE || 'http://127.0.0.1:8443'

export default defineConfig({
  plugins: [vue()],
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
