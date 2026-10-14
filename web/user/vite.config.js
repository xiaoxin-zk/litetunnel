import { defineConfig } from 'vite'
import vue from '@vitejs/plugin-vue'

// 开发期通过 VITE_API_BASE 指定后端地址，源码中不写死任何部署地址。
const apiBase = process.env.VITE_API_BASE || 'http://127.0.0.1:8080'

export default defineConfig({
  plugins: [vue()],
  server: {
    port: 5173,
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
