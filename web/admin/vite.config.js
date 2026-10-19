import { defineConfig } from 'vite'
import vue from '@vitejs/plugin-vue'

const ADMIN_BASE = './'

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
