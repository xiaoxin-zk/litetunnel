import { defineConfig } from 'vite'
import vue from '@vitejs/plugin-vue'

const apiBase = process.env.VITE_API_BASE || 'http://127.0.0.1:7848'

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
