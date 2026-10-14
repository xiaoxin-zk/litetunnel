import { defineConfig } from 'vite'
import vue from '@vitejs/plugin-vue'

// Wails 以相对路径加载静态资源，必须使用 './'。
export default defineConfig({
  plugins: [vue()],
  base: './',
  build: {
    outDir: 'dist',
    emptyOutDir: true,
    chunkSizeWarningLimit: 1200
  }
})
