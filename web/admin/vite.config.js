import { defineConfig } from 'vite'
import vue from '@vitejs/plugin-vue'

// 管理后台的挂载路径由服务端 LT_ADMIN_PATH 决定，并且可以随时修改。
//
// 为了让前端产物不绑定具体路径，这里使用**相对 base**（'./'）：
// 产物里的资源引用形如 ./assets/xxx.js，浏览器会按当前 URL 的目录解析，
// 因此挂在 /lt-console/、/abc123/ 等任意路径下都能正常工作。
//
// 配套要求：
//   1. 路由使用哈希模式（见 src/router/index.js），否则前端路由会与挂载路径耦合；
//   2. 服务端会把不带结尾斜杠的路径 302 到带斜杠的版本，
//      否则 ./assets 会被解析到站点根目录。
const ADMIN_BASE = './'

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
