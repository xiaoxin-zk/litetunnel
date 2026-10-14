<template>
  <div>
    <el-row :gutter="16">
      <el-col :xs="24" :md="14">
        <div class="lt-card">
          <div class="lt-card-title">
            <span>客户端下载</span>
            <el-button link :icon="Refresh" @click="load">刷新</el-button>
          </div>

          <el-table :data="files" v-loading="loading" stripe>
            <el-table-column label="文件" prop="name" min-width="220">
              <template #default="{ row }">
                <el-icon style="vertical-align: -2px"><Monitor /></el-icon>
                <span style="margin-left: 6px">{{ row.name }}</span>
              </template>
            </el-table-column>
            <el-table-column label="大小" width="110">
              <template #default="{ row }">{{ fmtBytes(row.size) }}</template>
            </el-table-column>
            <el-table-column label="更新时间" width="160">
              <template #default="{ row }">{{ formatTime(row.updated_at) }}</template>
            </el-table-column>
            <el-table-column label="操作" width="100">
              <template #default="{ row }">
                <el-button link type="primary" @click="downloadFile(row.name)">下载</el-button>
              </template>
            </el-table-column>
            <template #empty>
              <el-empty description="管理员尚未上传客户端安装包" />
            </template>
          </el-table>
        </div>
      </el-col>

      <el-col :xs="24" :md="10">
        <div class="lt-card">
          <div class="lt-card-title">接入信息</div>
          <el-descriptions :column="1" border size="small">
            <el-descriptions-item label="服务器地址">
              <span class="lt-mono">{{ info.server_addr || '-' }}:{{ info.server_port || '-' }}</span>
            </el-descriptions-item>
            <el-descriptions-item label="客户端标识">
              <span class="lt-mono">{{ info.user || '-' }}</span>
            </el-descriptions-item>
            <el-descriptions-item label="隧道域名">
              <span class="lt-mono">{{ info.tunnel_domain || '未配置' }}</span>
            </el-descriptions-item>
          </el-descriptions>

          <el-divider />

          <el-button type="primary" :icon="Download" style="width: 100%" @click="downloadConfig">
            下载 frpc.toml 配置
          </el-button>
          <div class="lt-muted" style="margin-top: 10px; line-height: 1.7">
            桌面客户端会自动拉取配置，通常无需手动下载。<br />
            使用官方 frpc 时，把该文件放到 frpc 同目录后执行即可。
          </div>
        </div>
      </el-col>
    </el-row>

    <div class="lt-card" style="margin-top: 16px">
      <div class="lt-card-title">快速开始</div>
      <el-steps :active="4" align-center>
        <el-step title="下载客户端" description="Windows 桌面版，双击即用" />
        <el-step title="登录账号" description="使用本控制台的账号密码" />
        <el-step title="创建隧道" description="在控制台新建并配置本地端口" />
        <el-step title="一键启动" description="客户端自动拉取配置并连接" />
      </el-steps>

      <el-divider />

      <el-descriptions title="游戏联机常用端口" :column="2" border size="small">
        <el-descriptions-item label="Minecraft Java 版">25565 / TCP</el-descriptions-item>
        <el-descriptions-item label="Minecraft 基岩版">19132 / UDP</el-descriptions-item>
        <el-descriptions-item label="泰拉瑞亚">7777 / TCP</el-descriptions-item>
        <el-descriptions-item label="幻兽帕鲁">8211 / UDP</el-descriptions-item>
        <el-descriptions-item label="CS2 / Source 引擎">27015 / UDP</el-descriptions-item>
        <el-descriptions-item label="群晖 DSM">5000 或 5001 / TCP</el-descriptions-item>
      </el-descriptions>
    </div>
  </div>
</template>

<script setup>
import { onMounted, ref } from 'vue'
import { Refresh, Monitor, Download } from '@element-plus/icons-vue'
import { clientApi, downloadFrpcConfig, downloadClientFile } from '../api'
import { formatBytes, formatTime } from '../utils/format'

const files = ref([])
const info = ref({})
const loading = ref(false)

function fmtBytes(v) {
  return formatBytes(v)
}

async function load() {
  loading.value = true
  try {
    const [f, i] = await Promise.all([clientApi.downloads(), clientApi.info()])
    files.value = f || []
    info.value = i || {}
  } finally {
    loading.value = false
  }
}

function downloadFile(name) {
  downloadClientFile(name)
}

function downloadConfig() {
  downloadFrpcConfig()
}

onMounted(load)
</script>
