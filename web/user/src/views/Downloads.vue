<template>
  <div>
    <el-row :gutter="16">
      <el-col :xs="24" :md="14">
        <div class="lt-card">
          <div class="lt-card-title">
            <span>客户端下载</span>
            <el-button v-if="!downloadUrl" link :icon="Refresh" @click="load">刷新</el-button>
          </div>

          <template v-if="downloadUrl">
            <el-alert
              type="info"
              :closable="false"
              show-icon
              title="客户端由官方发布页提供"
              description="点击下方按钮前往下载。发布页同时提供历史版本与校验信息，建议始终使用最新版。"
              style="margin-bottom: 16px"
            />
            <el-button type="primary" size="large" :icon="Download" style="width: 100%" @click="openDownloadUrl">
              前往下载客户端
            </el-button>
            <div class="lt-muted" style="margin-top: 12px; word-break: break-all; line-height: 1.7">
              {{ downloadUrl }}
            </div>
          </template>

          <template v-else>
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
          </template>
        </div>
      </el-col>

      <el-col :xs="24" :md="10">
        <div class="lt-card">
          <div class="lt-card-title">接入信息</div>
          <el-descriptions :column="1" border size="small">
            <el-descriptions-item label="服务器地址">
              <span class="lt-mono">{{ info.frontend_url || '未配置' }}</span>
              <el-button
                v-if="info.frontend_url"
                link
                type="primary"
                style="margin-left: 8px"
                @click="copyField(info.frontend_url, '服务器地址')"
              >
                复制
              </el-button>
            </el-descriptions-item>
            <el-descriptions-item label="隧道网关">
              <span class="lt-mono">{{ info.server_addr || '-' }}:{{ info.server_port || '-' }}</span>
              <el-button
                v-if="info.server_addr"
                link
                type="primary"
                style="margin-left: 8px"
                @click="copyField(`${info.server_addr}:${info.server_port}`, '隧道网关')"
              >
                复制
              </el-button>
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

        <div class="lt-card" style="margin-top: 16px">
          <div class="lt-card-title">三步接入</div>
          <div class="steps">
            <div class="step">
              <span class="idx">1</span>
              <div>
                <b>下载客户端</b>
                <div class="lt-muted">解压后双击 LiteTunnel.exe，无需安装。</div>
              </div>
            </div>
            <div class="step">
              <span class="idx">2</span>
              <div>
                <b>复制 API Key</b>
                <div class="lt-muted">注册时已自动生成，无需申请。</div>
                <el-button link type="primary" style="padding: 0" @click="$router.push('/apikey')">
                  去获取 API Key →
                </el-button>
              </div>
            </div>
            <div class="step">
              <span class="idx">3</span>
              <div>
                <b>粘贴并连接</b>
                <div class="lt-muted">
                  客户端已内置服务器地址，粘贴 Key 后点「连接」即可，隧道自动同步。
                </div>
              </div>
            </div>
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
import { ElMessage } from 'element-plus'
import { Refresh, Monitor, Download } from '@element-plus/icons-vue'
import { clientApi, downloadFrpcConfig, downloadClientFile } from '../api'
import { copyText, formatBytes, formatTime } from '../utils/format'

// 非安全上下文（http://内网IP）里 Clipboard API 不可用，统一交给 copyText 兜底。
async function copyField(text, label) {
  if (!text) return
  if (await copyText(text)) {
    ElMessage.success(`${label}已复制`)
    return
  }
  ElMessage.warning('复制失败，请手动选中复制')
}

const files = ref([])
const info = ref({})
const loading = ref(false)
const downloadUrl = ref('')

function fmtBytes(v) {
  return formatBytes(v)
}

function openDownloadUrl() {
  if (!downloadUrl.value) return
  window.open(downloadUrl.value, '_blank', 'noopener,noreferrer')
}

async function load() {
  loading.value = true
  try {
    const [d, i] = await Promise.all([clientApi.downloads(), clientApi.info()])
    files.value = d?.files || []
    downloadUrl.value = d?.download_url || ''
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

<style scoped>
.steps {
  display: flex;
  flex-direction: column;
  gap: 16px;
}

.step {
  display: flex;
  gap: 12px;
  align-items: flex-start;
}

.idx {
  flex: 0 0 22px;
  width: 22px;
  height: 22px;
  border-radius: 50%;
  background: linear-gradient(135deg, var(--lt-primary), var(--lt-primary-strong));
  color: #fff;
  font-size: 12px;
  display: flex;
  align-items: center;
  justify-content: center;
  margin-top: 1px;
}

.step b {
  font-weight: 600;
  font-size: 13.5px;
}

.step .lt-muted {
  line-height: 1.7;
  margin-top: 2px;
}
</style>
