<template>
  <div v-loading="loading">
    <div class="lt-card">
      <div class="lt-card-title">当前分发方式</div>

      <el-alert
        v-if="downloadUrl"
        type="success"
        :closable="false"
        show-icon
        title="用户将从外部地址获取客户端"
        :description="`用户控制台的「客户端下载」页会引导到：${downloadUrl}。下方本地文件仍然保留，但用户看不到它们——如果想改回本站分发，把「系统设置 → 站点 → 客户端下载地址」清空即可。`"
      />
      <el-alert
        v-else
        type="info"
        :closable="false"
        show-icon
        title="用户将从本站服务器下载客户端"
        description="上传的安装包会出现在用户控制台的「客户端下载」页。需要自行承担这部分流量与磁盘占用；若想改为从 GitHub Releases 分发，可在「系统设置 → 站点」填写外部下载地址。"
      />

      <el-descriptions :column="3" border size="small" style="margin-top: 14px">
        <el-descriptions-item label="分发方式">
          <el-tag :type="downloadUrl ? 'success' : 'info'" size="small" effect="plain">
            {{ downloadUrl ? '外部地址' : '本站分发' }}
          </el-tag>
        </el-descriptions-item>
        <el-descriptions-item label="本地文件">
          {{ files.length }} 个
        </el-descriptions-item>
        <el-descriptions-item label="存放目录">
          <span class="lt-mono">{{ distDir || '-' }}</span>
        </el-descriptions-item>
      </el-descriptions>
    </div>

    <div class="lt-card" style="margin-top: 16px">
      <div class="lt-card-title">上传安装包</div>

      <el-upload
        drag
        :show-file-list="false"
        :auto-upload="false"
        :on-change="handlePick"
        :accept="acceptList"
      >
        <el-icon class="el-icon--upload"><UploadFilled /></el-icon>
        <div class="el-upload__text">把安装包拖到这里，或<em>点击选择</em></div>
        <template #tip>
          <div class="el-upload__tip">
            支持 {{ acceptList }}，单个不超过 {{ maxSizeMB }} MB。
            文件名请勿包含路径分隔符。
          </div>
        </template>
      </el-upload>

      <div v-if="picked" class="picked">
        <div class="picked-info">
          <el-icon><Document /></el-icon>
          <span class="lt-mono picked-name">{{ picked.name }}</span>
          <span class="lt-muted">{{ fmtBytes(picked.size) }}</span>
        </div>
        <div class="picked-actions">
          <el-button :disabled="uploading" @click="picked = null">取消</el-button>
          <el-button type="primary" :loading="uploading" @click="doUpload">
            {{ uploading ? `上传中 ${percent}%` : '开始上传' }}
          </el-button>
        </div>
        <el-progress
          v-if="uploading"
          :percentage="percent"
          :stroke-width="6"
          style="margin-top: 10px; width: 100%"
        />
      </div>

      <el-alert
        v-if="pickErr"
        type="error"
        :closable="false"
        show-icon
        style="margin-top: 12px"
        :title="pickErr"
      />
    </div>

    <div class="lt-card" style="margin-top: 16px">
      <div class="lt-card-title">
        <span>已上传的安装包（{{ files.length }}）</span>
        <el-button link :icon="Refresh" @click="load">刷新</el-button>
      </div>

      <el-table :data="files" stripe>
        <el-table-column label="文件" prop="name" min-width="240">
          <template #default="{ row }">
            <el-icon style="vertical-align: -2px"><Monitor /></el-icon>
            <span class="lt-mono" style="margin-left: 6px">{{ row.name }}</span>
          </template>
        </el-table-column>
        <el-table-column label="大小" width="120">
          <template #default="{ row }">{{ fmtBytes(row.size) }}</template>
        </el-table-column>
        <el-table-column label="上传时间" width="180">
          <template #default="{ row }">{{ formatTime(row.updated_at) }}</template>
        </el-table-column>
        <el-table-column label="操作" width="100">
          <template #default="{ row }">
            <el-button link type="danger" @click="remove(row)">删除</el-button>
          </template>
        </el-table-column>
        <template #empty>
          <el-empty description="还没有上传任何安装包" />
        </template>
      </el-table>

      <el-alert
        v-if="!downloadUrl && files.length === 0"
        type="warning"
        :closable="false"
        show-icon
        style="margin-top: 12px"
        title="当前是「本站分发」模式，但目录里没有文件"
        description="用户打开「客户端下载」页会看到空列表。请上传安装包，或改为填写外部下载地址。"
      />
    </div>
  </div>
</template>

<script setup>
import { computed, onMounted, ref } from 'vue'
import { ElMessage, ElMessageBox } from 'element-plus'
import { Refresh } from '@element-plus/icons-vue'
import { clientPkgApi } from '../api'
import { formatBytes, formatTime } from '../utils/format'

const loading = ref(false)
const files = ref([])
const downloadUrl = ref('')
const distDir = ref('')
const maxSize = ref(100 << 20)

const picked = ref(null)
const uploading = ref(false)
const percent = ref(0)
const pickErr = ref('')

const acceptList = '.zip,.exe,.gz,.tar,.deb,.rpm,.dmg'
const maxSizeMB = computed(() => Math.round(maxSize.value / 1024 / 1024))
const fmtBytes = (v) => formatBytes(v)

function handlePick(file) {
  pickErr.value = ''
  const raw = file?.raw || file
  if (!raw) return
  if (raw.size > maxSize.value) {
    pickErr.value = `文件 ${fmtBytes(raw.size)} 超过上限 ${maxSizeMB.value} MB`
    picked.value = null
    return
  }
  if (raw.size === 0) {
    pickErr.value = '文件内容为空'
    picked.value = null
    return
  }
  picked.value = raw
}

async function doUpload() {
  if (!picked.value) return
  uploading.value = true
  percent.value = 0
  try {
    await clientPkgApi.upload(picked.value, (p) => {
      percent.value = p
    })
    ElMessage.success('上传成功')
    picked.value = null
    pickErr.value = ''
    await load()
  } catch {
  } finally {
    uploading.value = false
  }
}

async function remove(row) {
  await ElMessageBox.confirm(
    `确定删除 ${row.name} 吗？删除后用户将无法再从本站下载它。`,
    '删除安装包',
    { type: 'warning', confirmButtonText: '确认删除', cancelButtonText: '取消' }
  )
  await clientPkgApi.remove(row.name)
  ElMessage.success('已删除')
  await load()
}

async function load() {
  loading.value = true
  try {
    const d = await clientPkgApi.list()
    files.value = d?.files || []
    downloadUrl.value = d?.download_url || ''
    distDir.value = d?.dist_dir || ''
    if (d?.max_size) maxSize.value = d.max_size
  } finally {
    loading.value = false
  }
}

onMounted(load)
</script>

<style scoped>
.picked {
  display: flex;
  align-items: center;
  flex-wrap: wrap;
  gap: 12px;
  margin-top: 16px;
  padding: 12px 14px;
  background: var(--lt-surface-2);
  border: 1px solid var(--lt-line);
  border-radius: 10px;
}

.picked-info {
  display: flex;
  align-items: center;
  gap: 8px;
  min-width: 0;
  flex: 1;
}

.picked-name {
  overflow: hidden;
  text-overflow: ellipsis;
  white-space: nowrap;
  -webkit-user-select: text;
  user-select: text;
}

.picked-actions {
  display: flex;
  gap: 8px;
  flex: 0 0 auto;
}
</style>
