<template>
  <div>
    <el-row :gutter="16">
      <el-col :xs="24" :md="15">
        <div class="lt-card">
          <div class="lt-card-title">API Key</div>

          <el-alert
            type="warning"
            :closable="false"
            show-icon
            title="API Key 等同于账号凭据"
            description="注册时已自动生成，桌面客户端只用这一把钥匙。请勿分享给他人，也不要提交到公开仓库。重置后旧 Key 立即失效，客户端需要重新粘贴。"
            style="margin-bottom: 16px"
          />

          <el-descriptions :column="1" border>
            <el-descriptions-item label="当前 Key 前缀">
              <span class="lt-mono">{{ meta.prefix ? 'lt_' + meta.prefix + '********' : '未生成' }}</span>
            </el-descriptions-item>
            <el-descriptions-item label="创建时间">
              {{ formatTime(meta.created_at) }}
            </el-descriptions-item>
          </el-descriptions>

          <div v-if="revealed" class="reveal">
            <div class="lt-muted">完整 Key（仅本次显示，请立即保存）</div>
            <el-input v-model="revealed" readonly class="lt-mono" style="margin-top: 8px">
              <template #append>
                <el-button :icon="CopyDocument" @click="copy(revealed)">复制</el-button>
              </template>
            </el-input>
          </div>

          <div class="actions">
            <el-button type="primary" :icon="View" @click="reveal">显示完整 Key</el-button>
            <el-button type="danger" plain :icon="RefreshRight" @click="rotate">重置 API Key</el-button>
          </div>
        </div>
      </el-col>

      <el-col :xs="24" :md="9">
        <div class="lt-card">
          <div class="lt-card-title">使用方式</div>
          <p class="lt-muted">在请求头中携带 API Key 即可调用用户接口：</p>
          <pre class="code">Authorization: Bearer lt_xxxxxxxx_xxxx</pre>
          <p class="lt-muted" style="margin-top: 14px">获取当前账号的客户端配置：</p>
          <pre class="code">GET /api/user/client/config</pre>
          <p class="lt-muted" style="margin-top: 14px">
            桌面客户端会自动使用该 Key 拉取隧道配置，无需手动粘贴 frpc.toml。
          </p>
        </div>
      </el-col>
    </el-row>
  </div>
</template>

<script setup>
import { onMounted, ref } from 'vue'
import { ElMessage, ElMessageBox } from 'element-plus'
import { CopyDocument, View, RefreshRight } from '@element-plus/icons-vue'
import { apiKeyApi } from '../api'
import { formatTime, copyText } from '../utils/format'

const meta = ref({})
const revealed = ref('')

async function load() {
  meta.value = (await apiKeyApi.meta()) || {}
  revealed.value = ''
}

async function reveal() {
  const data = await apiKeyApi.reveal()
  revealed.value = data?.api_key || ''
}

async function rotate() {
  await ElMessageBox.confirm(
    '重置后旧 API Key 立即失效，已使用旧 Key 的客户端需要重新登录。确定继续？',
    '重置 API Key',
    { type: 'warning', confirmButtonText: '确定重置', cancelButtonText: '取消' }
  )
  const data = await apiKeyApi.rotate()
  revealed.value = data?.api_key || ''
  meta.value = (await apiKeyApi.meta()) || {}
  ElMessage.success('已重置，请立即保存新的 Key')
}

async function copy(text) {
  const ok = await copyText(text)
  ElMessage[ok ? 'success' : 'error'](ok ? '已复制' : '复制失败，请手动选择复制')
}

onMounted(load)
</script>

<style scoped>
.reveal {
  margin-top: 16px;
}

.actions {
  margin-top: 18px;
  display: flex;
  gap: 10px;
}

.code {
  background: #0f172a;
  color: #e2e8f0;
  padding: 12px 14px;
  border-radius: 10px;
  font-size: 12.5px;
  overflow-x: auto;
  margin: 8px 0 0;
}
</style>
