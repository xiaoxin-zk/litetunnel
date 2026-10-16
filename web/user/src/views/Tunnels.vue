<template>
  <div>
    <div class="lt-card">
      <div class="lt-card-title">
        <span>隧道列表</span>
        <el-button type="primary" :icon="Plus" @click="openCreate">新建隧道</el-button>
      </div>

      <el-alert
        type="info"
        :closable="false"
        show-icon
        style="margin-bottom: 14px"
        :title="`当前分组「${group?.name || '未分组'}」：最多 ${group?.max_tunnels || '不限'} 条隧道，可用协议 ${(group?.allow_protocols || '-').toUpperCase()}，单隧道限速 ${group?.bandwidth_limit_str || '不限'}`"
      />

      <el-table :data="list" v-loading="loading" stripe>
        <el-table-column label="名称" prop="name" min-width="120" />
        <el-table-column label="类型" width="90">
          <template #default="{ row }">
            <el-tag size="small" effect="plain">{{ row.type.toUpperCase() }}</el-tag>
          </template>
        </el-table-column>
        <el-table-column label="本地地址" min-width="150">
          <template #default="{ row }">
            <span class="lt-mono">{{ row.local_ip }}:{{ row.local_port }}</span>
          </template>
        </el-table-column>
        <el-table-column label="公网地址" min-width="190">
          <template #default="{ row }">
            <div class="addr">
              <span class="lt-mono">{{ row.public_addr || '-' }}</span>
              <el-button v-if="row.public_addr" link :icon="CopyDocument" @click="copy(row.public_addr)" />
            </div>
          </template>
        </el-table-column>
        <el-table-column label="状态" width="150">
          <template #default="{ row }">
            <el-tag v-if="row.status !== 'active'" type="info" size="small">已停用</el-tag>
            <el-tag v-else-if="row.online" type="success" size="small">在线</el-tag>
            <el-tag v-else type="warning" size="small">离线</el-tag>
          </template>
        </el-table-column>
        <el-table-column label="已用流量" width="110">
          <template #default="{ row }">{{ fmtBytes(row.traffic_used) }}</template>
        </el-table-column>
        <el-table-column label="操作" width="220" fixed="right">
          <template #default="{ row }">
            <el-button link type="primary" @click="openEdit(row)">编辑</el-button>
            <el-button link :type="row.status === 'active' ? 'warning' : 'success'" @click="toggle(row)">
              {{ row.status === 'active' ? '停用' : '启用' }}
            </el-button>
            <el-button link type="danger" @click="remove(row)">删除</el-button>
          </template>
        </el-table-column>
        <template #empty>
          <el-empty description="还没有隧道，点击右上角新建一条" />
        </template>
      </el-table>
    </div>

    <el-dialog v-model="dialogVisible" :title="editing ? '编辑隧道' : '新建隧道'" width="560px">
      <el-form :model="form" :rules="rules" ref="formRef" label-width="96px">
        <el-form-item label="隧道名称" prop="name">
          <el-input v-model="form.name" :disabled="editing" placeholder="字母、数字或下划线，1-32 位" />
        </el-form-item>

        <el-form-item label="协议类型" prop="type">
          <el-radio-group v-model="form.type" :disabled="editing" @change="onTypeChange">
            <el-radio-button v-for="p in allowedProtocols" :key="p" :value="p">
              {{ p.toUpperCase() }}
            </el-radio-button>
          </el-radio-group>
          <div class="lt-muted" style="margin-top: 6px">
            TCP/UDP 用于游戏联机与 NAS；HTTP/HTTPS 用于内网网站。
          </div>
          <div v-if="httpsUnavailable" class="lt-muted" style="margin-top: 6px">
            本站未开启端到端 HTTPS，因此没有 HTTPS 隧道入口：本地网站走 HTTP 时请选
            <b>HTTP</b> 隧道，由平台提供访客侧 HTTPS。
          </div>
        </el-form-item>

        <el-form-item label="本地地址" required>
          <div class="row">
            <el-input v-model="form.local_ip" placeholder="127.0.0.1" style="width: 200px" />
            <el-input-number v-model="form.local_port" :min="1" :max="65535" controls-position="right" />
          </div>
          <div class="lt-muted" style="margin-top: 6px">
            游戏服务器常用：Minecraft Java 25565(TCP)、基岩版 19132(UDP)。
          </div>
        </el-form-item>

        <template v-if="isPortType">
          <el-form-item label="远程端口">
            <el-input-number v-model="form.remote_port" :min="0" :max="65535" controls-position="right" />
            <span class="lt-muted" style="margin-left: 10px">填 0 由系统自动分配</span>
          </el-form-item>
        </template>

        <template v-else>
          <el-form-item label="二级域名" prop="subdomain">
            <el-input v-model="form.subdomain" :disabled="!!form.domain">
              <template #append v-if="tunnelDomain">.{{ tunnelDomain }}</template>
            </el-input>
          </el-form-item>
          <el-form-item v-if="group?.allow_custom_domain" label="自定义域名">
            <el-input v-model="form.domain" placeholder="留空则使用二级域名" />
          </el-form-item>
        </template>

        <el-form-item label="备注">
          <el-input v-model="form.remark" placeholder="选填" />
        </el-form-item>

        <el-form-item label="传输选项">
          <el-checkbox v-model="form.use_encryption">加密传输</el-checkbox>
          <el-checkbox v-model="form.use_compression">压缩传输</el-checkbox>
        </el-form-item>
      </el-form>

      <template #footer>
        <el-button @click="dialogVisible = false">取消</el-button>
        <el-button type="primary" :loading="saving" @click="save">保存</el-button>
      </template>
    </el-dialog>
  </div>
</template>

<script setup>
import { computed, onMounted, reactive, ref } from 'vue'
import { ElMessage, ElMessageBox } from 'element-plus'
import { Plus, CopyDocument } from '@element-plus/icons-vue'
import { tunnelApi, clientApi } from '../api'
import { formatBytes, copyText } from '../utils/format'

const props = defineProps({ profile: Object })
const emit = defineEmits(['refresh-profile'])

const list = ref([])
const loading = ref(false)
const saving = ref(false)
const dialogVisible = ref(false)
const editing = ref(null)
const formRef = ref()
const tunnelDomain = ref('')

const group = computed(() => props.profile?.group)

const allowedProtocols = computed(() => {
  const raw = group.value?.allow_protocols || 'tcp,udp'
  const list = raw.split(',').map((s) => s.trim()).filter(Boolean)
  // HTTPS 隧道需要平台在独立端口上做 SNI 透传（端到端模式），而 HTTP 隧道
  // 由 Caddy 在 443 上提供访客侧 HTTPS——没有那条入口时就把 https 选项拿掉。
  // 服务端也会拒绝，这里只是别让用户白填一遍表单。
  if (group.value && group.value.https_tunnel_enabled === false) {
    return list.filter((p) => p !== 'https')
  }
  return list
})

/** 当前隐藏了 https 选项（用于给出解释，而不是让选项「凭空消失」）。 */
const httpsUnavailable = computed(
  () =>
    (group.value?.allow_protocols || '').includes('https') &&
    group.value?.https_tunnel_enabled === false
)

const isPortType = computed(() => ['tcp', 'udp'].includes(form.type))

const form = reactive({
  name: '',
  type: 'tcp',
  local_ip: '127.0.0.1',
  local_port: 25565,
  remote_port: 0,
  domain: '',
  subdomain: '',
  remark: '',
  use_encryption: false,
  use_compression: false
})

const rules = {
  name: [
    { required: true, message: '请输入隧道名称', trigger: 'blur' },
    { pattern: /^[A-Za-z0-9_]{1,32}$/, message: '仅允许 1-32 位字母、数字或下划线', trigger: 'blur' }
  ],
  type: [{ required: true, message: '请选择协议', trigger: 'change' }]
}

function fmtBytes(v) {
  return formatBytes(v)
}

async function load() {
  loading.value = true
  try {
    list.value = (await tunnelApi.list()) || []
  } finally {
    loading.value = false
  }
}

function resetForm() {
  Object.assign(form, {
    name: '',
    type: allowedProtocols.value[0] || 'tcp',
    local_ip: '127.0.0.1',
    local_port: 25565,
    remote_port: 0,
    domain: '',
    subdomain: '',
    remark: '',
    use_encryption: false,
    use_compression: false
  })
}

function onTypeChange() {
  form.local_port = form.type === 'udp' ? 19132 : 25565
}

function openCreate() {
  editing.value = null
  resetForm()
  dialogVisible.value = true
}

function openEdit(row) {
  editing.value = row
  Object.assign(form, {
    name: row.name,
    type: row.type,
    local_ip: row.local_ip,
    local_port: row.local_port,
    remote_port: row.remote_port,
    domain: row.domain || '',
    subdomain: row.subdomain || '',
    remark: row.remark || '',
    use_encryption: row.use_encryption,
    use_compression: row.use_compression
  })
  dialogVisible.value = true
}

async function save() {
  await formRef.value.validate()
  saving.value = true
  try {
    if (editing.value) {
      await tunnelApi.update(editing.value.id, { ...form })
      ElMessage.success('已保存')
    } else {
      await tunnelApi.create({ ...form })
      ElMessage.success('隧道已创建，请重新下载客户端配置')
    }
    dialogVisible.value = false
    await load()
    emit('refresh-profile')
  } finally {
    saving.value = false
  }
}

async function toggle(row) {
  const next = row.status === 'active' ? 'disabled' : 'active'
  await tunnelApi.setStatus(row.id, next)
  ElMessage.success(next === 'active' ? '已启用' : '已停用')
  await load()
}

async function remove(row) {
  await ElMessageBox.confirm(`确定删除隧道「${row.name}」吗？该操作不可撤销。`, '删除确认', {
    type: 'warning',
    confirmButtonText: '删除',
    cancelButtonText: '取消'
  })
  await tunnelApi.remove(row.id)
  ElMessage.success('已删除')
  await load()
  emit('refresh-profile')
}

async function copy(text) {
  const ok = await copyText(text)
  ElMessage[ok ? 'success' : 'error'](ok ? '已复制到剪贴板' : '复制失败，请手动复制')
}

onMounted(async () => {
  await load()
  try {
    const info = await clientApi.info()
    tunnelDomain.value = info?.tunnel_domain || ''
  } catch {
    tunnelDomain.value = ''
  }
})
</script>

<style scoped>
.row {
  display: flex;
  gap: 10px;
  align-items: center;
}

.addr {
  display: flex;
  align-items: center;
  gap: 4px;
}
</style>
