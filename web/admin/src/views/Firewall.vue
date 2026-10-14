<template>
  <div v-loading="loading">
    <!-- ============ 状态总览 ============ -->
    <div class="lt-card">
      <div class="lt-card-title">
        <span>防火墙状态</span>
        <div>
          <el-button :icon="Refresh" @click="load">重新扫描</el-button>
          <el-button type="primary" @click="$router.push('/system')">去系统设置</el-button>
        </div>
      </div>

      <el-alert
        v-if="!fw.enabled"
        type="info"
        :closable="false"
        show-icon
        style="margin-bottom: 16px"
        title="防火墙控制未启用"
        description="当前面板不会修改主机防火墙。隧道端口需要你在云安全组或手工放行。如需自动放行，请到「系统设置 → 端口与防火墙」启用。"
      />
      <el-alert
        v-else-if="fw.reason"
        type="warning"
        :closable="false"
        show-icon
        style="margin-bottom: 16px"
        :title="`后端不可用：${fw.reason}`"
        description="已启用但探测不到可用后端。请确认容器已授予 NET_ADMIN 且安装了 iptables，或改用手工放行。"
      />
      <el-alert
        v-else
        type="success"
        :closable="false"
        show-icon
        style="margin-bottom: 16px"
        :title="`后端 ${fw.backend} 已接管，${fw.auto_open ? '新隧道会自动放行端口' : '自动放行已关闭'}`"
        description="云服务器安全组不受本功能影响，仍需在云控制台单独放行。"
      />

      <el-descriptions :column="4" border size="small">
        <el-descriptions-item label="启用状态">
          <el-tag :type="fw.enabled ? 'success' : 'info'" size="small">
            {{ fw.enabled ? '已启用' : '未启用' }}
          </el-tag>
        </el-descriptions-item>
        <el-descriptions-item label="后端">{{ fw.backend || '-' }}</el-descriptions-item>
        <el-descriptions-item label="规则生效">
          <el-tag :type="fw.active ? 'success' : 'info'" size="small">
            {{ fw.active ? '生效中' : '未生效' }}
          </el-tag>
        </el-descriptions-item>
        <el-descriptions-item label="自动放行">
          {{ fw.auto_open ? '开启' : '关闭' }}
        </el-descriptions-item>
      </el-descriptions>

      <el-alert
        v-if="fw.protected_ports?.length"
        type="warning"
        :closable="false"
        show-icon
        style="margin-top: 14px"
        :title="`保护端口：${fw.protected_ports.join(', ')}`"
        description="这些端口永远不会被面板关闭，是防止把自己锁在服务器外的最后一道保险。"
      />
    </div>

    <!-- ============ 端口池 ============ -->
    <div class="lt-card" style="margin-top: 16px">
      <div class="lt-card-title">端口池使用情况</div>

      <div class="pool-bar">
        <div class="seg reserved" :style="{ width: pct(pool.reserved?.length) }" />
        <div class="seg system" :style="{ width: pct(pool.system_listening?.length) }" />
        <div class="seg allocated" :style="{ width: pct(pool.allocated?.length) }" />
        <div class="seg free" :style="{ width: pct(pool.free) }" />
      </div>
      <div class="legend">
        <span><i class="dot reserved" />保留 {{ pool.reserved?.length || 0 }}</span>
        <span><i class="dot system" />系统占用 {{ pool.system_listening?.length || 0 }}</span>
        <span><i class="dot allocated" />已分配 {{ pool.allocated?.length || 0 }}</span>
        <span><i class="dot free" />可分配 {{ pool.free || 0 }}</span>
        <span class="lt-muted">池范围 {{ pool.pool_start }}-{{ pool.pool_end }}，共 {{ pool.total }} 个</span>
      </div>

      <el-alert
        v-if="(pool.system_listening?.length || 0) > 0"
        type="info"
        :closable="false"
        show-icon
        style="margin-top: 14px"
        title="检测到端口池内有端口被系统服务占用"
        description="这些端口不会被分配给用户隧道。如果你的服务器上跑着其他服务，建议把它们也填进「保留端口」，避免误判。"
      />

      <el-collapse v-if="(pool.system_listening?.length || 0) > 0" style="margin-top: 10px">
        <el-collapse-item :title="`查看被占用的端口（${pool.system_listening.length}）`">
          <div class="chips">
            <el-tag v-for="p in pool.system_listening" :key="p" size="small" type="warning">{{ p }}</el-tag>
          </div>
        </el-collapse-item>
      </el-collapse>
    </div>

    <!-- ============ 规则 ============ -->
    <div class="lt-card" style="margin-top: 16px">
      <div class="lt-card-title">
        <span>放行规则</span>
        <el-button type="primary" :icon="Plus" @click="openVisible = true">手工放行端口</el-button>
      </div>

      <el-tabs v-model="ruleTab">
        <el-tab-pane :label="`面板托管（${fw.managed_rules?.length || 0}）`" name="managed">
          <el-table :data="fw.managed_rules || []" size="small" stripe>
            <el-table-column label="端口" prop="port" width="100" />
            <el-table-column label="协议" width="90">
              <template #default="{ row }">
                <el-tag size="small" effect="plain">{{ row.proto.toUpperCase() }}</el-tag>
              </template>
            </el-table-column>
            <el-table-column label="来源" prop="source" min-width="140">
              <template #default="{ row }">{{ row.source || '不限' }}</template>
            </el-table-column>
            <el-table-column label="操作" width="100">
              <template #default="{ row }">
                <el-button link type="danger" @click="closePort(row)">关闭</el-button>
              </template>
            </el-table-column>
            <template #empty><el-empty description="暂无托管规则" /></template>
          </el-table>
        </el-tab-pane>

        <el-tab-pane :label="`系统既有（${fw.external_rules?.length || 0}）`" name="external">
          <el-alert
            type="info"
            :closable="false"
            show-icon
            style="margin-bottom: 12px"
            title="这些规则由系统或你手工添加，面板只读展示"
            description="面板不会修改它们。之所以要展示，是为了避免你误以为「端口没放行」而重复添加。"
          />
          <el-table :data="fw.external_rules || []" size="small" stripe>
            <el-table-column label="端口" prop="port" width="100" />
            <el-table-column label="协议" width="90">
              <template #default="{ row }">
                <el-tag size="small" effect="plain">{{ row.proto.toUpperCase() }}</el-tag>
              </template>
            </el-table-column>
            <el-table-column label="来源" prop="source" min-width="140">
              <template #default="{ row }">{{ row.source || '不限' }}</template>
            </el-table-column>
            <template #empty><el-empty description="暂无系统规则" /></template>
          </el-table>
        </el-tab-pane>
      </el-tabs>
    </div>

    <!-- ============ 监听端口 ============ -->
    <div class="lt-card" style="margin-top: 16px">
      <div class="lt-card-title">
        <span>主机监听端口（{{ fw.listening?.length || 0 }}）</span>
      </div>
      <el-table :data="fw.listening || []" size="small" stripe max-height="360">
        <el-table-column label="端口" prop="port" width="100" />
        <el-table-column label="协议" width="90">
          <template #default="{ row }">
            <el-tag size="small" effect="plain">{{ row.proto.toUpperCase() }}</el-tag>
          </template>
        </el-table-column>
        <el-table-column label="监听地址" prop="addr" min-width="180" />
        <el-table-column label="对外可达" width="110">
          <template #default="{ row }">
            <el-tag size="small" :type="row.exposed ? 'warning' : 'info'">
              {{ row.exposed ? '是' : '仅本机' }}
            </el-tag>
          </template>
        </el-table-column>
        <template #empty><el-empty description="未扫描到监听端口" /></template>
      </el-table>
    </div>

    <!-- ============ 手工放行 ============ -->
    <el-dialog v-model="openVisible" title="手工放行端口" width="440px">
      <el-alert
        type="warning"
        :closable="false"
        show-icon
        style="margin-bottom: 14px"
        title="端口必须在隧道端口池范围内"
        :description="`当前池范围 ${pool.pool_start}-${pool.pool_end}，特权端口（<1024）一律拒绝。`"
      />
      <el-form label-width="80px">
        <el-form-item label="端口">
          <el-input-number v-model="openForm.port" :min="1" :max="65535" style="width: 100%" />
        </el-form-item>
        <el-form-item label="协议">
          <el-radio-group v-model="openForm.proto">
            <el-radio value="tcp">TCP</el-radio>
            <el-radio value="udp">UDP</el-radio>
          </el-radio-group>
        </el-form-item>
      </el-form>
      <template #footer>
        <el-button @click="openVisible = false">取消</el-button>
        <el-button type="primary" :loading="acting" @click="doOpen">放行</el-button>
      </template>
    </el-dialog>
  </div>
</template>

<script setup>
import { onMounted, reactive, ref } from 'vue'
import { ElMessage, ElMessageBox } from 'element-plus'
import { Refresh, Plus } from '@element-plus/icons-vue'
import { firewallApi } from '../api'

const loading = ref(false)
const acting = ref(false)
const ruleTab = ref('managed')
const openVisible = ref(false)
const fw = ref({})
const pool = ref({})
const openForm = reactive({ port: null, proto: 'tcp' })

// 各分段宽度按端口池总量归一化，直观反映占用比例
function pct(n) {
  const total = pool.value.total || 1
  const v = ((n || 0) / total) * 100
  return `${Math.max(v, v > 0 ? 1 : 0)}%`
}

async function load() {
  loading.value = true
  try {
    const data = await firewallApi.rescan()
    fw.value = data?.firewall || {}
    pool.value = data?.pool || {}
  } finally {
    loading.value = false
  }
}

async function doOpen() {
  if (!openForm.port) {
    ElMessage.warning('请填写端口')
    return
  }
  acting.value = true
  try {
    await firewallApi.open(openForm.port, openForm.proto)
    ElMessage.success('端口已放行')
    openVisible.value = false
    await load()
  } finally {
    acting.value = false
  }
}

async function closePort(row) {
  await ElMessageBox.confirm(
    `确定关闭 ${row.port}/${row.proto} 吗？关闭后该端口将无法从公网访问。`,
    '关闭端口',
    { type: 'warning', confirmButtonText: '确认关闭', cancelButtonText: '取消' }
  )
  await firewallApi.close(row.port, row.proto)
  ElMessage.success('端口已关闭')
  await load()
}

onMounted(load)
</script>

<style scoped>
.pool-bar {
  display: flex;
  height: 22px;
  border-radius: 6px;
  overflow: hidden;
  background: #f3f4f6;
  margin-bottom: 12px;
}

.seg {
  height: 100%;
  transition: width 0.3s;
}

.seg.reserved {
  background: #94a3b8;
}
.seg.system {
  background: #f59e0b;
}
.seg.allocated {
  background: #2563eb;
}
.seg.free {
  background: #d1fae5;
}

.legend {
  display: flex;
  gap: 18px;
  flex-wrap: wrap;
  font-size: 13px;
  color: #4b5563;
  align-items: center;
}

.dot {
  display: inline-block;
  width: 9px;
  height: 9px;
  border-radius: 50%;
  margin-right: 5px;
}

.dot.reserved {
  background: #94a3b8;
}
.dot.system {
  background: #f59e0b;
}
.dot.allocated {
  background: #2563eb;
}
.dot.free {
  background: #d1fae5;
}

.chips {
  display: flex;
  flex-wrap: wrap;
  gap: 6px;
}
</style>
