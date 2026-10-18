<template>
  <div v-loading="loading">
    <!-- ============ 状态 ============ -->
    <div class="lt-card">
      <div class="lt-card-title">
        <span>下发与证书状态</span>
        <div>
          <el-button :icon="Refresh" @click="load">刷新状态</el-button>
          <el-button :icon="Search" @click="checkDNS">DNS 检查</el-button>
        </div>
      </div>

      <el-alert
        v-if="status.pending"
        type="warning"
        :closable="false"
        show-icon
        style="margin-bottom: 16px"
        title="已保存的配置还没有在宿主机上生效"
        :description="pendingText"
      />

      <el-alert
        v-if="!status.helper_configured"
        type="warning"
        :closable="false"
        show-icon
        style="margin-bottom: 16px"
        title="尚未配置宿主机配置服务"
        :description="status.helper_reason || '请在下方「配置服务」处填写 lt-config 的地址与访问令牌。'"
      />
      <el-alert
        v-else-if="!status.helper?.available"
        type="error"
        :closable="false"
        show-icon
        style="margin-bottom: 16px"
        :title="`配置服务不可用`"
        :description="status.helper_reason || '请确认 lt-config 服务已启动、令牌一致、docker 可用。'"
      />
      <el-alert
        v-else
        type="success"
        :closable="false"
        show-icon
        style="margin-bottom: 16px"
        :title="`配置服务可用：${status.helper.deploy_dir}`"
        description="配置只由文件生效：保存后由它渲染 Caddyfile / frps.toml、校验通过再写盘并重建容器。Caddy 的管理 API 始终保持关闭，不为管理方便单独开放。"
      />

      <el-descriptions :column="4" border size="small">
        <el-descriptions-item label="面板域名">{{ form.panel || '-' }}</el-descriptions-item>
        <el-descriptions-item label="隧道根域名">{{ form.tunnel || '未启用' }}</el-descriptions-item>
        <el-descriptions-item label="HTTPS 隧道模式">
          <el-tag size="small" :type="form.mode === 'e2e' ? 'warning' : 'success'" effect="plain">
            {{ form.mode === 'e2e' ? '端到端（证书在本地网站）' : '边缘（证书在 Caddy）' }}
          </el-tag>
        </el-descriptions-item>
        <el-descriptions-item label="DNS 服务商">{{ form.provider || '-' }}</el-descriptions-item>
        <el-descriptions-item label="网关端口">{{ status.helper?.ports?.gateway || '-' }} TCP</el-descriptions-item>
        <el-descriptions-item label="KCP 端口">{{ status.helper?.ports?.kcp || '-' }} UDP</el-descriptions-item>
        <el-descriptions-item label="HTTP 隧道入口">
          {{ status.helper?.ports?.vhost_http || '-' }}（仅本机，由 Caddy 转发）
        </el-descriptions-item>
        <el-descriptions-item label="HTTPS 隧道入口">
          {{ status.helper?.ports?.vhost_https || '-' }}
          <span v-if="form.mode === 'e2e'" class="lt-muted">（需对公网放行）</span>
          <span v-else class="lt-muted">（仅本机）</span>
        </el-descriptions-item>
        <!--
          上面几项是「期望值」（表单里保存的那份），这一项是宿主机上**实际在用**
          的那份。保存与下发是两步，不做区分的话，「只保存未下发」与「下发失败」
          在页面上都表现成「已经改了」，而流量还走在旧配置上。
        -->
        <el-descriptions-item label="宿主机实际在用" :span="2">
          <span class="mono">{{ appliedText }}</span>
        </el-descriptions-item>
        <el-descriptions-item label="下发状态">
          <el-tag size="small" :type="status.pending ? 'warning' : 'success'" effect="plain">
            {{ status.pending ? '待下发' : '与期望一致' }}
          </el-tag>
        </el-descriptions-item>
      </el-descriptions>
    </div>

    <!-- ============ 证书 ============ -->
    <div class="lt-card" style="margin-top: 16px">
      <div class="lt-card-title">Caddy 证书（{{ status.certs?.certs?.length || 0 }}）</div>

      <el-alert
        v-if="status.certs?.reason"
        type="info"
        :closable="false"
        show-icon
        style="margin-bottom: 12px"
        :title="status.certs.reason"
      />

      <el-table :data="status.certs?.certs || []" size="small" stripe>
        <el-table-column label="域名" prop="domain" min-width="200" />
        <el-table-column label="覆盖范围" min-width="200">
          <template #default="{ row }">
            <span class="mono">{{ (row.names || []).join(', ') || '-' }}</span>
          </template>
        </el-table-column>
        <el-table-column label="签发者" prop="issuer" min-width="160" />
        <el-table-column label="类型" width="100">
          <template #default="{ row }">
            <el-tag size="small" effect="plain" :type="row.kind === 'acme' ? 'success' : 'info'">
              {{ row.kind === 'acme' ? 'ACME' : '内部 CA' }}
            </el-tag>
          </template>
        </el-table-column>
        <el-table-column label="到期时间" min-width="170">
          <template #default="{ row }">{{ formatTime(row.not_after) }}</template>
        </el-table-column>
        <el-table-column label="剩余" width="110">
          <template #default="{ row }">
            <el-tag size="small" :type="daysType(row.days_left)">{{ row.days_left }} 天</el-tag>
          </template>
        </el-table-column>
        <template #empty><el-empty description="还没有签发任何证书" /></template>
      </el-table>

      <div class="hint">
        证书留在 Caddy 的 /data 目录里，不会下发给客户端。端到端模式（e2e）下证书由本地网站自己持有，
        这里看到的是平台自己用的那几张。
      </div>
    </div>

    <!-- ============ 配置 ============ -->
    <div class="lt-card" style="margin-top: 16px">
      <div class="lt-card-title">
        <span>域名与证书设置</span>
        <div>
          <el-button :loading="saving" @click="save(false)">仅保存</el-button>
          <el-button :loading="saving" :disabled="!status.helper?.available" @click="save(false, true)">
            保存并校验
          </el-button>
          <el-button type="primary" :loading="saving" :disabled="!status.helper?.available" @click="save(true)">
            保存并应用
          </el-button>
        </div>
      </div>

      <el-form :model="form" label-width="150px">
        <el-form-item label="面板域名">
          <el-input v-model="form.panel" placeholder="panel.example.com" />
        </el-form-item>
        <div class="hint">
          控制台地址（域名或公网 IP），必须解析到本机；找回密码邮件也用它拼链接。
          协议取自 <span class="mono">LT_USER_PUBLIC_URL</span>：填 <span class="mono">http://</span> 时
          Caddy 不申请证书、也不发送 HSTS，适合无域名/无法备案的部署，但凭据会明文传输。
        </div>

        <el-form-item label="隧道根域名">
          <el-input v-model="form.tunnel" placeholder="tunnel.example.com（留空表示不启用 HTTP/HTTPS 隧道）" />
        </el-form-item>
        <div class="hint">
          填<b>裸域名</b>，不要带 <span class="mono">*.</span> 前缀。客户端用
          <span class="mono">&lt;子域&gt;.根域名</span> 访问，Caddy 侧自动申请泛域名证书。
          留空即关闭 HTTP/HTTPS 隧道。
        </div>

        <el-form-item label="ACME 通知邮箱">
          <el-input v-model="form.acme" placeholder="留空则用 admin@面板域名" />
        </el-form-item>

        <el-form-item label="DNS 服务商">
          <el-select v-model="form.provider" clearable placeholder="选择或输入 dns 指令名" style="width: 320px">
            <el-option v-for="p in providers" :key="p" :label="p" :value="p" />
          </el-select>
        </el-form-item>
        <div class="hint">
          泛域名证书只能用 DNS Challenge 验证，这里的名字即 Caddyfile 里的
          <span class="mono">dns</span> 指令名，必须与镜像里编入的插件一致
          （<span class="mono">LT_CADDY_DNS_MODULES</span> + 自建镜像，见 deploy/caddy/Dockerfile）。
          官方 <span class="mono">caddy:2-alpine</span> 不带任何插件，配了泛域名会以
          <span class="mono">unrecognized directive: dns</span> 拒绝启动——本页面会在下发前拦下这种组合。
        </div>

        <el-form-item label="DNS API 凭据">
          <el-input
            v-model="form.credential"
            type="password"
            show-password
            :placeholder="secretPlaceholder('credential')"
          />
        </el-form-item>
        <div class="hint">
          加密存储，只回显脱敏值。它会被写进部署目录的 .env，由 docker-compose 注入 Caddy 容器
          （Caddyfile 里只出现 <span class="mono">{env.LT_CADDY_DNS_CREDENTIAL}</span>，凭据不进配置文件）。
        </div>

        <el-form-item label="HTTPS 隧道模式">
          <el-radio-group v-model="form.mode">
            <el-radio value="edge">边缘（证书留在 Caddy）</el-radio>
            <el-radio value="e2e">端到端（证书留在本地网站）</el-radio>
          </el-radio-group>
        </el-form-item>
        <div class="hint">
          <b>边缘</b>：Caddy 用泛域名证书在 443 上终止 TLS，再以 HTTP 转发给 frps；本地网站继续用 HTTP，
          证书不下发给客户端。<br />
          <b>端到端</b>：HTTPS 隧道走独立端口（上面的「HTTPS 隧道入口」），frps 按 SNI 透传原始 TLS 连接，
          证书由本地网站自己持有；该端口必须对公网放行。两种模式可以同时使用，互不干扰。
        </div>

        <el-divider content-position="left">高级</el-divider>

        <el-form-item label="DNS 指令参数">
          <el-input v-model="form.dnsArgs" placeholder="留空 = {env.LT_CADDY_DNS_CREDENTIAL}" />
        </el-form-item>
        <div class="hint">
          需要两个参数的服务商（如 route53）在这里显式写
          <span class="mono">{env.X} {env.Y}</span>，并把额外变量补进 caddy 容器的 environment。
        </div>

        <el-form-item label="期待解析地址">
          <el-input v-model="form.expectedIp" placeholder="本机公网 IP，可留空" />
        </el-form-item>
        <div class="hint">填了就参与 DNS 检查的比对，用来快速判断「域名是不是解析到别处去了」。</div>

        <el-form-item label="配置服务地址">
          <el-input v-model="form.helperAddr" placeholder="http://127.0.0.1:7850" />
        </el-form-item>
        <el-form-item label="配置服务令牌">
          <el-input
            v-model="form.helperToken"
            type="password"
            show-password
            :placeholder="secretPlaceholder('helperToken')"
          />
        </el-form-item>
        <div class="hint">
          宿主机上的 lt-config：只监听回环、只接受 Bearer token，部署见
          <span class="mono">deploy/systemd/lt-config.service</span> 与
          <span class="mono">lt-config.env.example</span>。令牌要与那边的 LT_CFG_TOKEN 完全一致。
        </div>
      </el-form>
    </div>

    <!-- ============ 下发结果 ============ -->
    <div v-if="result" class="lt-card" style="margin-top: 16px">
      <div class="lt-card-title">
        <span>下发结果</span>
        <el-tag v-if="result.partial" size="small" type="danger">部分应用，需人工处理</el-tag>
        <el-tag v-else size="small" :type="result.applied ? 'success' : 'info'">
          {{ result.applied ? '已应用（容器已重建）' : '仅生成，未应用' }}
        </el-tag>
      </div>

      <el-alert
        v-if="result.partial"
        type="error"
        :closable="false"
        show-icon
        style="margin-bottom: 10px"
        title="配置与容器可能不在同一版本，已停止自动继续"
        :description="result.message || '请根据下方容器状态与服务日志人工确认后再处理配置现场。'"
      />
      <el-alert
        v-for="(w, i) in result.warnings || []"
        :key="i"
        type="warning"
        :closable="false"
        show-icon
        style="margin-bottom: 10px"
        :title="w"
      />

      <el-descriptions :column="3" border size="small" style="margin-bottom: 12px">
        <el-descriptions-item label="变化文件">
          {{ (result.changed || []).join(', ') || '无（内容一致，未触碰容器）' }}
        </el-descriptions-item>
        <el-descriptions-item label="同步的 .env 项">
          {{ (result.env_updated || []).join(', ') || '无' }}
        </el-descriptions-item>
        <el-descriptions-item label="需放行的端口">
          {{ (result.required_ports || []).join(', ') || '-' }}
        </el-descriptions-item>
      </el-descriptions>

      <el-descriptions
        v-if="result.partial"
        :column="3"
        border
        size="small"
        title="容器实际状态"
        style="margin-bottom: 12px"
      >
        <el-descriptions-item
          v-for="svc in result.services || []"
          :key="svc.name"
          :label="svc.name"
        >
          {{ svc.state || '未知' }}
        </el-descriptions-item>
        <el-descriptions-item v-if="!(result.services || []).length" label="容器状态">
          未能读取，请查看 lt-config 与 docker compose 日志
        </el-descriptions-item>
      </el-descriptions>

      <div class="hint">保存并应用会重建 caddy 与 frps 容器，期间 HTTPS 与隧道会短暂中断（数秒）。</div>

      <el-collapse style="margin-top: 10px">
        <el-collapse-item title="查看校验与容器输出">
          <pre class="output">{{ result.validate || '（无输出）' }}</pre>
        </el-collapse-item>
      </el-collapse>
    </div>

    <!-- ============ DNS 检查 ============ -->
    <div v-if="dns.length" class="lt-card" style="margin-top: 16px">
      <div class="lt-card-title">DNS 检查结果</div>
      <el-table :data="dns" size="small" stripe>
        <el-table-column label="域名" prop="name" min-width="220" />
        <el-table-column label="别名" min-width="160">
          <template #default="{ row }">{{ row.cname || '-' }}</template>
        </el-table-column>
        <el-table-column label="解析结果" min-width="200">
          <template #default="{ row }">
            <span class="mono">{{ (row.ips || []).join(', ') || '-' }}</span>
          </template>
        </el-table-column>
        <el-table-column label="结论" min-width="300">
          <template #default="{ row }">
            <el-tag v-if="row.error" size="small" type="danger" effect="plain">解析失败</el-tag>
            <el-tag v-else-if="row.matched" size="small" type="success" effect="plain">与期待地址一致</el-tag>
            <el-tag v-else size="small" type="warning" effect="plain">需确认</el-tag>
            <span class="hint-inline">{{ row.hint }}</span>
          </template>
        </el-table-column>
        <template #empty><el-empty description="暂无检查结果" /></template>
      </el-table>
      <div class="hint">
        通配符探测用的随机子域每次都会变：泛域名证书签发的前提就是服务商侧存在一条泛解析记录，
        探测结果为空说明该记录还没加。
      </div>
    </div>
  </div>
</template>

<script setup>
import { computed, onMounted, reactive, ref } from 'vue'
import { ElMessage } from 'element-plus'
import { Refresh, Search } from '@element-plus/icons-vue'
import { domainApi, settingsApi } from '../api'

// 与后端 service.SecretMask 保持一致：留空且原本已配置 → 提交占位符表示不修改
const SECRET_MASK = '__UNCHANGED__'

// 常见服务商只是候选，允许手填：插件名由镜像决定，硬编码成白名单反而挡住自建镜像。
const providers = ['cloudflare', 'alidns', 'dnspod', 'route53', 'gandi', 'namecheap', 'porkbun']

const loading = ref(false)
const saving = ref(false)
const status = ref({})
const result = ref(null)
const dns = ref([])
const secretLoaded = reactive({})

const form = reactive({
  panel: '',
  tunnel: '',
  acme: '',
  provider: '',
  credential: '',
  dnsArgs: '',
  mode: 'edge',
  expectedIp: '',
  helperAddr: '',
  helperToken: ''
})

const secretPlaceholder = (key) =>
  secretLoaded[key] ? '已配置，留空表示不修改' : '尚未配置'

const modeText = (m) => (m === 'e2e' ? '端到端' : '边缘')

// 宿主机上实际在用的配置（由后端记录「已下发」的那一份，不是表单里的值）。
const appliedText = computed(() => {
  const a = status.value.applied || {}
  return `${a.panel || '（未设置面板域名）'} · ${a.tunnel || '（未启用隧道域名）'} · ${modeText(a.https_mode)}`
})

// 把「期望 → 已生效」的差异写清楚，管理员才知道点一次下发会改掉什么。
const pendingText = computed(() => {
  const a = status.value.applied || {}
  const d = status.value.desired || {}
  const parts = []
  if ((d.panel || '') !== (a.panel || '')) {
    parts.push(`面板域名 ${a.panel || '（空）'} → ${d.panel || '（空）'}`)
  }
  if ((d.tunnel || '') !== (a.tunnel || '')) {
    parts.push(`隧道根域名 ${a.tunnel || '（未启用）'} → ${d.tunnel || '（未启用）'}`)
  }
  if ((d.https_mode || '') !== (a.https_mode || '')) {
    parts.push(`HTTPS 模式 ${modeText(a.https_mode)} → ${modeText(d.https_mode)}`)
  }
  // pending 也可能是由「不进 DomainAppliedSet」的字段引起的：DNS 服务商、
  // DNS 参数、凭据、ACME 邮箱都会改变渲染结果，同样需要一次下发才生效。
  // 此时上面三项完全相同，若只说「待切换」却不列出任何一项，管理员会以为
  // 是页面误报。
  const detail = parts.length
    ? `待切换：${parts.join('；')}。`
    : '证书相关参数（ACME 邮箱 / DNS 服务商 / 凭据 / 参数）与已生效的那一份不同。'
  return `宿主机上仍在用：${appliedText.value}。${detail}配置要等下发出成功（渲染、校验、写盘并重建容器）之后才会切换。`
})

function applySettings(data) {
  const d = data || {}
  form.panel = d['domain.panel'] || ''
  form.tunnel = d['domain.tunnel'] || ''
  form.acme = d['domain.acme_email'] || ''
  form.provider = d['domain.dns_provider'] || ''
  form.dnsArgs = d['domain.dns_args'] || ''
  form.mode = d['domain.https_mode'] === 'e2e' ? 'e2e' : 'edge'
  form.expectedIp = d['domain.expected_ip'] || ''
  form.helperAddr = d['domain.helper_addr'] || ''
  secretLoaded.credential = d['domain.dns_credential'] === SECRET_MASK
  secretLoaded.helperToken = d['domain.helper_token'] === SECRET_MASK
  form.credential = ''
  form.helperToken = ''
}

function buildPayload() {
  return {
    'domain.panel': form.panel,
    'domain.tunnel': form.tunnel,
    'domain.acme_email': form.acme,
    'domain.dns_provider': form.provider,
    'domain.dns_args': form.dnsArgs,
    'domain.https_mode': form.mode,
    'domain.expected_ip': form.expectedIp,
    'domain.helper_addr': form.helperAddr,
    'domain.dns_credential':
      form.credential === '' && secretLoaded.credential ? SECRET_MASK : form.credential,
    'domain.helper_token':
      form.helperToken === '' && secretLoaded.helperToken ? SECRET_MASK : form.helperToken
  }
}

async function load() {
  loading.value = true
  try {
    const [settings, st] = await Promise.all([settingsApi.get(), domainApi.status()])
    applySettings(settings)
    status.value = st || {}
  } finally {
    loading.value = false
  }
}

// apply：false = 仅保存（或先渲染校验），true = 保存并重建容器。
//
// 校验与保存分开是有意的：宿主机上的渲染/校验可能失败（插件没编进镜像、
// 端口没放行），那时配置值得先存下来，让管理员改完环境再重试下发。
async function save(apply, validateOnly = false) {
  saving.value = true
  result.value = null
  try {
    await settingsApi.update(buildPayload())
    if (!apply && !validateOnly) {
      ElMessage.success('已保存。配置尚未下发，点「保存并应用」后才会生效')
      await load()
      return
    }
    const res = await domainApi.apply(apply)
    result.value = res || {}
    if (res?.applied) {
      ElMessage.success(res.message || '已应用')
    } else if (validateOnly) {
      ElMessage.success('配置已生成并通过校验（未重建容器）')
    }
    await load()
  } finally {
    saving.value = false
  }
}

// 检查的是「服务端已保存的域名」，因此这里**不重新加载表单**：
// 管理员可能正改着一半的配置，刷新会把未保存的输入抹掉。
async function checkDNS() {
  dns.value = []
  const res = await domainApi.dnsCheck()
  dns.value = res?.records || []
  if (!dns.value.length) {
    ElMessage.warning('没有需要检查的域名，请先保存面板域名与隧道根域名')
    return
  }
  const bad = dns.value.filter((r) => r.error || (form.expectedIp && !r.matched))
  if (bad.length) {
    ElMessage.warning(`${bad.length} 条记录需要确认，详见下方结果`)
  } else {
    ElMessage.success('解析结果正常')
  }
}

function formatTime(v) {
  if (!v) return '-'
  const d = new Date(v)
  if (Number.isNaN(d.getTime())) return v
  return d.toLocaleString('zh-CN', { hour12: false })
}

function daysType(days) {
  if (days <= 7) return 'danger'
  if (days <= 21) return 'warning'
  return 'success'
}

onMounted(load)
</script>

<style scoped>
.hint {
  margin: -8px 0 18px 150px;
  font-size: 12px;
  line-height: 1.8;
  color: #909399;
}

.hint-inline {
  margin-left: 8px;
  font-size: 12px;
  color: #909399;
}

.mono {
  font-family: 'JetBrains Mono', Consolas, Monaco, monospace;
  font-size: 12px;
}

.output {
  margin: 0;
  max-height: 320px;
  overflow: auto;
  background: #0b1220;
  color: #e5e7eb;
  padding: 12px;
  border-radius: 8px;
  font-size: 12px;
  line-height: 1.6;
  white-space: pre-wrap;
  word-break: break-all;
}
</style>
