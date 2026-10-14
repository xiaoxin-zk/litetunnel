<template>
  <div class="lt-card" v-loading="loading">
    <div class="lt-card-title">
      <span>系统设置</span>
      <div>
        <el-button :icon="Refresh" @click="load">重新载入</el-button>
        <el-button type="primary" :loading="saving" @click="save">保存设置</el-button>
      </div>
    </div>

    <el-alert
      type="info"
      :closable="false"
      show-icon
      style="margin-bottom: 16px"
      title="这里的配置存数据库、即时生效，无需重启容器"
      description="密钥类字段加密存储，界面只显示占位符；留空表示保持原值不变。环境变量中的同名值作为首次部署的默认值。"
    />

    <el-tabs v-model="tab">
      <!-- ============ 站点 ============ -->
      <el-tab-pane label="站点" name="site">
        <el-form label-width="140px" style="max-width: 720px">
          <el-form-item label="站点名称">
            <el-input v-model="form['site.name']" placeholder="显示在控制台与邮件标题中" />
          </el-form-item>
          <el-form-item label="站点公告">
            <el-input v-model="form['site.announcement']" type="textarea" :rows="2" placeholder="登录页顶部展示，留空则不显示" />
          </el-form-item>
          <el-form-item label="ICP 备案号">
            <el-input v-model="form['site.icp']" placeholder="如 京ICP备xxxxxxxx号，留空则不显示" />
          </el-form-item>
        </el-form>
      </el-tab-pane>

      <!-- ============ 注册与准入 ============ -->
      <el-tab-pane label="注册与准入" name="register">
        <el-form label-width="140px" style="max-width: 780px">
          <el-form-item label="开放注册">
            <el-switch v-model="boolForm['register.enabled']" />
            <span class="hint">关闭后任何人都无法自助注册，只能由管理员创建</span>
          </el-form-item>
          <el-form-item label="注册图形验证码">
            <el-switch v-model="boolForm['register.captcha_enabled']" />
            <span class="hint">强烈建议保持开启，否则脚本可批量注册</span>
          </el-form-item>
          <el-form-item label="单 IP 每日上限">
            <el-input-number v-model="numForm['register.max_per_ip_per_day']" :min="0" :max="1000" />
            <span class="hint">0 表示不限制；默认 3</span>
          </el-form-item>
          <el-form-item label="邮箱域名黑名单">
            <el-input
              v-model="form['register.blocked_email_domains']"
              type="textarea"
              :rows="2"
              placeholder="逗号分隔，如 tempmail.com, mailinator.com"
            />
            <span class="hint">命中域名及其子域将被拒绝注册</span>
          </el-form-item>
          <el-form-item label="注册服务条款">
            <el-input v-model="form['register.terms']" type="textarea" :rows="12" />
            <span class="hint">注册时必须勾选同意；建议保留禁止滥用与违规处置条款</span>
          </el-form-item>
        </el-form>
      </el-tab-pane>

      <!-- ============ 邮件 ============ -->
      <el-tab-pane label="邮件" name="smtp">
        <el-form label-width="140px" style="max-width: 720px">
          <el-form-item label="启用邮件">
            <el-switch v-model="boolForm['smtp.enabled']" />
            <span class="hint">启用后可用于找回密码、注册验证码</span>
          </el-form-item>
          <el-form-item label="SMTP 服务器">
            <el-input v-model="form['smtp.host']" placeholder="QQ 邮箱填 smtp.qq.com" />
          </el-form-item>
          <el-form-item label="端口">
            <el-input-number v-model="numForm['smtp.port']" :min="1" :max="65535" />
            <span class="hint">465（SSL）或 587（STARTTLS）；国内 25 端口普遍被封</span>
          </el-form-item>
          <el-form-item label="加密方式">
            <el-select v-model="form['smtp.tls']" style="width: 220px">
              <el-option label="SSL（465）" value="ssl" />
              <el-option label="STARTTLS（587）" value="starttls" />
              <el-option label="不加密（仅内网调试）" value="none" />
            </el-select>
          </el-form-item>
          <el-form-item label="账号">
            <el-input v-model="form['smtp.user']" placeholder="完整邮箱地址" />
          </el-form-item>
          <el-form-item label="授权码">
            <el-input
              v-model="form['smtp.password']"
              type="password"
              show-password
              :placeholder="secretPlaceholder('smtp.password')"
            />
            <span class="hint">QQ 邮箱需填「授权码」而非登录密码；留空表示不修改</span>
          </el-form-item>
          <el-form-item label="发件人">
            <el-input v-model="form['smtp.from']" placeholder="留空则使用账号，如 LiteTunnel <xxx@qq.com>" />
          </el-form-item>
          <el-form-item label="连通性测试">
            <el-input v-model="testTo" placeholder="收件邮箱" style="width: 260px; margin-right: 10px" />
            <el-button :loading="testing" @click="testMail">发送测试邮件</el-button>
            <div class="hint">先点「保存设置」再测试，否则测的是旧配置</div>
          </el-form-item>
        </el-form>
      </el-tab-pane>

      <!-- ============ 支付 ============ -->
      <el-tab-pane label="支付" name="payment">
        <el-alert
          type="warning"
          :closable="false"
          show-icon
          style="margin-bottom: 16px"
          title="当前仅保存配置，尚未接入实际支付流程"
          description="这里先把商户号、密钥、回调地址等信息登记好，后续接入渠道时直接读取。请在正式启用前确认渠道已完成签约。"
        />
        <el-form label-width="140px" style="max-width: 720px">
          <el-form-item label="启用支付">
            <el-switch v-model="boolForm['payment.enabled']" />
          </el-form-item>
          <el-form-item label="支付渠道">
            <el-select v-model="form['payment.provider']" style="width: 260px">
              <el-option label="易支付（聚合）" value="easypay" />
              <el-option label="支付宝" value="alipay" />
              <el-option label="微信支付" value="wechat" />
              <el-option label="Stripe" value="stripe" />
            </el-select>
          </el-form-item>
          <el-form-item label="商户号">
            <el-input v-model="form['payment.app_id']" placeholder="渠道分配的商户号 / AppID" />
          </el-form-item>
          <el-form-item label="商户密钥">
            <el-input
              v-model="form['payment.secret']"
              type="password"
              show-password
              :placeholder="secretPlaceholder('payment.secret')"
            />
            <span class="hint">加密存储；留空表示不修改</span>
          </el-form-item>
          <el-form-item label="异步回调地址">
            <el-input v-model="form['payment.notify_url']" placeholder="https://你的域名/api/payment/notify" />
            <span class="hint">必须公网可达，用于接收支付结果通知</span>
          </el-form-item>
          <el-form-item label="同步跳转地址">
            <el-input v-model="form['payment.return_url']" placeholder="https://你的域名/recharge" />
          </el-form-item>
          <el-form-item label="商品名前缀">
            <el-input v-model="form['payment.product_name']" style="width: 260px" />
          </el-form-item>
          <el-form-item label="充值金额范围">
            <el-input-number v-model="numForm['payment.min_amount']" :min="1" /> 分 ~
            <el-input-number v-model="numForm['payment.max_amount']" :min="1" /> 分
            <div class="hint">单位：分。如 100 表示最低充值 1 元</div>
          </el-form-item>
        </el-form>
      </el-tab-pane>

      <!-- ============ 登录安全 ============ -->
      <el-tab-pane label="登录安全" name="security">
        <el-form label-width="160px" style="max-width: 720px">
          <el-form-item label="失败几次后要验证码">
            <el-input-number v-model="numForm['login.captcha_after_failures']" :min="0" :max="20" />
            <span class="hint">0 表示始终不要求；默认 3</span>
          </el-form-item>
          <el-form-item label="单 IP 每分钟登录上限">
            <el-input-number v-model="numForm['login.max_per_minute']" :min="1" :max="600" />
          </el-form-item>
        </el-form>

        <el-divider />

        <div class="lt-muted" style="line-height: 2">
          以下机制不可通过界面关闭，属于平台底线：<br />
          · 账号级指数退避锁定（合并登录入口：3 次失败锁 30 分钟起，上限 24 小时）<br />
          · 管理员双因素认证（TOTP）<br />
          · 改密即全端下线（令牌版本号）<br />
          · 全部登录尝试写入审计日志，保留 180 天
        </div>
      </el-tab-pane>

      <!-- ============ 端口与防火墙 ============ -->
      <el-tab-pane label="端口与防火墙" name="port">
        <el-alert
          type="warning"
          :closable="false"
          show-icon
          style="margin-bottom: 16px"
          title="防火墙控制为高危功能，默认关闭"
          description="开启后面板需要 NET_ADMIN 能力并接管指定防火墙链，才能自动放行隧道端口。请务必确认「保护端口」包含 SSH 与控制面端口，否则可能把自己锁在服务器外。云服务器安全组不受此功能影响，仍需在云控制台手动放行。"
        />
        <el-form label-width="160px" style="max-width: 780px">
          <el-form-item label="保留端口">
            <el-input
              v-model="form['port.reserved']"
              type="textarea"
              :rows="3"
              placeholder="如 22,80,443,3306,6379,10000-10100"
            />
            <span class="hint">
              这些端口不会被分配给用户隧道。服务器上已被其他服务占用的端口请填在这里；
              面板启动时也会主动探测实际被监听的端口并自动排除。
            </span>
          </el-form-item>

          <el-divider />

          <el-form-item label="启用防火墙控制">
            <el-switch v-model="boolForm['firewall.enabled']" />
            <span class="hint">关闭时面板完全不碰系统防火墙</span>
          </el-form-item>
          <el-form-item label="防火墙后端">
            <el-select v-model="form['firewall.backend']" style="width: 240px">
              <el-option label="自动探测" value="auto" />
              <el-option label="iptables" value="iptables" />
              <el-option label="nftables" value="nftables" />
              <el-option label="ufw" value="ufw" />
              <el-option label="firewalld" value="firewalld" />
            </el-select>
          </el-form-item>
          <el-form-item label="自动放行隧道端口">
            <el-switch v-model="boolForm['firewall.auto_open']" />
            <span class="hint">创建隧道时自动放行，删除或停用时自动收回</span>
          </el-form-item>
          <el-form-item label="保护端口">
            <el-input v-model="form['firewall.protected_ports']" placeholder="如 22,80,443,7848" />
            <span class="hint">
              这些端口永远不会被面板关闭。必须包含 SSH 与控制面端口，作为最后一道保险。
            </span>
          </el-form-item>
        </el-form>
      </el-tab-pane>
    </el-tabs>
  </div>
</template>

<script setup>
import { computed, onMounted, reactive, ref } from 'vue'
import { ElMessage } from 'element-plus'
import { Refresh } from '@element-plus/icons-vue'
import { settingsApi } from '../api'

// 与后端 service.SecretMask 保持一致：原样提交表示「不修改此项」
const SECRET_MASK = '__UNCHANGED__'

const BOOL_KEYS = [
  'register.enabled',
  'register.captcha_enabled',
  'smtp.enabled',
  'payment.enabled',
  'firewall.enabled',
  'firewall.auto_open'
]

const NUM_KEYS = [
  'register.max_per_ip_per_day',
  'smtp.port',
  'payment.min_amount',
  'payment.max_amount',
  'login.captcha_after_failures',
  'login.max_per_minute'
]

const SECRET_KEYS = ['smtp.password', 'payment.secret']

const loading = ref(false)
const saving = ref(false)
const testing = ref(false)
const tab = ref('site')
const testTo = ref('')

const form = reactive({})
const boolForm = reactive({})
const numForm = reactive({})
// 记录服务端返回的敏感字段状态，用于判断「留空 = 不修改」
const secretLoaded = reactive({})

const secretPlaceholder = (key) =>
  secretLoaded[key] ? '已配置，留空表示不修改' : '尚未配置'

function apply(data) {
  const d = data || {}
  Object.keys(d).forEach((k) => {
    const v = d[k]
    if (SECRET_KEYS.includes(k)) {
      secretLoaded[k] = v === SECRET_MASK
      form[k] = ''
      return
    }
    if (BOOL_KEYS.includes(k)) {
      boolForm[k] = v === 'true' || v === '1'
      return
    }
    if (NUM_KEYS.includes(k)) {
      const n = parseInt(v, 10)
      numForm[k] = Number.isNaN(n) ? 0 : n
      return
    }
    form[k] = v ?? ''
  })
}

async function load() {
  loading.value = true
  try {
    apply(await settingsApi.get())
  } finally {
    loading.value = false
  }
}

const payload = computed(() => {
  const out = {}
  Object.keys(form).forEach((k) => {
    if (SECRET_KEYS.includes(k)) {
      // 留空且原本已配置 → 提交占位符表示保持原值
      out[k] = form[k] === '' && secretLoaded[k] ? SECRET_MASK : form[k]
      return
    }
    out[k] = form[k] ?? ''
  })
  Object.keys(boolForm).forEach((k) => {
    out[k] = boolForm[k] ? 'true' : 'false'
  })
  Object.keys(numForm).forEach((k) => {
    out[k] = String(numForm[k] ?? 0)
  })
  return out
})

async function save() {
  saving.value = true
  try {
    await settingsApi.update(payload.value)
    ElMessage.success('已保存，配置即时生效')
    await load()
  } finally {
    saving.value = false
  }
}

async function testMail() {
  if (!testTo.value.trim()) {
    ElMessage.warning('请填写收件邮箱')
    return
  }
  testing.value = true
  try {
    await settingsApi.testMail(testTo.value.trim())
    ElMessage.success('测试邮件已发送，请查收')
  } finally {
    testing.value = false
  }
}

onMounted(load)
</script>

<style scoped>
.hint {
  margin-left: 12px;
  color: #6b7280;
  font-size: 12.5px;
  line-height: 1.7;
}
</style>
