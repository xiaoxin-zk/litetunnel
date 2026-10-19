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
      <el-tab-pane label="站点" name="site">
        <el-form label-width="140px" style="max-width: 720px">
          <el-form-item label="站点名称">
            <el-input v-model="form['site.name']" placeholder="显示在控制台与邮件标题中" />
          </el-form-item>
          <el-form-item label="站点副标题">
            <el-input v-model="form['site.subtitle']" placeholder="显示在登录页站点名下方，留空则不显示" />
          </el-form-item>
          <el-form-item label="站点 Logo">
            <div style="display: flex; align-items: center; gap: 12px">
              <img
                v-if="form['site.logo']"
                :src="form['site.logo']"
                alt="logo"
                style="height: 40px; border-radius: 6px"
              />
              <el-upload
                :auto-upload="false"
                :show-file-list="false"
                accept="image/png,image/jpeg,image/webp,image/gif"
                :on-change="onLogoChange"
              >
                <el-button>选择图片</el-button>
              </el-upload>
              <el-button v-if="form['site.logo']" link type="danger" @click="form['site.logo'] = ''">
                移除
              </el-button>
            </div>
            <span class="hint">
              PNG / JPEG / WebP / GIF，256KB 以内。图片以 data URL 存在设置表里，不依赖对象存储；
              不接受外链与 SVG（SVG 可携带脚本）
            </span>
          </el-form-item>
          <el-form-item label="首页说明">
            <el-input
              v-model="form['site.home_content']"
              type="textarea"
              :rows="4"
              placeholder="登录页公告下方展示，留空则不显示；按纯文本渲染，换行会保留"
            />
          </el-form-item>
          <el-form-item label="站点公告">
            <el-input v-model="form['site.announcement']" type="textarea" :rows="2" placeholder="登录页顶部展示，留空则不显示" />
          </el-form-item>
          <el-form-item label="ICP 备案号">
            <el-input v-model="form['site.icp']" placeholder="如 京ICP备xxxxxxxx号，留空则不显示" />
          </el-form-item>
          <el-form-item label="客户端下载地址">
            <el-input
              v-model="form['site.client_download_url']"
              placeholder="https://github.com/你的账号/仓库/releases/latest"
            />
            <span class="hint">
              填写后控制台的「客户端下载」页会引导用户前往该地址，不再从本站服务器分发。
              留空则回退到本地目录（<code>LT_CLIENT_DIST_DIR</code>）分发
            </span>
          </el-form-item>
          <el-form-item label="隧道网关地址">
            <el-input
              v-model="form['gateway.host']"
              placeholder="panel.example.com 或 203.0.113.10"
            />
            <span class="hint">
              用户端「客户端下载 → 接入信息」显示的服务器地址，也是下发配置里的
              <code>serverAddr</code>。只填主机名或 IP，不要带协议和端口；留空时回落
              <code>LT_GATEWAY_HOST</code>
            </span>
          </el-form-item>
          <el-form-item label="隧道网关端口">
            <el-input-number v-model="numForm['gateway.port']" :min="1" :max="65535" />
            <span class="hint">客户端连接 frps 的端口，默认 7001；留空回落 <code>LT_GATEWAY_PORT</code></span>
          </el-form-item>
        </el-form>
      </el-tab-pane>

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
          <el-form-item label="注册邮箱验证">
            <el-switch v-model="boolForm['register.require_email_verify']" />
            <span class="hint">
              仅在「邮件」页启用了 SMTP 后生效。开启后注册必须填写邮箱并通过一次性验证码，
              邮箱从「可选联系方式」升级为「身份凭证」——这是最有效的反批量注册手段
            </span>
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
              placeholder="逗号分隔，如 @tempmail.com, mailinator.com"
            />
            <span class="hint">
              命中域名及其子域将被直接拒绝，优先级最高；发验证码时就会提示，不用等到提交注册
            </span>
          </el-form-item>

          <el-divider content-position="left">邮箱域名白名单</el-divider>

          <el-form-item label="白名单域名">
            <el-input
              v-model="form['register.allowed_email_domains']"
              type="textarea"
              :rows="2"
              placeholder="@qq.com, @163.com, company.com, *.edu.cn"
            />
            <span class="hint">
              写 <code>@qq.com</code> 或 <code>qq.com</code> 等价，只放行该域名本身（<code>s.qq.com</code> 不放行）；
              要连子域一起放行请写 <code>*.your-domain.com</code>（<code>*.edu.cn</code> 匹配 edu.cn 及其子域）。
              典型用法：企业自有域名列入白名单供员工自由注册；其余公共邮箱仍可注册但受下方限制。
              填错会被拒绝保存，不会静默失效
            </span>
          </el-form-item>
          <el-form-item label="仅白名单可注册">
            <el-switch v-model="boolForm['register.whitelist_only']" />
            <span class="hint">
              开启后非白名单邮箱一律无法注册（填写白名单后才可开启）；发验证码时即拦截
            </span>
          </el-form-item>
          <el-form-item label="白名单外域名名额">
            <el-input-number v-model="numForm['register.non_whitelist_quota']" :min="0" :max="100000" />
            <span class="hint">
              仅「仅白名单可注册」开启且白名单非空时生效：0 = 白名单外直接拒绝；
              N = 每个白名单外主域（如 qq.com）最多注册 N 个账号，累计不按天重置
            </span>
          </el-form-item>
          <el-form-item label="单域名每日上限">
            <el-input-number v-model="numForm['register.max_per_domain_per_day']" :min="0" :max="1000" />
            <span class="hint">
              同一邮箱域名（如 qq.com）每日可注册的数量，0 表示不限；默认 5
            </span>
          </el-form-item>
          <el-form-item label="白名单跳过限制">
            <el-switch v-model="boolForm['register.trusted_domain_skip_limits']" />
            <span class="hint">开启后白名单域名不受「单 IP 上限」与「单域名上限」约束</span>
          </el-form-item>
          <el-form-item label="注册服务条款">
            <el-input v-model="form['register.terms']" type="textarea" :rows="12" />
            <span class="hint">注册时必须勾选同意；建议保留禁止滥用与违规处置条款</span>
          </el-form-item>
        </el-form>
      </el-tab-pane>

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

      <el-tab-pane label="登录安全" name="security">
        <el-form label-width="160px" style="max-width: 720px">
          <el-form-item label="失败几次后要验证码">
            <el-input-number v-model="numForm['login.captcha_after_failures']" :min="0" :max="20" />
            <span class="hint">0 表示始终不要求；默认 3</span>
          </el-form-item>
          <div class="hint" style="margin: -8px 0 18px 160px; line-height: 1.8">
            计数存在数据库表 <code>lt_login_fail_counters</code>（30 分钟窗口，登录成功即清零），
            因此多实例部署共用一个数据库时该阈值仍然成立。但「账号 + IP」的登录硬锁仍在各实例进程内，
            多实例下需要网关会话粘滞，详见 README「多实例部署」。
          </div>
          <el-form-item label="单 IP 每分钟登录上限">
            <el-input-number v-model="numForm['login.max_per_minute']" :min="1" :max="600" />
          </el-form-item>

          <el-divider content-position="left">面板接口限流</el-divider>

          <el-form-item label="接口每分钟上限">
            <el-input-number v-model="numForm['api.rate_limit_per_minute']" :min="1" :max="100000" />
            <span class="hint">单个 IP 每分钟可发起的业务接口请求数，默认 120</span>
          </el-form-item>
          <el-form-item label="接口突发容量">
            <el-input-number v-model="numForm['api.rate_limit_burst']" :min="1" :max="10000" />
            <span class="hint">允许的瞬时峰值，默认 60；调低可防刷，但页面并发加载多时易误伤</span>
          </el-form-item>

          <el-divider content-position="left">敏感操作二次验证</el-divider>

          <el-form-item label="开启 step-up">
            <el-switch v-model="boolForm['security.step_up_enabled']" />
            <span class="hint">
              开启后，改系统设置、管理员管理、防火墙与域名操作、重置用户凭据都需要再输一次动态口令，
              通过后本次登录 15 分钟内有效。开关本身也受保护：关闭它同样要先验证
            </span>
          </el-form-item>

          <el-divider content-position="left">审计日志</el-divider>

          <el-form-item label="操作日志保留天数">
            <el-input-number v-model="numForm['audit.retention_days']" :min="0" :max="3650" />
            <span class="hint">
              每小时维护任务分批清理超期记录，单轮有 5 秒预算，量大会跨轮清完；
              0 表示永久保留，只能手动清理。登录日志固定保留 180 天
            </span>
          </el-form-item>
        </el-form>

        <el-divider />

        <div class="lt-muted" style="line-height: 2">
          以下机制不可通过界面关闭，属于平台底线：<br />
          · 账号级指数退避锁定（合并登录入口：3 次失败锁 30 分钟起，上限 24 小时）<br />
          · 管理员双因素认证（TOTP）<br />
          · 改密即全端下线（令牌版本号）<br />
          · 全部登录尝试写入审计日志，操作日志保留天数可在上方调整
        </div>
      </el-tab-pane>

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

          <el-alert
            type="info"
            :closable="false"
            show-icon
            style="margin-bottom: 16px"
            title="防火墙写操作由宿主机上的 helper 执行"
            description="面板容器不含 iptables，也不持有 NET_ADMIN。它只做只读的端口扫描；需要改防火墙时，请求会转发给宿主机上的 lt-fw 服务。这样即使面板被攻破，攻击者也无法接管主机防火墙。"
          />

          <el-form-item label="启用防火墙控制">
            <el-switch v-model="boolForm['firewall.enabled']" />
            <span class="hint">关闭时面板完全不碰系统防火墙</span>
          </el-form-item>
          <el-form-item label="helper 地址">
            <el-input
              v-model="form['firewall.helper_addr']"
              placeholder="http://127.0.0.1:7849"
            />
            <span class="hint">宿主机 lt-fw 服务的回环地址，通常保持默认即可</span>
          </el-form-item>
          <el-form-item label="helper 访问令牌">
            <el-input
              v-model="form['firewall.helper_token']"
              type="password"
              show-password
              placeholder="与 /etc/litetunnel/lt-fw.env 中的 LT_FW_TOKEN 一致"
            />
            <span class="hint">
              必须与宿主机上 <code>LT_FW_TOKEN</code> 完全一致。
              留空表示不修改；令牌至少 16 个字符
            </span>
          </el-form-item>
          <el-form-item label="自动放行隧道端口">
            <el-switch v-model="boolForm['firewall.auto_open']" />
            <span class="hint">创建隧道时自动放行，删除或停用时自动收回</span>
          </el-form-item>
          <el-form-item label="保护端口">
            <el-input v-model="form['firewall.protected_ports']" placeholder="如 22,80,443,7848" />
            <span class="hint">
              这些端口永远不会被面板关闭。必须包含 SSH 与控制面端口，作为最后一道保险。
              建议与 helper 的 <code>LT_FW_PROTECTED_PORTS</code> 保持一致
            </span>
          </el-form-item>
        </el-form>
      </el-tab-pane>

      <el-tab-pane label="邮件模板" name="mail">
        <el-alert
          type="info"
          :closable="false"
          show-icon
          style="margin-bottom: 16px"
          title="模板存数据库，恢复默认后使用代码内置模板"
          description="只做双花括号占位符的纯文本替换，不执行模板表达式；填入未知变量会被拒绝保存。自定义模板渲染失败时自动回退内置模板，验证码类邮件不会因为模板写错而发不出。"
        />
        <el-form label-width="120px" style="max-width: 900px">
          <el-form-item label="邮件类型">
            <el-select v-model="mailEvent" style="width: 260px" @change="selectMailEvent">
              <el-option
                v-for="t in mailTemplates"
                :key="t.event"
                :label="t.name + (t.custom ? '（已自定义）' : '（内置默认）')"
                :value="t.event"
              />
            </el-select>
            <el-button style="margin-left: 12px" :loading="mailPreviewing" @click="previewMail">
              预览
            </el-button>
            <el-button type="primary" :loading="mailSaving" @click="saveMail">保存模板</el-button>
            <el-button :disabled="!currentMail || !currentMail.custom" @click="resetMail">
              恢复默认
            </el-button>
          </el-form-item>
          <el-form-item label="邮件标题">
            <el-input v-model="mailForm.subject" />
          </el-form-item>
          <el-form-item label="正文 HTML">
            <el-input v-model="mailForm.body" type="textarea" :rows="16" />
            <span class="hint">可用变量：{{ mailVarHint }}</span>
          </el-form-item>
        </el-form>
        <div v-if="mailPreview" style="max-width: 900px">
          <el-divider content-position="left">预览（示例数据）</el-divider>
          <div class="hint" style="margin: 0 0 8px">标题：{{ mailPreview.subject }}</div>
          <iframe
            :srcdoc="mailPreview.body"
            style="width: 100%; height: 460px; border: 1px solid #e5e7eb; border-radius: 8px; background: #fff"
          />
        </div>
      </el-tab-pane>
    </el-tabs>
  </div>
</template>

<script setup>
import { computed, onMounted, reactive, ref } from 'vue'
import { ElMessage } from 'element-plus'
import { Refresh } from '@element-plus/icons-vue'
import { mailTemplateApi, settingsApi } from '../api'

const SECRET_MASK = '__UNCHANGED__'

const BOOL_KEYS = [
  'register.enabled',
  'register.captcha_enabled',
  'register.require_email_verify',
  'register.whitelist_only',
  'register.trusted_domain_skip_limits',
  'smtp.enabled',
  'payment.enabled',
  'firewall.enabled',
  'firewall.auto_open',
  'security.step_up_enabled'
]

const NUM_KEYS = [
  'register.max_per_ip_per_day',
  'register.max_per_domain_per_day',
  'register.non_whitelist_quota',
  'gateway.port',
  'smtp.port',
  'payment.min_amount',
  'payment.max_amount',
  'login.captcha_after_failures',
  'login.max_per_minute',
  'api.rate_limit_per_minute',
  'api.rate_limit_burst',
  'audit.retention_days'
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

const LOGO_MAX_BYTES = 256 * 1024

function onLogoChange(file) {
  const raw = file && file.raw
  if (!raw) return
  if (raw.size > LOGO_MAX_BYTES) {
    ElMessage.warning('图片不能超过 256KB，请压缩后再上传')
    return
  }
  const reader = new FileReader()
  reader.onload = () => {
    form['site.logo'] = String(reader.result || '')
  }
  reader.onerror = () => ElMessage.error('读取图片失败')
  reader.readAsDataURL(raw)
}

const mailTemplates = ref([])
const mailEvent = ref('email_code')
const mailForm = reactive({ subject: '', body: '' })
const mailPreview = ref(null)
const mailSaving = ref(false)
const mailPreviewing = ref(false)

const currentMail = computed(() => mailTemplates.value.find((t) => t.event === mailEvent.value))
const mailVarHint = computed(() =>
  (currentMail.value ? currentMail.value.vars : []).map((v) => `{{${v}}}`).join('  ')
)

function fillMailForm() {
  const t = currentMail.value
  mailForm.subject = t ? t.subject : ''
  mailForm.body = t ? t.body : ''
  mailPreview.value = null
}

async function loadMailTemplates() {
  mailTemplates.value = await mailTemplateApi.list()
  if (!mailTemplates.value.some((t) => t.event === mailEvent.value)) {
    mailEvent.value = mailTemplates.value.length ? mailTemplates.value[0].event : ''
  }
  fillMailForm()
}

function selectMailEvent() {
  fillMailForm()
}

async function saveMail() {
  if (!mailEvent.value) return
  mailSaving.value = true
  try {
    await mailTemplateApi.save(mailEvent.value, {
      subject: mailForm.subject,
      body: mailForm.body
    })
    ElMessage.success('模板已保存，下一次发信生效')
    await loadMailTemplates()
  } finally {
    mailSaving.value = false
  }
}

async function resetMail() {
  if (!mailEvent.value) return
  await mailTemplateApi.reset(mailEvent.value)
  ElMessage.success('已恢复内置默认模板')
  await loadMailTemplates()
}

async function previewMail() {
  if (!mailEvent.value) return
  mailPreviewing.value = true
  try {
    mailPreview.value = await mailTemplateApi.preview(mailEvent.value, {
      subject: mailForm.subject,
      body: mailForm.body
    })
  } finally {
    mailPreviewing.value = false
  }
}

onMounted(() => {
  load()
  loadMailTemplates()
})
</script>

<style scoped>
.hint {
  margin-left: 12px;
  color: #6b7280;
  font-size: 12.5px;
  line-height: 1.7;
}

code {
  font-family: ui-monospace, SFMono-Regular, Consolas, monospace;
  font-size: 12px;
  background: #f5f7fa;
  padding: 1px 4px;
  border-radius: 3px;
  color: #303133;
}
</style>
