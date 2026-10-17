// Package model 定义控制面全部持久化实体。
package model

import "time"

// 用户状态
const (
	UserStatusActive   = "active"
	UserStatusDisabled = "disabled"
	UserStatusBanned   = "banned"
)

// 隧道状态
const (
	TunnelStatusActive   = "active"
	TunnelStatusDisabled = "disabled"
)

// 隧道协议
const (
	ProxyTypeTCP   = "tcp"
	ProxyTypeUDP   = "udp"
	ProxyTypeHTTP  = "http"
	ProxyTypeHTTPS = "https"
)

// 兑换码类型
const (
	RedeemTypeTraffic  = "traffic"  // 增加流量额度（字节）
	RedeemTypeGroup    = "group"    // 升级/切换到指定分组
	RedeemTypeBalance  = "balance"  // 充值余额（分）
	RedeemTypeDuration = "duration" // 延长当前分组有效期（天）
)

// 兑换码状态
const (
	RedeemStatusUnused   = "unused"
	RedeemStatusUsedUp   = "used_up"
	RedeemStatusDisabled = "disabled"
)

// User 平台用户。
//
// 注意：Password 与 APIKeyHash 带 json:"-"，永不进入任何 API 响应。
type User struct {
	ID       uint   `gorm:"primarykey" json:"id"`
	Username string `gorm:"size:64;uniqueIndex;not null" json:"username"`
	Email    string `gorm:"size:128;index" json:"email"`
	Password string `gorm:"size:128;not null" json:"-"`
	Nickname string `gorm:"size:64" json:"nickname"`
	Status   string `gorm:"size:16;index;default:active" json:"status"`

	GroupID uint   `gorm:"index" json:"group_id"`
	Group   *Group `gorm:"foreignKey:GroupID" json:"group,omitempty"`

	// 流量：本计费周期已用/配额（字节）。配额为 0 时回落到分组配额。
	TrafficUsed  int64 `json:"traffic_used"`
	TrafficQuota int64 `json:"traffic_quota"`
	// TrafficResetAt 是周期结束时刻，流量采集每轮按「已到期」筛出需要清零的用户。
	//
	// 必须建索引：不筛的话每轮都得把全部用户读出来才能发现谁到期了，
	// 而那正是要避免的全表成本（见 refreshGuardDue）。
	TrafficResetAt time.Time `gorm:"index" json:"traffic_reset_at"`

	// TrafficResetGen 在管理员清零用量时自增，是**跨进程**的清零代次。
	//
	// 采集写增量时按它做条件更新：清零之后，任何按清零前基线算出的增量都
	// 写不进去，不会出现「清零完流量又冒出来」。进程内的清零标记只对当前
	// 实例可见——多副本时清零请求落在 B、采集跑在 A，A 根本看不到那个标记。
	TrafficResetGen int64 `gorm:"not null;default:0" json:"-"`

	// 余额（单位：分）
	Balance int64 `json:"balance"`

	// 分组到期时间，nil 表示不过期。
	//
	// 同样要索引：到期之后配额与限速回落到默认分组，而数据库里没有任何
	// 写入可挂钩（是时间到了），只能靠调度按「已到期」筛出来重算。
	GroupExpireAt *time.Time `gorm:"index" json:"group_expire_at"`

	// API Key：仅存哈希用于校验；加密密文用于控制台回显；明文只在生成时返回一次
	APIKeyHash      string     `gorm:"size:64;index" json:"-"`
	APIKeyPrefix    string     `gorm:"size:16" json:"api_key_prefix"`
	APIKeyEnc       string     `gorm:"size:512" json:"-"`
	APIKeyCreatedAt *time.Time `json:"api_key_created_at"`

	// ClientSecret 客户端接入凭据，写入 frpc 配置的 metadatas，
	// 由 frps 服务端插件在 Login 回调中校验，实现「每用户独立凭据」。
	// 与 API Key 分离：重置客户端凭据不影响 API 调用，反之亦然。
	ClientSecret string `gorm:"size:64;index" json:"-"`

	// TokenVersion 是已签发令牌的版本号。改密 / 重置密码时自增，
	// 使所有旧令牌立即失效（JWT 本身无状态，无法单独吊销）。
	TokenVersion int `gorm:"default:1" json:"-"`

	// RegisterIP 记录注册来源，用于「单 IP 每日注册上限」的风控统计。
	RegisterIP string `gorm:"size:64;index" json:"-"`
	// EmailDomain 是**注册时**邮箱域名的冗余列，用于「单域名每日注册上限」
	// 的统计。单独存一列而不是每次用 LIKE 查询，是为了让统计能命中索引。
	//
	// 刻意**不随换邮箱更新**：它记的是注册来源。跟着改等于用户换一次邮箱
	// 就把原域名的当日额度退回去，批量注册可以靠「注册→换域名」无限续杯。
	EmailDomain string `gorm:"size:128;index" json:"-"`
	// EmailVerified 表示邮箱是否通过验证码校验（未开启邮件验证时恒为 false）。
	EmailVerified bool `gorm:"default:false" json:"email_verified"`

	Remark      string     `gorm:"size:255" json:"remark"`
	LastLoginAt *time.Time `json:"last_login_at"`
	LastLoginIP string     `gorm:"size:64" json:"last_login_ip"`

	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`

	Tunnels []Tunnel `gorm:"foreignKey:UserID" json:"tunnels,omitempty"`
}

// TableName 固定表名，避免复数推断差异。
func (User) TableName() string { return "lt_users" }

// Group 分组权限套餐。管理员通过分组统一控制用户的隧道数、端口数、流量与限速。
type Group struct {
	ID          uint   `gorm:"primarykey" json:"id"`
	Name        string `gorm:"size:64;uniqueIndex;not null" json:"name"`
	Description string `gorm:"size:255" json:"description"`

	MaxTunnels   int   `json:"max_tunnels"`   // 最大隧道数，0=不限
	MaxPorts     int   `json:"max_ports"`     // 最大端口占用数，0=不限
	TrafficQuota int64 `json:"traffic_quota"` // 月流量配额（字节），0=不限
	// BandwidthLimit 单隧道限速（bit/s），0=不限。由服务端插件强制下发，客户端无法篡改。
	BandwidthLimit int64 `json:"bandwidth_limit"`

	AllowProtocols      string `gorm:"size:64;default:'tcp,udp,http,https'" json:"allow_protocols"`
	AllowCustomDomain   bool   `json:"allow_custom_domain"`
	AllowPrivilegedPort bool   `json:"allow_privileged_port"`

	// Priority 越大越优先，仅用于后台展示排序与默认推荐
	Priority int `json:"priority"`

	IsDefault bool `gorm:"index" json:"is_default"`

	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
}

// TableName 固定表名。
func (Group) TableName() string { return "lt_groups" }

// Tunnel 一条映射规则，对应 frpc 配置中的一个 proxy。
type Tunnel struct {
	ID     uint   `gorm:"primarykey" json:"id"`
	UserID uint   `gorm:"index;not null;uniqueIndex:idx_user_tunnel" json:"user_id"`
	Name   string `gorm:"size:64;not null;uniqueIndex:idx_user_tunnel" json:"name"`
	Type   string `gorm:"size:16;not null" json:"type"`

	LocalIP   string `gorm:"size:64;default:'127.0.0.1'" json:"local_ip"`
	LocalPort int    `json:"local_port"`

	// TCP/UDP 使用固定远程端口；HTTP/HTTPS 使用域名
	RemotePort int    `gorm:"index" json:"remote_port"`
	Domain     string `gorm:"size:128" json:"domain"`
	Subdomain  string `gorm:"size:64;index" json:"subdomain"`

	// 生效限速（bit/s），创建时按分组快照写入
	BandwidthLimit int64 `json:"bandwidth_limit"`

	UseEncryption  bool `json:"use_encryption"`
	UseCompression bool `json:"use_compression"`

	Status string `gorm:"size:16;index;default:active" json:"status"`
	Remark string `gorm:"size:255" json:"remark"`

	// 累计流量（字节），由流量采集器累加
	TrafficUsed int64 `json:"traffic_used"`

	// 以下为运行态，不入库
	Online          bool       `gorm:"-" json:"online"`
	CurConns        int64      `gorm:"-" json:"cur_conns"`
	TodayTrafficIn  int64      `gorm:"-" json:"today_traffic_in"`
	TodayTrafficOut int64      `gorm:"-" json:"today_traffic_out"`
	LastOnlineAt    *time.Time `json:"last_online_at"`

	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
}

// TableName 固定表名。
func (Tunnel) TableName() string { return "lt_tunnels" }

// TunnelListRev 是某个用户隧道清单的修订号，供客户端分页同步时对账。
//
// 由**数据库触发器**维护（见 store.Open 里的 lt_tunnels_rev_* 触发器），
// 而不是由业务代码在每条写路径上手工递增：写隧道的入口有十来处
// （建 / 改 / 删 / 启停 / 批量 / 管理员改归属 / 兑换改套餐 / 删除用户），
// 漏掉任何一处都只会让客户端「少发现一次变更」，很难测出来。
// 触发器与数据变更在同一事务里，天然原子。
//
// 触发条件只覆盖**对账相关字段**：traffic_used、last_online_at 由采集器
// 每轮写入，计入版本会让客户端的多页同步被反复打断。改字段清单时
// 别忘了同步触发器里的 UPDATE OF 列表（见 store.tunnelListRevTriggers）。
type TunnelListRev struct {
	UserID uint  `gorm:"primaryKey;autoIncrement:false" json:"user_id"`
	Rev    int64 `gorm:"not null;default:0" json:"rev"`
}

// TableName 固定表名。
func (TunnelListRev) TableName() string { return "lt_tunnel_list_revs" }

// RedeemCode 兑换码。
type RedeemCode struct {
	ID      uint   `gorm:"primarykey" json:"id"`
	Code    string `gorm:"size:64;uniqueIndex;not null" json:"code"`
	BatchNo string `gorm:"size:64;index" json:"batch_no"`

	Type    string `gorm:"size:16;not null" json:"type"`
	Value   int64  `json:"value"`
	GroupID uint   `json:"group_id"`

	MaxUses   int `json:"max_uses"`
	UsedCount int `json:"used_count"`

	Status   string     `gorm:"size:16;index;default:unused" json:"status"`
	ExpireAt *time.Time `json:"expire_at"`

	CreatedBy uint   `json:"created_by"`
	Remark    string `gorm:"size:255" json:"remark"`

	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
}

// TableName 固定表名。
func (RedeemCode) TableName() string { return "lt_redeem_codes" }

// RedeemRecord 兑换流水。
type RedeemRecord struct {
	ID     uint   `gorm:"primarykey" json:"id"`
	UserID uint   `gorm:"index" json:"user_id"`
	CodeID uint   `gorm:"index" json:"code_id"`
	Code   string `gorm:"size:64" json:"code"`
	Type   string `gorm:"size:16" json:"type"`
	Value  int64  `json:"value"`
	Result string `gorm:"size:32" json:"result"`
	IP     string `gorm:"size:64" json:"ip"`

	CreatedAt time.Time `gorm:"index" json:"created_at"`
}

// TableName 固定表名。
func (RedeemRecord) TableName() string { return "lt_redeem_records" }

// AuditLog 管理员操作审计。
type AuditLog struct {
	ID        uint   `gorm:"primarykey" json:"id"`
	AdminID   uint   `gorm:"index" json:"admin_id"`
	AdminName string `gorm:"size:64" json:"admin_name"`
	Action    string `gorm:"size:64;index" json:"action"`
	Target    string `gorm:"size:64" json:"target"`
	TargetID  string `gorm:"size:64" json:"target_id"`
	Detail    string `gorm:"type:text" json:"detail"`
	IP        string `gorm:"size:64" json:"ip"`

	CreatedAt time.Time `gorm:"index" json:"created_at"`
}

// TableName 固定表名。
func (AuditLog) TableName() string { return "lt_audit_logs" }

// ClientSession 记录一次 frpc 登录会话，用于在线状态与设备管理。
//
// 安全语义：本表**只在 Login 回调通过每用户凭据校验后才写入**，
// 因此它是「该 run_id 确实完成过认证」的唯一凭据来源。
// 服务端插件在内存缓存未命中时，必须依赖本表而不是客户端自报的用户名。
type ClientSession struct {
	ID       uint   `gorm:"primarykey" json:"id"`
	UserID   uint   `gorm:"index" json:"user_id"`
	Username string `gorm:"size:64;index" json:"username"`
	RunID    string `gorm:"size:64;uniqueIndex" json:"run_id"`
	Addr     string `gorm:"size:64" json:"addr"`
	Version  string `gorm:"size:32" json:"version"`
	OS       string `gorm:"size:32" json:"os"`
	Arch     string `gorm:"size:32" json:"arch"`

	Online     bool      `gorm:"index" json:"online"`
	LastSeenAt time.Time `json:"last_seen_at"`
	CreatedAt  time.Time `json:"created_at"`
}

// TableName 固定表名。
func (ClientSession) TableName() string { return "lt_client_sessions" }

// TrafficDaily 按天汇总的流量，用于曲线展示。
type TrafficDaily struct {
	ID       uint   `gorm:"primarykey" json:"id"`
	UserID   uint   `gorm:"index:idx_traffic_day,unique" json:"user_id"`
	TunnelID uint   `gorm:"index:idx_traffic_day,unique" json:"tunnel_id"`
	Date     string `gorm:"size:10;index:idx_traffic_day,unique" json:"date"`

	InBytes  int64 `json:"in_bytes"`
	OutBytes int64 `json:"out_bytes"`
}

// TableName 固定表名。
func (TrafficDaily) TableName() string { return "lt_traffic_daily" }

// 登录主体类型
const (
	LoginKindUser  = "user"
	LoginKindAdmin = "admin"
)

// 登录来源
const (
	LoginSourceWeb    = "web"
	LoginSourceClient = "client"
)

// 登录结果
const (
	LoginResultSuccess  = "success"
	LoginResultBadCred  = "bad_credentials"
	LoginResultDisabled = "disabled"
	LoginResultLocked   = "locked"
	LoginResultTOTPFail = "totp_failed"
)

// LoginLog 记录每一次登录尝试，用户与管理员共用一张表。
//
// 无论成功失败都记录：失败记录才是发现暴力破解的依据。
type LoginLog struct {
	ID        uint   `gorm:"primarykey" json:"id"`
	Kind      string `gorm:"size:16;index" json:"kind"`
	AccountID uint   `gorm:"index" json:"account_id"`
	Username  string `gorm:"size:64;index" json:"username"`
	IP        string `gorm:"size:64" json:"ip"`
	UserAgent string `gorm:"size:255" json:"user_agent"`
	Source    string `gorm:"size:16" json:"source"`
	Result    string `gorm:"size:24;index" json:"result"`
	Detail    string `gorm:"size:255" json:"detail"`

	CreatedAt time.Time `gorm:"index" json:"created_at"`
}

// TableName 固定表名。
func (LoginLog) TableName() string { return "lt_login_logs" }

// EmailCode 是一次性邮箱验证码（6 位数字）。
//
// 与 PasswordResetToken 并存不是冗余，而是场景不同：
//   - 网页端找回密码：点邮件里的链接最省事，用 PasswordResetToken；
//   - 桌面客户端：在应用里点链接体验很差，填 6 位验证码更自然，用本表；
//   - 注册邮箱验证：同理用验证码。
//
// 只存 SHA-256 摘要：数据库被读取时无法反推出可用的验证码。
type EmailCode struct {
	ID    uint   `gorm:"primarykey" json:"id"`
	Email string `gorm:"size:128;index;not null" json:"-"`
	// Scene 区分用途：register（注册验证）| reset（找回密码）
	Scene    string `gorm:"size:32;index;not null" json:"-"`
	CodeHash string `gorm:"size:64;not null" json:"-"`
	// Attempts 记录校验失败次数。6 位数字只有 100 万种可能，
	// 不限次数的校验等于把这个验证码变成一个可暴力枚举的口令。
	Attempts  int        `gorm:"default:0" json:"-"`
	UsedAt    *time.Time `json:"-"`
	ExpireAt  time.Time  `gorm:"index" json:"-"`
	IP        string     `gorm:"size:64" json:"-"`
	CreatedAt time.Time  `json:"-"`
	// MailID 是激活这条验证码的发件箱记录 ID，用于「最新凭据胜出」判定：
	// 入队更晚（ID 更大）的邮件产生的凭据优先。必须持久化而不是靠
	// created_at 比较——SQLite 的时间精度是秒级，同一秒内的两封信
	// 分不出先后；而且凭据被使用后行仍然保留（只置 used_at），
	// 这条「谁更新」的关系才不会随消费而消失。
	MailID uint `gorm:"index" json:"-"`
}

// TableName 固定表名。
func (EmailCode) TableName() string { return "lt_email_codes" }

// PasswordResetToken 是找回密码的一次性令牌。
//
// 只存 SHA-256 摘要：数据库泄露也无法据此重置他人密码。
type PasswordResetToken struct {
	ID        uint       `gorm:"primarykey" json:"id"`
	UserID    uint       `gorm:"index" json:"user_id"`
	TokenHash string     `gorm:"size:64;uniqueIndex" json:"-"`
	ExpireAt  time.Time  `gorm:"index" json:"expire_at"`
	UsedAt    *time.Time `json:"used_at"`
	IP        string     `gorm:"size:64" json:"ip"`

	CreatedAt time.Time `json:"created_at"`
	// MailID 是激活这条令牌的发件箱记录 ID，语义见 EmailCode.MailID：
	// 用持久化的先后关系（而不是秒级的 created_at）判定最新凭据，
	// 且该关系在令牌被使用后仍然保留。
	MailID uint `gorm:"index" json:"-"`
}

// TableName 固定表名。
func (PasswordResetToken) TableName() string { return "lt_password_reset_tokens" }

// 发件箱状态。
const (
	// MailPending 待发送（含等待重试）。
	MailPending = "pending"
	// MailSending 已被某个实例领取、正在发送。
	//
	// 领取是条件更新（pending → sending，并把 next_at 写成租约到期时间）：
	// 多实例共用一个库时，同一封信只会被一个实例取走；实例在发送途中崩溃，
	// 租约到期后另一个实例可以重新领取（至多重复投递一次，方向安全）。
	MailSending = "sending"
	// MailActivating 已被某个实例领取、正在执行凭据动作（激活验证码/令牌）。
	//
	// 与发送分开是必要的：激活不重发邮件、失败只重试这一步；两者各自需要
	// 「谁领谁写」的租约，否则多实例会各激活一次（验证码被插两条，一次性失效）。
	MailActivating = "activating"
	// MailDraft 是**已废弃**的状态，仅为升级清理保留。
	//
	// 某个中间版本用它表示「已写好、待复核额度」，进程若在复核与释放之间
	// 崩溃就会留下这种行：正文里是明文验证码/重置链接，而清理任务只回收
	// failed / sent。启动时会统一把它们按失败处理并清空敏感内容
	// （见 store.purgeLegacyMailDrafts），代码里不应再写入这个状态。
	MailDraft = "draft"
	// MailDelivered 邮件已送达，但凭据动作还没完成。
	//
	// 必须与 MailSent 分开：凭据激活是数据库操作，可能瞬时失败。若把它和
	// 「发送」绑成一步，激活失败就会把整封邮件标成 failed 而不再重试——
	// 用户手里拿着一个验证码，库里却没有对应记录，谁也救不回来。
	// 分开之后，这一步只重试**数据库动作**，不会重复发信。
	MailDelivered = "delivered"
	// MailSent 已送达且凭据动作已完成，整件事结束。
	MailSent = "sent"
	// MailFailed 重试次数耗尽，已放弃。需要人工介入。
	MailFailed = "failed"
)

// 邮件类型，决定送达后要执行什么凭据动作。
const (
	// MailKindEmailCodeRegister 注册邮箱验证码。
	MailKindEmailCodeRegister = "email_code_register"
	// MailKindEmailCodeReset 找回密码的邮箱验证码。
	MailKindEmailCodeReset = "email_code_reset"
	// MailKindEmailCodeChange 更换邮箱时发给**新地址**的验证码。
	//
	// 单独一种而不是复用上面两种：作废旧凭据、限流计数、注销清理都按
	// 类型/场景区分，混用会让「换邮箱」与「注册验证」互相干扰。
	MailKindEmailCodeChange = "email_code_change"
	// MailKindResetLink 找回密码的重置链接。
	MailKindResetLink = "reset_link"
)

// MailOutbox 是持久化的发件箱。
//
// # 为什么必须是持久化的
//
// 发信原先走内存 channel：进程一重启，队列里的信就没了；SMTP 报错也只是记一行
// 日志然后把信丢掉。而验证码与重置链接的流程会在「信进队列」时就作废旧凭据，
// 于是用户既收不到新凭据、旧凭据也失效了——账号彻底找不回来。
//
// 落库之后：重启不丢信、失败可重试，并且**凭据只在送达之后才生效**
// （见 Payload 与 service 里的 applyMailAction）。
//
// Body 里含有明文验证码/重置链接，这是「可重发」的前提，但也意味着它是一份
// 敏感数据。因此它的生命周期被压到最短：**发送成功那一刻就清空**（不会再重发），
// 而不是等 24 小时后随记录一起清理——数据库备份或只读泄露期间，留在库里的
// 明文凭据仍然可用。Payload 里是凭据摘要与参数，在凭据动作完成后同样清空。
type MailOutbox struct {
	ID uint `gorm:"primarykey" json:"id"`
	// To 收件人。列名用 to_addr：to 在部分数据库里是保留字。
	To      string `gorm:"column:to_addr;size:255;not null;index" json:"to"`
	Subject string `gorm:"size:255;not null" json:"subject"`
	Body    string `gorm:"type:text" json:"-"`

	// Kind 决定送达后执行哪个凭据动作。
	Kind string `gorm:"size:32;not null;index" json:"kind"`
	// Payload 是凭据动作所需的参数（JSON）。
	Payload string `gorm:"type:text" json:"-"`

	// Attempts 是**发送**的尝试次数。
	Attempts int `gorm:"not null;default:0" json:"attempts"`
	// ActionAttempts 是凭据激活的尝试次数，与发送分开计数：
	// 两者失败原因完全不同（网络 vs 数据库），混在一起会让排查无从下手。
	ActionAttempts int    `gorm:"not null;default:0" json:"action_attempts"`
	Status         string `gorm:"size:16;not null;index;default:pending" json:"status"`
	// ClaimToken 是当前持有者的领取令牌（每次领取重新生成）。
	//
	// 所有回写（送达/失败/激活结果）都必须带上它：租约过期、别的实例接手之后，
	// 旧持有者的结果不能再覆盖新持有者的状态——否则会出现「已被换邮箱作废的
	// 邮件被旧持有者写回待发」「旧实例把新实例的领取状态改掉」这类交错。
	ClaimToken string `gorm:"size:32" json:"-"`
	// NextAt 下次尝试时间，用于退避（发送与激活共用）；领取时改写为租约到期时间。
	NextAt  time.Time `gorm:"not null;index" json:"next_at"`
	LastErr string    `gorm:"size:255" json:"last_err"`

	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
}

// TableName 固定表名。
func (MailOutbox) TableName() string { return "lt_mail_outbox" }

// TrafficBaseline 是流量采集的采样基线。
//
// # 为什么必须落库
//
// 采集器算的是「frps 当前累计值 − 上次采样值」。这个上次采样值原先只在内存
// 里，控制面一重启就没了，而 frps 的**当日累计值还在**——第一次采集于是把
// 当天全部流量当成新增量记一遍：用户配额被凭空扣掉一大截，统计也跟着翻倍。
//
// 只在「只重启控制面、frps 没重启」时暴露，而滚动升级恰好就是这个形态，
// 所以它属于「上线时才炸」的那类问题。
//
// 按代理全名（"lt_u1.mc"）保存，并记下日期：跨零点后 frps 的当日计数归零，
// 昨天的基线不能再拿来相减。
type TrafficBaseline struct {
	ProxyName string `gorm:"primarykey;size:191" json:"proxy_name"`
	// Date 是基线所属日期（本地时区 YYYY-MM-DD）。
	Date string `gorm:"size:10;not null;index" json:"date"`
	// InBytes / OutBytes 是采样时刻 frps 上报的当日累计值。
	InBytes  int64 `gorm:"not null;default:0" json:"in_bytes"`
	OutBytes int64 `gorm:"not null;default:0" json:"out_bytes"`
	// TunnelID 是采样时这条代理对应的隧道行 ID。
	//
	// 代理名只由「用户 ID + 隧道名」组成：删掉隧道再建一条同名的，
	// 代理名完全相同但 frps 侧的当日累计从 0 重新开始。没有这个标识的话，
	// 采集会拿旧代理的基线去减新代理的计数，把新隧道前段流量算丢。
	TunnelID  uint      `gorm:"index" json:"tunnel_id"`
	UpdatedAt time.Time `json:"updated_at"`
}

// TableName 固定表名。
func (TrafficBaseline) TableName() string { return "lt_traffic_baseline" }

// TrafficResetMark 记录「当前采样基线对应的用户清零代次」。
//
// # 为什么必须落库
//
// 清零代次（User.TrafficResetGen）用来判断「这一轮增量是否横跨了清零点」。
// 判断需要两个值：当前代次，以及**上一次基线对应的代次**。后者原先只在内存里，
// 采集进程重启或换手后是空的，于是「清零发生在上次采样之后、重启之前」这段
// 窗口里的旧流量会被重新计入——而这正是代次机制要防的事。
//
// 与基线一样，写入发生在落库事务里：基线推进到哪，代次就记到哪。
type TrafficResetMark struct {
	UserID    uint      `gorm:"primarykey" json:"user_id"`
	Gen       int64     `gorm:"not null;default:0" json:"gen"`
	UpdatedAt time.Time `json:"updated_at"`
}

// TableName 固定表名。
func (TrafficResetMark) TableName() string { return "lt_traffic_reset_marks" }

// RuntimeLease 是跨实例的运行期租约（当前用于「流量采集只由一个实例跑」）。
//
// # 为什么需要它
//
// 每个面板进程都会启动采集器，各自从 frps 读同一份累计值、各自算增量、
// 各自把增量加进用户用量——同一段流量会被记两遍。进程内的互斥（Runtime.mu）
// 管不到别的进程，所以租约必须落在数据库里。
//
// 抢占用条件更新实现：只有把 expires_at 推进成功的那一个实例，在租期内独占。
// 实例崩溃后租约自然过期，另一个实例接手；接手的实例要重新读一次采样基线
// （它自己的内存基线是旧的），否则会把当天累计值整个重记一遍。
type RuntimeLease struct {
	Name      string    `gorm:"primarykey;size:64" json:"name"`
	Holder    string    `gorm:"size:64" json:"holder"`
	ExpiresAt time.Time `gorm:"index" json:"expires_at"`
	// Gen 是递增的租约代次：每次取得/续租/交还都 +1。
	//
	// 它是 fencing token：持有者写库时在**同一个事务里**核对代次，代次变了
	// 就说明租约已被别人接手（或已交还），本轮结果必须丢弃。只看「现在是不是
	// 我持有」是不够的——检查与提交之间仍可能被接管。
	Gen       int64     `gorm:"not null;default:0" json:"gen"`
	UpdatedAt time.Time `json:"updated_at"`
}

// TableName 固定表名。
func (RuntimeLease) TableName() string { return "lt_runtime_leases" }

// FirewallPending 是一条待重试的防火墙端口操作。
//
// # 为什么必须落库
//
// 这个队列原先只在内存里：helper 不可用时关闭失败，待办记在内存，进程一重启
// 就没了。而启动时的规则对齐**只补放行活跃隧道的端口、不回收任何规则**，
// 于是那条本该关掉的规则会长期留在宿主机防火墙上——端口对外开着，
// 而面板上那条隧道早已停用或删除，没有任何地方能看出来。
//
// 落库之后，重启只是「换个人继续重试」，意图不会丢。
//
// 注意 Port 是唯一键：一个端口同时只可能有一个意图，后来的覆盖先前的。
type FirewallPending struct {
	Port int `gorm:"primarykey" json:"port"`
	// Proto 是 tcp / udp。
	Proto string `gorm:"size:8;not null" json:"proto"`
	// Open 为 true 表示待放行，false 表示待收回。
	Open bool `gorm:"not null" json:"open"`
	// Attempts 已重试次数，达到上限后放弃并记录日志。
	Attempts int `gorm:"not null;default:0" json:"attempts"`
	// Exhausted 为 true 表示重试已到上限、自动处理终止：
	// 记录保留在管理页上，等管理员手工处理。
	//
	// 以前到上限是直接删记录，只留一行日志——日志一滚动就什么线索都没有了，
	// 「该收回的端口一直开着」这件事从此在界面上任何地方都看不出来。
	Exhausted bool `gorm:"not null;default:0" json:"exhausted"`
	// LastErr 最后一次失败原因，供排查用。
	LastErr   string    `gorm:"size:255" json:"last_err"`
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
}

// TableName 固定表名。
func (FirewallPending) TableName() string { return "lt_firewall_pending" }

// Setting 运行期可调的键值配置。
type Setting struct {
	Key       string    `gorm:"primarykey;size:64" json:"key"`
	Value     string    `gorm:"type:text" json:"value"`
	UpdatedAt time.Time `json:"updated_at"`
}

// TableName 固定表名。
func (Setting) TableName() string { return "lt_settings" }

// Admin 管理员账号，与用户体系完全隔离（不同表、不同登录入口、不同密钥）。
//
// 管理后台与用户控制台共用公网端口，因此管理员口令之外还必须提供
// 第二道防线：TOTP 双因素认证。
type Admin struct {
	ID          uint       `gorm:"primarykey" json:"id"`
	Username    string     `gorm:"size:64;uniqueIndex;not null" json:"username"`
	Password    string     `gorm:"size:128;not null" json:"-"`
	Nickname    string     `gorm:"size:64" json:"nickname"`
	Role        string     `gorm:"size:32;default:'super'" json:"role"` // super | operator | auditor
	Status      string     `gorm:"size:16;default:active" json:"status"`
	LastLoginAt *time.Time `json:"last_login_at"`
	LastLoginIP string     `gorm:"size:64" json:"last_login_ip"`

	// TokenVersion 同用户侧：改密后旧令牌立即失效。
	TokenVersion int `gorm:"default:1" json:"-"`

	// TOTPSecret 为双因素认证共享密钥（Base32）。json:"-" 保证永不外泄。
	TOTPSecret string `gorm:"size:64" json:"-"`
	// TOTPPendingSecret 是**待确认**的新密钥（换绑流程用）。
	//
	// 换绑时新密钥先放这里，totp_secret / totp_enabled 保持原样；等管理员用新
	// 设备生成的口令调 Enable 验证通过，才原子地把它提升为生效密钥。
	//
	// 为什么不直接替换：直接替换会把 totp_enabled 置回 false，而确认这一步要等
	// 用户去扫码、输码——中间只要关掉页面、网络中断或输错，账号就会停在
	// 「只有密码保护」的状态，而用户以为自己刚换绑成功。暂存之后，未完成换绑
	// 等于什么都没发生。
	TOTPPendingSecret string `gorm:"size:64" json:"-"`
	// TOTPEnabled 为 true 时登录必须携带动态口令。
	TOTPEnabled bool `gorm:"default:false" json:"totp_enabled"`
	// TOTPVerifiedAt 记录最近一次成功校验时间，仅用于展示。
	TOTPVerifiedAt *time.Time `json:"totp_verified_at"`
	// TOTPLastStep 记录最近一次被接受的动态口令步进码，用于防重放。
	//
	// 必须落库：以前只记在内存里，控制面重启、或请求被负载均衡到另一个实例
	// 之后记录就没了，而同一个口令在 ±1 步（最长 90 秒）窗口内仍然有效——
	// 钓鱼反代拿到口令后重放，就能在窗口内二次登录。
	TOTPLastStep int64 `gorm:"not null;default:0" json:"-"`

	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
}

// TableName 固定表名。
func (Admin) TableName() string { return "lt_admins" }
