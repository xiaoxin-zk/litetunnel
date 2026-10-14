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
	TrafficUsed    int64     `json:"traffic_used"`
	TrafficQuota   int64     `json:"traffic_quota"`
	TrafficResetAt time.Time `json:"traffic_reset_at"`

	// 余额（单位：分）
	Balance int64 `json:"balance"`

	// 分组到期时间，nil 表示不过期
	GroupExpireAt *time.Time `json:"group_expire_at"`

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
	// EmailDomain 是邮箱域名的冗余列，用于「单域名每日注册上限」的统计。
	// 单独存一列而不是每次用 LIKE 查询，是为了让统计能命中索引。
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
	LoginResultSuccess   = "success"
	LoginResultBadCred   = "bad_credentials"
	LoginResultDisabled  = "disabled"
	LoginResultLocked    = "locked"
	LoginResultTOTPFail  = "totp_failed"
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
}

// TableName 固定表名。
func (PasswordResetToken) TableName() string { return "lt_password_reset_tokens" }

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
	// TOTPEnabled 为 true 时登录必须携带动态口令。
	TOTPEnabled bool `gorm:"default:false" json:"totp_enabled"`
	// TOTPVerifiedAt 记录最近一次成功校验时间，仅用于展示。
	TOTPVerifiedAt *time.Time `json:"totp_verified_at"`

	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
}

// TableName 固定表名。
func (Admin) TableName() string { return "lt_admins" }
