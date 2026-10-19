package model

import "time"

const (
	UserStatusActive   = "active"
	UserStatusDisabled = "disabled"
	UserStatusBanned   = "banned"
)

const (
	TunnelStatusActive   = "active"
	TunnelStatusDisabled = "disabled"
)

const (
	ProxyTypeTCP   = "tcp"
	ProxyTypeUDP   = "udp"
	ProxyTypeHTTP  = "http"
	ProxyTypeHTTPS = "https"
)

const (
	RedeemTypeTraffic  = "traffic"
	RedeemTypeGroup    = "group"
	RedeemTypeBalance  = "balance"
	RedeemTypeDuration = "duration"
)

const (
	RedeemStatusUnused   = "unused"
	RedeemStatusUsedUp   = "used_up"
	RedeemStatusDisabled = "disabled"
)

type User struct {
	ID       uint   `gorm:"primarykey" json:"id"`
	Username string `gorm:"size:64;uniqueIndex;not null" json:"username"`
	Email    string `gorm:"size:128;index" json:"email"`
	Password string `gorm:"size:128;not null" json:"-"`
	Nickname string `gorm:"size:64" json:"nickname"`
	Status   string `gorm:"size:16;index;default:active" json:"status"`

	StateVersion uint64 `gorm:"not null;default:0" json:"-"`
	Incarnation  string `gorm:"size:32;index;not null;default:''" json:"-"`

	GroupID uint   `gorm:"index" json:"group_id"`
	Group   *Group `gorm:"foreignKey:GroupID" json:"group,omitempty"`

	TrafficUsed    int64     `json:"traffic_used"`
	TrafficQuota   int64     `json:"traffic_quota"`
	TrafficResetAt time.Time `gorm:"index" json:"traffic_reset_at"`

	TrafficResetGen int64 `gorm:"not null;default:0" json:"-"`

	Balance int64 `json:"balance"`

	GroupExpireAt *time.Time `gorm:"index" json:"group_expire_at"`

	APIKeyHash      string     `gorm:"size:64;index" json:"-"`
	APIKeyPrefix    string     `gorm:"size:16" json:"api_key_prefix"`
	APIKeyEnc       string     `gorm:"size:512" json:"-"`
	APIKeyCreatedAt *time.Time `json:"api_key_created_at"`

	ClientSecret string `gorm:"size:64;index" json:"-"`

	TokenVersion int `gorm:"default:1" json:"-"`

	RegisterIP    string `gorm:"size:64;index" json:"-"`
	EmailDomain   string `gorm:"size:128;index" json:"-"`
	EmailVerified bool   `gorm:"default:false" json:"email_verified"`

	Remark      string     `gorm:"size:255" json:"remark"`
	LastLoginAt *time.Time `json:"last_login_at"`
	LastLoginIP string     `gorm:"size:64" json:"last_login_ip"`

	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`

	Tunnels []Tunnel `gorm:"foreignKey:UserID" json:"tunnels,omitempty"`
}

func (User) TableName() string { return "lt_users" }

type Group struct {
	ID          uint   `gorm:"primarykey" json:"id"`
	Name        string `gorm:"size:64;uniqueIndex;not null" json:"name"`
	Description string `gorm:"size:255" json:"description"`

	MaxTunnels     int   `json:"max_tunnels"`
	MaxPorts       int   `json:"max_ports"`
	TrafficQuota   int64 `json:"traffic_quota"`
	BandwidthLimit int64 `json:"bandwidth_limit"`

	AllowProtocols      string `gorm:"size:64;default:'tcp,udp,http,https'" json:"allow_protocols"`
	AllowCustomDomain   bool   `json:"allow_custom_domain"`
	AllowPrivilegedPort bool   `json:"allow_privileged_port"`

	Priority int `json:"priority"`

	IsDefault bool `gorm:"index" json:"is_default"`

	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
}

func (Group) TableName() string { return "lt_groups" }

type Tunnel struct {
	ID     uint   `gorm:"primarykey" json:"id"`
	UserID uint   `gorm:"index;not null;uniqueIndex:idx_user_tunnel" json:"user_id"`
	Name   string `gorm:"size:64;not null;uniqueIndex:idx_user_tunnel" json:"name"`
	Type   string `gorm:"size:16;not null" json:"type"`

	LocalIP   string `gorm:"size:64;default:'127.0.0.1'" json:"local_ip"`
	LocalPort int    `json:"local_port"`

	RemotePort int    `gorm:"index" json:"remote_port"`
	Domain     string `gorm:"size:128" json:"domain"`
	Subdomain  string `gorm:"size:64;index" json:"subdomain"`

	BandwidthLimit int64 `json:"bandwidth_limit"`

	UseEncryption  bool `json:"use_encryption"`
	UseCompression bool `json:"use_compression"`

	Status string `gorm:"size:16;index;default:active" json:"status"`
	Remark string `gorm:"size:255" json:"remark"`

	TrafficUsed int64 `json:"traffic_used"`

	Online          bool       `gorm:"-" json:"online"`
	CurConns        int64      `gorm:"-" json:"cur_conns"`
	TodayTrafficIn  int64      `gorm:"-" json:"today_traffic_in"`
	TodayTrafficOut int64      `gorm:"-" json:"today_traffic_out"`
	LastOnlineAt    *time.Time `json:"last_online_at"`

	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
}

func (Tunnel) TableName() string { return "lt_tunnels" }

type TunnelListRev struct {
	UserID uint  `gorm:"primaryKey;autoIncrement:false" json:"user_id"`
	Rev    int64 `gorm:"not null;default:0" json:"rev"`
}

func (TunnelListRev) TableName() string { return "lt_tunnel_list_revs" }

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

func (RedeemCode) TableName() string { return "lt_redeem_codes" }

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

func (RedeemRecord) TableName() string { return "lt_redeem_records" }

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

func (AuditLog) TableName() string { return "lt_audit_logs" }

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

func (ClientSession) TableName() string { return "lt_client_sessions" }

type TrafficDaily struct {
	ID       uint   `gorm:"primarykey" json:"id"`
	UserID   uint   `gorm:"index:idx_traffic_day,unique" json:"user_id"`
	TunnelID uint   `gorm:"index:idx_traffic_day,unique" json:"tunnel_id"`
	Date     string `gorm:"size:10;index:idx_traffic_day,unique" json:"date"`

	InBytes  int64 `json:"in_bytes"`
	OutBytes int64 `json:"out_bytes"`
}

func (TrafficDaily) TableName() string { return "lt_traffic_daily" }

const (
	LoginKindUser  = "user"
	LoginKindAdmin = "admin"
)

const (
	LoginSourceWeb    = "web"
	LoginSourceClient = "client"
)

const (
	LoginResultSuccess  = "success"
	LoginResultBadCred  = "bad_credentials"
	LoginResultDisabled = "disabled"
	LoginResultLocked   = "locked"
	LoginResultTOTPFail = "totp_failed"
)

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

func (LoginLog) TableName() string { return "lt_login_logs" }

// MailTemplate 是可自定义的邮件模板；没有行记录时使用代码内置默认模板。
type MailTemplate struct {
	ID      uint   `gorm:"primarykey" json:"id"`
	Event   string `gorm:"size:64;uniqueIndex;not null" json:"event"`
	Subject string `gorm:"size:255;not null" json:"subject"`
	Body    string `gorm:"type:text;not null" json:"body"`

	UpdatedAt time.Time `json:"updated_at"`
}

func (MailTemplate) TableName() string { return "lt_mail_templates" }

// StepUpGrant 记录某个管理员会话在有效期内已通过 TOTP 二次验证，
// 一条记录对应一次「登录令牌签发批次」，过期即失效。
type StepUpGrant struct {
	ID         uint      `gorm:"primarykey" json:"id"`
	AdminID    uint      `gorm:"uniqueIndex:idx_stepup_session;not null" json:"admin_id"`
	SessionKey string    `gorm:"size:64;uniqueIndex:idx_stepup_session;not null" json:"session_key"`
	ExpiresAt  time.Time `gorm:"index;not null" json:"expires_at"`

	CreatedAt time.Time `json:"created_at"`
}

func (StepUpGrant) TableName() string { return "lt_admin_stepup_grants" }

type EmailCode struct {
	ID        uint       `gorm:"primarykey" json:"id"`
	Email     string     `gorm:"size:128;index;not null" json:"-"`
	Scene     string     `gorm:"size:32;index;not null" json:"-"`
	CodeHash  string     `gorm:"size:64;not null" json:"-"`
	Attempts  int        `gorm:"default:0" json:"-"`
	UsedAt    *time.Time `json:"-"`
	ExpireAt  time.Time  `gorm:"index" json:"-"`
	IP        string     `gorm:"size:64" json:"-"`
	CreatedAt time.Time  `json:"-"`
	MailID    uint       `gorm:"index" json:"-"`
}

func (EmailCode) TableName() string { return "lt_email_codes" }

type PasswordResetToken struct {
	ID        uint       `gorm:"primarykey" json:"id"`
	UserID    uint       `gorm:"index" json:"user_id"`
	TokenHash string     `gorm:"size:64;uniqueIndex" json:"-"`
	ExpireAt  time.Time  `gorm:"index" json:"expire_at"`
	UsedAt    *time.Time `json:"used_at"`
	IP        string     `gorm:"size:64" json:"ip"`

	CreatedAt time.Time `json:"created_at"`
	MailID    uint      `gorm:"index" json:"-"`
}

func (PasswordResetToken) TableName() string { return "lt_password_reset_tokens" }

const (
	MailPending    = "pending"
	MailSending    = "sending"
	MailActivating = "activating"
	MailDraft      = "draft"
	MailDelivered  = "delivered"
	MailSent       = "sent"
	MailFailed     = "failed"
)

const (
	MailKindEmailCodeRegister = "email_code_register"
	MailKindEmailCodeReset    = "email_code_reset"
	MailKindEmailCodeChange   = "email_code_change"
	MailKindResetLink         = "reset_link"
)

type MailOutbox struct {
	ID      uint   `gorm:"primarykey" json:"id"`
	To      string `gorm:"column:to_addr;size:255;not null;index" json:"to"`
	Subject string `gorm:"size:255;not null" json:"subject"`
	Body    string `gorm:"type:text" json:"-"`

	Kind    string `gorm:"size:32;not null;index" json:"kind"`
	Payload string `gorm:"type:text" json:"-"`

	Attempts       int       `gorm:"not null;default:0" json:"attempts"`
	ActionAttempts int       `gorm:"not null;default:0" json:"action_attempts"`
	Status         string    `gorm:"size:16;not null;index;default:pending" json:"status"`
	ClaimToken     string    `gorm:"size:32" json:"-"`
	NextAt         time.Time `gorm:"not null;index" json:"next_at"`
	LastErr        string    `gorm:"size:255" json:"last_err"`

	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
}

func (MailOutbox) TableName() string { return "lt_mail_outbox" }

type TrafficBaseline struct {
	ProxyName string    `gorm:"primarykey;size:191" json:"proxy_name"`
	Date      string    `gorm:"size:10;not null;index" json:"date"`
	InBytes   int64     `gorm:"not null;default:0" json:"in_bytes"`
	OutBytes  int64     `gorm:"not null;default:0" json:"out_bytes"`
	TunnelID  uint      `gorm:"index" json:"tunnel_id"`
	UpdatedAt time.Time `json:"updated_at"`
}

func (TrafficBaseline) TableName() string { return "lt_traffic_baseline" }

type TrafficResetMark struct {
	UserID    uint      `gorm:"primarykey" json:"user_id"`
	Gen       int64     `gorm:"not null;default:0" json:"gen"`
	UpdatedAt time.Time `json:"updated_at"`
}

func (TrafficResetMark) TableName() string { return "lt_traffic_reset_marks" }

type RuntimeLease struct {
	Name      string    `gorm:"primarykey;size:64" json:"name"`
	Holder    string    `gorm:"size:64" json:"holder"`
	ExpiresAt time.Time `gorm:"index" json:"expires_at"`
	Gen       int64     `gorm:"not null;default:0" json:"gen"`
	UpdatedAt time.Time `json:"updated_at"`
}

func (RuntimeLease) TableName() string { return "lt_runtime_leases" }

type FirewallPending struct {
	Port       int       `gorm:"primarykey" json:"port"`
	Proto      string    `gorm:"size:8;not null" json:"proto"`
	Open       bool      `gorm:"not null" json:"open"`
	Attempts   int       `gorm:"not null;default:0" json:"attempts"`
	Exhausted  bool      `gorm:"not null;default:0" json:"exhausted"`
	Generation int64     `gorm:"not null;default:0" json:"generation"`
	LastErr    string    `gorm:"size:255" json:"last_err"`
	CreatedAt  time.Time `json:"created_at"`
	UpdatedAt  time.Time `json:"updated_at"`
}

func (FirewallPending) TableName() string { return "lt_firewall_pending" }

type FirewallSeq struct {
	ID   uint  `gorm:"primarykey" json:"id"`
	Next int64 `gorm:"not null;default:1" json:"next"`
}

func (FirewallSeq) TableName() string { return "lt_firewall_seq" }

type ProxyDrainPending struct {
	UserID       uint      `gorm:"primaryKey;autoIncrement:false" json:"user_id"`
	Incarnation  string    `gorm:"size:32;index" json:"incarnation"`
	Prefix       string    `gorm:"size:64;not null" json:"prefix"`
	StatusGen    uint64    `gorm:"not null;default:0" json:"status_gen"`
	NotAfter     int64     `gorm:"not null;default:0" json:"not_after"`
	Deleted      bool      `gorm:"not null;default:0" json:"deleted"`
	IntentAt     int64     `gorm:"not null;default:0" json:"intent_at"`
	Targets      string    `gorm:"type:text" json:"targets,omitempty"`
	Attempts     int       `gorm:"not null;default:0" json:"attempts"`
	Exhausted    bool      `gorm:"not null;default:0" json:"exhausted"`
	NextAt       time.Time `gorm:"not null;index" json:"next_at"`
	Fence        string    `gorm:"size:32" json:"-"`
	LastErr      string    `gorm:"size:255" json:"last_err"`
	ManualReview bool      `gorm:"not null;default:0;index" json:"manual_review"`
	Suspects     string    `gorm:"type:text" json:"suspects,omitempty"`
	CreatedAt    time.Time `json:"created_at"`
	UpdatedAt    time.Time `json:"updated_at"`
}

func (ProxyDrainPending) TableName() string { return "lt_proxy_drain_pending" }

type LoginFailCounter struct {
	Account   string    `gorm:"primarykey;size:191" json:"account"`
	Count     int       `gorm:"not null;default:0" json:"count"`
	Since     int64     `gorm:"not null;default:0;index" json:"since"`
	UpdatedAt time.Time `json:"updated_at"`
}

func (LoginFailCounter) TableName() string { return "lt_login_fail_counters" }

type Setting struct {
	Key       string    `gorm:"primarykey;size:64" json:"key"`
	Value     string    `gorm:"type:text" json:"value"`
	UpdatedAt time.Time `json:"updated_at"`
}

func (Setting) TableName() string { return "lt_settings" }

type Admin struct {
	ID          uint       `gorm:"primarykey" json:"id"`
	Username    string     `gorm:"size:64;uniqueIndex;not null" json:"username"`
	Password    string     `gorm:"size:128;not null" json:"-"`
	Nickname    string     `gorm:"size:64" json:"nickname"`
	Role        string     `gorm:"size:32;default:'super'" json:"role"`
	Status      string     `gorm:"size:16;default:active" json:"status"`
	LastLoginAt *time.Time `json:"last_login_at"`
	LastLoginIP string     `gorm:"size:64" json:"last_login_ip"`

	TokenVersion int `gorm:"default:1" json:"-"`

	TOTPSecret        string     `gorm:"size:64" json:"-"`
	TOTPPendingSecret string     `gorm:"size:64" json:"-"`
	TOTPEnabled       bool       `gorm:"default:false" json:"totp_enabled"`
	TOTPVerifiedAt    *time.Time `json:"totp_verified_at"`
	TOTPLastStep      int64      `gorm:"not null;default:0" json:"-"`

	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
}

func (Admin) TableName() string { return "lt_admins" }
