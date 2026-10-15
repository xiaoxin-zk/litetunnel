// Package userapi 实现用户控制台 API。
//
// 该包只注册在「用户侧监听地址」上，与管理后台在物理端口上隔离：
// 即使管理路由被误注册，也无法从公网端口访问。
package userapi

import (
	"errors"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/gin-gonic/gin"

	"github.com/xiaoxin-zk/litetunnel/server/internal/handler/shared"
	"github.com/xiaoxin-zk/litetunnel/server/internal/httpx"
	"github.com/xiaoxin-zk/litetunnel/server/internal/middleware"
	"github.com/xiaoxin-zk/litetunnel/server/internal/model"
	"github.com/xiaoxin-zk/litetunnel/server/internal/service"
)

// Handler 用户控制台处理器。
type Handler struct {
	svc *service.Services
	// guard 按账号维度锁定连续登录失败，抵御代理池对单一账号的慢速爆破。
	guard *middleware.LoginGuard
}

// New 构造处理器。
func New(svc *service.Services) *Handler {
	return &Handler{
		svc: svc,
		// 连续失败 5 次开始锁定，首次 15 分钟，之后逐次翻倍，上限 24 小时。
		guard: middleware.NewLoginGuard(5, 15*time.Minute, 24*time.Hour),
	}
}

// ---- 认证 ----

type registerReq struct {
	Username string `json:"username" binding:"required"`
	Password string `json:"password" binding:"required"`
	Email    string `json:"email"`

	// 准入校验材料：条款勾选与图形验证码
	Agreed        bool   `json:"agreed"`
	CaptchaTicket string `json:"captcha_ticket"`
	CaptchaAnswer string `json:"captcha_answer"`
	// EmailCode 是邮箱一次性验证码。站点启用邮件后为必填。
	EmailCode string `json:"email_code"`
}

// Register 用户注册。
//
// 准入校验（注册开关、条款、验证码、邮箱黑名单、同 IP 频率）都在 service 层完成，
// handler 只负责把请求字段透传过去。
func (h *Handler) Register(c *gin.Context) {
	var req registerReq
	if err := c.ShouldBindJSON(&req); err != nil {
		httpx.BadRequest(c, "请填写用户名与密码")
		return
	}
	u, err := h.svc.Register(service.RegisterInput{
		Username:      req.Username,
		Password:      req.Password,
		Email:         req.Email,
		IP:            httpx.ClientIP(c),
		AgreedTerms:   req.Agreed,
		CaptchaTicket: req.CaptchaTicket,
		CaptchaAnswer: req.CaptchaAnswer,
		EmailCode:     req.EmailCode,
	})
	if err != nil {
		shared.Fail(c, err)
		return
	}
	httpx.OK(c, gin.H{"id": u.ID, "username": u.Username})
}

// recordLogin 写入登录日志，自动补齐 IP 与 UA。
func (h *Handler) recordLogin(c *gin.Context, a service.LoginAttempt) {
	a.IP = httpx.ClientIP(c)
	a.UserAgent = c.GetHeader("User-Agent")
	h.svc.RecordLogin(a)
}

// 说明：用户登录已合并到 /api/auth/login（见 handler/authapi），
// 这里不再保留独立的用户登录入口，避免出现第二条可爆破的密码校验路径。

// Logout 用户登出。JWT 无状态，服务端仅作审计记录，客户端需自行清除令牌。
func (h *Handler) Logout(c *gin.Context) {
	httpx.OK(c, gin.H{"message": "已退出登录"})
}

// Profile 当前用户信息。
func (h *Handler) Profile(c *gin.Context) {
	u, err := h.svc.LoadUser(middleware.CurrentUserID(c))
	if err != nil {
		shared.Fail(c, err)
		return
	}
	httpx.OK(c, h.profileVO(u))
}

// UpdateProfile 修改当前用户资料（用户名 / 昵称 / 邮箱）。
//
// 用户名可以修改：frp 侧以不可变用户 ID 识别身份，改名不会影响已连接的客户端。
func (h *Handler) UpdateProfile(c *gin.Context) {
	var in service.ProfileUpdateInput
	if err := c.ShouldBindJSON(&in); err != nil {
		httpx.BadRequest(c, "参数格式不正确")
		return
	}
	u, err := h.svc.UpdateProfile(middleware.CurrentUserID(c), in)
	if err != nil {
		shared.Fail(c, err)
		return
	}
	httpx.OK(c, h.profileVO(u))
}

type deleteAccountReq struct {
	Password string `json:"password" binding:"required"`
}

// DeleteAccount 用户注销自己的账号。
//
// 需要密码二次确认：注销不可恢复，必须防止令牌被盗后被恶意注销。
func (h *Handler) DeleteAccount(c *gin.Context) {
	var req deleteAccountReq
	if err := c.ShouldBindJSON(&req); err != nil {
		httpx.BadRequest(c, "请输入登录密码以确认注销")
		return
	}
	uid := middleware.CurrentUserID(c)
	if err := h.svc.DeleteAccount(uid, req.Password); err != nil {
		shared.Fail(c, err)
		return
	}
	h.svc.RecordLogin(service.LoginAttempt{
		Kind:      model.LoginKindUser,
		AccountID: uid,
		IP:        httpx.ClientIP(c),
		UserAgent: c.GetHeader("User-Agent"),
		Source:    model.LoginSourceWeb,
		Result:    "account_deleted",
		Detail:    "用户自助注销账号",
	})
	httpx.OK(c, gin.H{"message": "账号已注销，感谢使用"})
}

type changePasswordReq struct {
	OldPassword string `json:"old_password" binding:"required"`
	NewPassword string `json:"new_password" binding:"required"`
}

// ChangePassword 修改密码。
func (h *Handler) ChangePassword(c *gin.Context) {
	var req changePasswordReq
	if err := c.ShouldBindJSON(&req); err != nil {
		httpx.BadRequest(c, "请填写原密码与新密码")
		return
	}
	if err := h.svc.UpdatePassword(middleware.CurrentUserID(c), req.OldPassword, req.NewPassword); err != nil {
		shared.Fail(c, err)
		return
	}
	httpx.OK(c, gin.H{"message": "密码已更新，请重新登录"})
}

// profileVO 用户信息视图对象。不包含口令与任何密钥字段。
func (h *Handler) profileVO(u *model.User) gin.H {
	g := h.svc.EffectiveGroup(u)
	quota := h.svc.EffectiveQuota(u)
	vo := gin.H{
		"id":                u.ID,
		"username":          u.Username,
		"nickname":          u.Nickname,
		"email":             u.Email,
		"status":            u.Status,
		"traffic_used":      u.TrafficUsed,
		"traffic_quota":     quota,
		"traffic_reset_at":  u.TrafficResetAt,
		"traffic_exceeded":  h.svc.QuotaExceeded(u),
		"balance":           u.Balance,
		"group_expire_at":   u.GroupExpireAt,
		"api_key_prefix":    u.APIKeyPrefix,
		"api_key_created_at": u.APIKeyCreatedAt,
		"created_at":        u.CreatedAt,
		"last_login_at":     u.LastLoginAt,
	}
	if g != nil {
		vo["group"] = gin.H{
			"id":                  g.ID,
			"name":                g.Name,
			"max_tunnels":         g.MaxTunnels,
			"max_ports":           g.MaxPorts,
			"traffic_quota":       g.TrafficQuota,
			"bandwidth_limit":     g.BandwidthLimit,
			// 给用户看的文案用 Human 版本（Mbps 口径），
			// 与后台分组表单填写的数字保持一致。
			"bandwidth_limit_str": service.FormatBandwidthHuman(g.BandwidthLimit),
			"allow_protocols":     g.AllowProtocols,
			"allow_custom_domain": g.AllowCustomDomain,
		}
	}
	return vo
}

// ---- 找回密码 ----

type forgotPasswordReq struct {
	// Account 可以是用户名或邮箱
	Account string `json:"account" binding:"required"`
}

// ForgotPassword 发起找回密码。
//
// 无论账号是否存在，一律返回同样的提示：该接口若区分「不存在」与「已发送」，
// 就会变成账号枚举工具。找回密码页面的响应时间也做了对齐（发信走异步队列）。
func (h *Handler) ForgotPassword(c *gin.Context) {
	var req forgotPasswordReq
	if err := c.ShouldBindJSON(&req); err != nil {
		httpx.BadRequest(c, "请输入用户名或邮箱")
		return
	}

	baseURL := h.svc.Cfg.UserPublicURL
	if baseURL == "" {
		// 未配置对外地址时用请求来源推断，保证链接在部署后仍然可用。
		scheme := "https"
		if c.Request.TLS == nil && c.GetHeader("X-Forwarded-Proto") == "" {
			scheme = "http"
		}
		if proto := c.GetHeader("X-Forwarded-Proto"); proto != "" {
			scheme = proto
		}
		baseURL = scheme + "://" + c.Request.Host
	}

	if err := h.svc.RequestPasswordReset(req.Account, httpx.ClientIP(c), baseURL); err != nil {
		shared.Fail(c, err)
		return
	}
	httpx.OK(c, gin.H{
		"message": "如果该账号存在且已绑定邮箱，我们已发送重置链接，请查收（30 分钟内有效）",
	})
}

type resetPasswordReq struct {
	// Token 是邮件链接里的令牌（网页端「点链接」流程）
	Token string `json:"token"`
	// Account 是用户名或邮箱，验证码模式与旧密码模式都需要
	Account  string `json:"account"`
	Password string `json:"password" binding:"required"`
	// OldPassword 在「站点未启用邮件」时用于证明身份
	OldPassword string `json:"old_password"`
	// EmailCode 在「站点已启用邮件」时用于验证身份
	EmailCode string `json:"email_code"`
}

// ResetPassword 重置密码。三种入口，按站点配置与请求内容自动选择：
//
//  1. 邮件链接令牌（网页端点链接的既有流程）
//  2. 旧密码 + 新密码 —— 站点**未启用**邮件时使用
//  3. 邮箱一次性验证码 + 新密码 —— 站点**已启用**邮件时使用
//
// 这样在无法发信的部署环境下用户依然能自助重置，而不是只能找管理员；
// 而一旦有了邮件通道，就自动升级为更安全的验证码流程。
func (h *Handler) ResetPassword(c *gin.Context) {
	var req resetPasswordReq
	if err := c.ShouldBindJSON(&req); err != nil {
		httpx.BadRequest(c, "参数不完整")
		return
	}
	ip := httpx.ClientIP(c)
	const okMsg = "密码已重置，所有设备已下线，请用新密码登录"

	// 入口 1：邮件链接令牌
	if strings.TrimSpace(req.Token) != "" {
		if err := h.svc.ResetPassword(req.Token, req.Password, ip); err != nil {
			shared.Fail(c, err)
			return
		}
		httpx.OK(c, gin.H{"message": okMsg})
		return
	}

	account := strings.ToLower(strings.TrimSpace(req.Account))
	if account == "" {
		httpx.BadRequest(c, "请填写账号或邮箱")
		return
	}

	// 入口 2：旧密码模式（站点未启用邮件）
	if !h.svc.MailEnabled() {
		// 复用登录的账号锁定维度。不这么做的话，本接口会立刻变成
		// 绕过登录锁定的旁路：被锁住的攻击者改打这里继续撞库。
		if !shared.CheckLoginLock(c, h.guard, shared.LoginLockScopeUser, account, ip) {
			return
		}
		err := h.svc.ResetPasswordByOldPassword(req.Account, req.OldPassword, req.Password, ip)
		if err != nil {
			// 只有「凭据错误」才计入锁定次数；密码强度不合格之类不该算失败。
			if errors.Is(err, service.ErrBadCredentials) {
				shared.LoginFailed(h.guard, shared.LoginLockScopeUser, account, ip)
			}
			shared.Fail(c, err)
			return
		}
		shared.LoginSucceeded(h.guard, shared.LoginLockScopeUser, account, ip)
		httpx.OK(c, gin.H{"message": okMsg})
		return
	}

	// 入口 3：邮箱验证码模式（站点已启用邮件）
	if err := h.svc.ResetPasswordByEmailCode(req.Account, req.EmailCode, req.Password, ip); err != nil {
		shared.Fail(c, err)
		return
	}
	httpx.OK(c, gin.H{"message": okMsg})
}

type sendEmailCodeReq struct {
	Email string `json:"email" binding:"required"`
	// Scene 决定用途：register（注册验证）| reset（找回密码）
	Scene string `json:"scene" binding:"required"`
}

// SendEmailCode 发送邮箱一次性验证码。
//
// 两种 scene 对「邮箱是否已注册」的处理刻意不同：
// 注册场景会明确告知邮箱已被占用（否则用户无法继续），
// 找回场景则一律返回成功，避免接口退化成账号枚举工具。
func (h *Handler) SendEmailCode(c *gin.Context) {
	var req sendEmailCodeReq
	if err := c.ShouldBindJSON(&req); err != nil {
		httpx.BadRequest(c, "请填写邮箱")
		return
	}
	if err := h.svc.SendEmailCode(req.Email, req.Scene, httpx.ClientIP(c)); err != nil {
		shared.Fail(c, err)
		return
	}
	httpx.OK(c, gin.H{
		"message":   "验证码已发送，请查收（10 分钟内有效）",
		"expire_in": 600,
	})
}

// ResetMailStatus 返回站点是否已启用邮件找回功能，供前端决定是否显示入口。
func (h *Handler) ResetMailStatus(c *gin.Context) {
	httpx.OK(c, gin.H{"mail_enabled": h.svc.MailEnabled()})
}

// ---- 桌面客户端接入 ----

type clientAuthReq struct {
	Username string `json:"username" binding:"required"`
	Password string `json:"password" binding:"required"`
}

// ClientAuth 供桌面客户端首次登录使用，直接返回可用的接入信息与完整配置。
//
// 这是与网页登录等价的密码校验入口，必须套用同样的账号锁定策略，
// 否则攻击者可以绕过网页端的锁定直接从客户端接口爆破。
func (h *Handler) ClientAuth(c *gin.Context) {
	var req clientAuthReq
	if err := c.ShouldBindJSON(&req); err != nil {
		httpx.BadRequest(c, "请填写用户名与密码")
		return
	}

	account := strings.ToLower(strings.TrimSpace(req.Username))
	attempt := service.LoginAttempt{
		Kind:     model.LoginKindUser,
		Username: req.Username,
		Source:   model.LoginSourceClient,
	}

	ip := httpx.ClientIP(c)
	if !shared.CheckLoginLock(c, h.guard, shared.LoginLockScopeUser, account, ip) {
		attempt.Result = model.LoginResultLocked
		attempt.Detail = "账号在当前网络下处于登录锁定期"
		h.recordLogin(c, attempt)
		return
	}

	u, err := h.svc.Authenticate(req.Username, req.Password, ip)
	if err != nil {
		shared.LoginFailed(h.guard, shared.LoginLockScopeUser, account, ip)
		attempt.Result = shared.LoginResultOf(err)
		attempt.Detail = err.Error()
		h.recordLogin(c, attempt)
		shared.Fail(c, err)
		return
	}
	shared.LoginSucceeded(h.guard, shared.LoginLockScopeUser, account, ip)
	attempt.AccountID = u.ID
	attempt.Username = u.Username
	attempt.Result = model.LoginResultSuccess
	h.recordLogin(c, attempt)
	tunnels, err := h.svc.ListTunnels(u.ID)
	if err != nil {
		shared.Fail(c, err)
		return
	}
	info, err := h.svc.BuildClientInfo(u)
	if err != nil {
		shared.Fail(c, err)
		return
	}
	cfgText, err := h.svc.BuildFrpcConfig(u, tunnels)
	if err != nil {
		shared.Fail(c, err)
		return
	}
	httpx.OK(c, gin.H{"client": info, "config": cfgText})
}

// clientInfoResp 是客户端接入信息与隧道清单的组合。
//
// 字段直接内嵌 ClientInfo，保证既有前端读取 server_addr 等字段不受影响。
type clientInfoResp struct {
	*service.ClientInfo
	// 客户端只持有 API Key，因此账号信息必须由服务端下发，
	// 不能像以前那样依赖用户在登录框里填的用户名。
	Username     string   `json:"username"`
	Nickname     string   `json:"nickname"`
	Tunnels      []gin.H `json:"tunnels"`
	TrafficUsed  int64    `json:"traffic_used"`
	TrafficQuota int64    `json:"traffic_quota"`
	Exceeded     bool     `json:"exceeded"`

	// Group 是分组限制。客户端要能自己建隧道，就必须知道
	// 「允许哪些协议」「最多几条隧道」——否则表单会放行注定被拒的提交，
	// 用户填完才收到「协议不允许」的报错。
	Group *gin.H `json:"group,omitempty"`
	// Balance 仅在站点启用支付时下发，避免客户端显示一个无法使用的余额。
	BalanceCents   int64 `json:"balance_cents"`
	PaymentEnabled bool  `json:"payment_enabled"`
}

// ClientInfo 返回接入信息与当前隧道清单（需已认证）。
func (h *Handler) ClientInfo(c *gin.Context) {
	u, err := h.svc.LoadUser(middleware.CurrentUserID(c))
	if err != nil {
		shared.Fail(c, err)
		return
	}
	info, err := h.svc.BuildClientInfo(u)
	if err != nil {
		shared.Fail(c, err)
		return
	}
	tunnels, err := h.svc.ListTunnels(u.ID)
	if err != nil {
		shared.Fail(c, err)
		return
	}
	out := make([]gin.H, 0, len(tunnels))
	for i := range tunnels {
		out = append(out, h.tunnelVO(&tunnels[i]))
	}
	// 分组信息：客户端据此限制建隧道表单的可选项
	var groupVO *gin.H
	if g := h.svc.EffectiveGroup(u); g != nil {
		groupVO = &gin.H{
			"id":                  g.ID,
			"name":                g.Name,
			"max_tunnels":         g.MaxTunnels,
			"max_ports":           g.MaxPorts,
			"bandwidth_limit_str": service.FormatBandwidthHuman(g.BandwidthLimit),
			"allow_protocols":     g.AllowProtocols,
			"allow_custom_domain": g.AllowCustomDomain,
		}
	}

	httpx.OK(c, clientInfoResp{
		ClientInfo:     info,
		Username:       u.Username,
		Nickname:       u.Nickname,
		Tunnels:        out,
		TrafficUsed:    u.TrafficUsed,
		TrafficQuota:   h.svc.EffectiveQuota(u),
		Exceeded:       h.svc.QuotaExceeded(u),
		Group:          groupVO,
		BalanceCents:   u.Balance,
		PaymentEnabled: h.svc.Settings.Bool(service.KeyPaymentEnabled),
	})
}

// ClientConfig 下载当前账号的 frpc.toml。
func (h *Handler) ClientConfig(c *gin.Context) {
	u, err := h.svc.LoadUser(middleware.CurrentUserID(c))
	if err != nil {
		shared.Fail(c, err)
		return
	}
	tunnels, err := h.svc.ListTunnels(u.ID)
	if err != nil {
		shared.Fail(c, err)
		return
	}
	text, err := h.svc.BuildFrpcConfig(u, tunnels)
	if err != nil {
		shared.Fail(c, err)
		return
	}
	if c.Query("download") == "1" {
		c.Header("Content-Disposition", `attachment; filename="frpc.toml"`)
	}
	c.Data(http.StatusOK, "text/plain; charset=utf-8", []byte(text))
}

// ClientDownload 客户端安装包信息。
type ClientDownload struct {
	Name    string `json:"name"`
	Size    int64  `json:"size"`
	Updated string `json:"updated_at"`
}

// ClientDownloads 列出可下载的客户端安装包。
//
// 只读取固定目录下的一级文件，且拒绝任何路径穿越，
// 目录不存在时返回空列表而不是报错。
func (h *Handler) ClientDownloads(c *gin.Context) {
	// 配置了外部下载地址（通常是 GitHub Releases）时只返回该地址，
	// 不列本地目录：两套来源同时出现会让用户不知道该点哪个，
	// 而且外部地址往往版本更新，本地那份可能是旧的。
	if url := strings.TrimSpace(h.svc.Settings.Get(service.KeySiteClientDownloadURL)); url != "" {
		httpx.OK(c, gin.H{"download_url": url, "files": []ClientDownload{}})
		return
	}

	dir := h.svc.Cfg.ClientDistDir
	entries, err := os.ReadDir(dir)
	if err != nil {
		httpx.OK(c, gin.H{"download_url": "", "files": []ClientDownload{}})
		return
	}
	list := make([]ClientDownload, 0, len(entries))
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		name := e.Name()
		if name != filepath.Base(name) {
			continue
		}
		info, err := e.Info()
		if err != nil {
			continue
		}
		list = append(list, ClientDownload{
			Name:    name,
			Size:    info.Size(),
			Updated: info.ModTime().Format(time.RFC3339),
		})
	}
	sort.Slice(list, func(i, j int) bool { return list[i].Name < list[j].Name })
	httpx.OK(c, gin.H{"download_url": "", "files": list})
}

// ClientDownloadFile 下载指定的客户端安装包。
func (h *Handler) ClientDownloadFile(c *gin.Context) {
	name := c.Param("name")
	// 双重防线：文件名必须等于其 base，且不允许出现路径分隔符。
	if name == "" || name != filepath.Base(name) || name == "." || name == ".." {
		httpx.BadRequest(c, "文件名非法")
		return
	}
	full := filepath.Join(h.svc.Cfg.ClientDistDir, name)
	c.FileAttachment(full, name)
}

// ---- 隧道管理 ----

// ListTunnels 列出当前用户隧道，并附加运行态。
func (h *Handler) ListTunnels(c *gin.Context) {
	uid := middleware.CurrentUserID(c)
	list, err := h.svc.ListTunnels(uid)
	if err != nil {
		shared.Fail(c, err)
		return
	}
	out := make([]gin.H, 0, len(list))
	for i := range list {
		out = append(out, h.tunnelVO(&list[i]))
	}
	httpx.OK(c, out)
}

func (h *Handler) tunnelVO(t *model.Tunnel) gin.H {
	return gin.H{
		"id":                   t.ID,
		"name":                 t.Name,
		"type":                 t.Type,
		"local_ip":             t.LocalIP,
		"local_port":           t.LocalPort,
		"remote_port":          t.RemotePort,
		"domain":               t.Domain,
		"subdomain":            t.Subdomain,
		"remark":               t.Remark,
		"status":               t.Status,
		"online":               h.svc.Runtime.IsTunnelOnline(t.ID),
		"traffic_used":         t.TrafficUsed,
		"bandwidth_limit":      t.BandwidthLimit,
		"bandwidth_limit_str":  service.FormatBandwidthHuman(t.BandwidthLimit),
		"use_encryption":       t.UseEncryption,
		"use_compression":      t.UseCompression,
		"last_online_at":       t.LastOnlineAt,
		"created_at":           t.CreatedAt,
		"public_addr":          h.publicAddr(t),
	}
}

// publicAddr 给出该隧道对外的访问地址，方便用户直接复制。
func (h *Handler) publicAddr(t *model.Tunnel) string {
	host := h.svc.Cfg.GatewayHost
	switch t.Type {
	case model.ProxyTypeTCP, model.ProxyTypeUDP:
		if t.RemotePort == 0 {
			return ""
		}
		return host + ":" + strconv.Itoa(t.RemotePort)
	case model.ProxyTypeHTTP, model.ProxyTypeHTTPS:
		if t.Domain != "" {
			return t.Domain
		}
		if t.Subdomain != "" && h.svc.Cfg.TunnelDomain != "" {
			return t.Subdomain + "." + h.svc.Cfg.TunnelDomain
		}
	}
	return ""
}

// CreateTunnel 新建隧道。
func (h *Handler) CreateTunnel(c *gin.Context) {
	var in service.TunnelInput
	if err := c.ShouldBindJSON(&in); err != nil {
		httpx.BadRequest(c, "参数格式不正确")
		return
	}
	u, err := h.svc.LoadUser(middleware.CurrentUserID(c))
	if err != nil {
		shared.Fail(c, err)
		return
	}
	t, err := h.svc.CreateTunnel(u, in)
	if err != nil {
		shared.Fail(c, err)
		return
	}
	httpx.OK(c, h.tunnelVO(t))
}

// UpdateTunnel 修改隧道。
func (h *Handler) UpdateTunnel(c *gin.Context) {
	id, err := parseID(c)
	if err != nil {
		httpx.BadRequest(c, "隧道 ID 非法")
		return
	}
	var in service.TunnelInput
	if err := c.ShouldBindJSON(&in); err != nil {
		httpx.BadRequest(c, "参数格式不正确")
		return
	}
	u, err := h.svc.LoadUser(middleware.CurrentUserID(c))
	if err != nil {
		shared.Fail(c, err)
		return
	}
	t, err := h.svc.UpdateTunnel(u, id, in)
	if err != nil {
		shared.Fail(c, err)
		return
	}
	httpx.OK(c, h.tunnelVO(t))
}

// DeleteTunnel 删除隧道。
func (h *Handler) DeleteTunnel(c *gin.Context) {
	id, err := parseID(c)
	if err != nil {
		httpx.BadRequest(c, "隧道 ID 非法")
		return
	}
	if err := h.svc.DeleteTunnel(middleware.CurrentUserID(c), id); err != nil {
		shared.Fail(c, err)
		return
	}
	httpx.OK(c, gin.H{"message": "隧道已删除"})
}

type tunnelStatusReq struct {
	Status string `json:"status" binding:"required"`
}

// SetTunnelStatus 启用或停用隧道。
func (h *Handler) SetTunnelStatus(c *gin.Context) {
	id, err := parseID(c)
	if err != nil {
		httpx.BadRequest(c, "隧道 ID 非法")
		return
	}
	var req tunnelStatusReq
	if err := c.ShouldBindJSON(&req); err != nil {
		httpx.BadRequest(c, "参数格式不正确")
		return
	}
	if err := h.svc.SetTunnelStatus(middleware.CurrentUserID(c), id, req.Status); err != nil {
		shared.Fail(c, err)
		return
	}
	httpx.OK(c, gin.H{"message": "状态已更新"})
}

// ---- API Key ----

// GetAPIKey 返回 API Key 的元信息（不含明文）。
func (h *Handler) GetAPIKey(c *gin.Context) {
	u, err := h.svc.LoadUser(middleware.CurrentUserID(c))
	if err != nil {
		shared.Fail(c, err)
		return
	}
	httpx.OK(c, gin.H{
		"prefix":     u.APIKeyPrefix,
		"created_at": u.APIKeyCreatedAt,
		"exists":     u.APIKeyHash != "",
	})
}

// RevealAPIKey 解密回显 API Key 明文，供用户复制到客户端。
func (h *Handler) RevealAPIKey(c *gin.Context) {
	u, err := h.svc.LoadUser(middleware.CurrentUserID(c))
	if err != nil {
		shared.Fail(c, err)
		return
	}
	plain, err := h.svc.RevealAPIKey(u)
	if err != nil {
		httpx.BadRequest(c, "尚未生成 API Key，请先重置生成")
		return
	}
	httpx.OK(c, gin.H{"api_key": plain})
}

// RotateAPIKey 重置 API Key，旧 Key 立即失效。
func (h *Handler) RotateAPIKey(c *gin.Context) {
	uid := middleware.CurrentUserID(c)
	plain, prefix, err := h.svc.RotateAPIKey(uid)
	if err != nil {
		shared.Fail(c, err)
		return
	}
	httpx.OK(c, gin.H{
		"api_key": plain,
		"prefix":  prefix,
		"message": "API Key 已重置，请妥善保存，旧 Key 已失效",
	})
}

// ---- 兑换 ----

type redeemReq struct {
	Code string `json:"code" binding:"required"`
}

// Redeem 兑换码核销。
func (h *Handler) Redeem(c *gin.Context) {
	var req redeemReq
	if err := c.ShouldBindJSON(&req); err != nil {
		httpx.BadRequest(c, "请输入兑换码")
		return
	}
	res, err := h.svc.Redeem(middleware.CurrentUserID(c), req.Code, httpx.ClientIP(c))
	if err != nil {
		shared.Fail(c, err)
		return
	}
	httpx.OK(c, res)
}

// RedeemRecords 我的兑换记录。
func (h *Handler) RedeemRecords(c *gin.Context) {
	page, pageSize, offset := httpx.Pagination(c)
	list, total, err := h.svc.ListRedeemRecords(middleware.CurrentUserID(c), offset, pageSize)
	if err != nil {
		shared.Fail(c, err)
		return
	}
	httpx.PageOK(c, list, total, page, pageSize)
}

// ---- 概览与统计 ----

// StatsOverview 控制台首页概览。
func (h *Handler) StatsOverview(c *gin.Context) {
	uid := middleware.CurrentUserID(c)
	u, err := h.svc.LoadUser(uid)
	if err != nil {
		shared.Fail(c, err)
		return
	}
	tunnels, err := h.svc.ListTunnels(uid)
	if err != nil {
		shared.Fail(c, err)
		return
	}
	online := 0
	for i := range tunnels {
		if h.svc.Runtime.IsTunnelOnline(tunnels[i].ID) {
			online++
		}
	}
	httpx.OK(c, gin.H{
		"traffic_used":     u.TrafficUsed,
		"traffic_quota":    h.svc.EffectiveQuota(u),
		"traffic_exceeded": h.svc.QuotaExceeded(u),
		"balance":          u.Balance,
		"tunnel_total":     len(tunnels),
		"tunnel_online":    online,
		"group_name":       groupName(h.svc.EffectiveGroup(u)),
	})
}

func groupName(g *model.Group) string {
	if g == nil {
		return "未分组"
	}
	return g.Name
}

// TrafficStats 近 N 天流量曲线。
func (h *Handler) TrafficStats(c *gin.Context) {
	uid := middleware.CurrentUserID(c)
	days := 7
	if v, err := strconv.Atoi(c.DefaultQuery("days", "7")); err == nil && v > 0 && v <= 90 {
		days = v
	}
	type row struct {
		Date     string `json:"date"`
		InBytes  int64  `json:"in_bytes"`
		OutBytes int64  `json:"out_bytes"`
	}
	var rows []row
	err := h.svc.DB.Model(&model.TrafficDaily{}).
		Select("date, SUM(in_bytes) AS in_bytes, SUM(out_bytes) AS out_bytes").
		Where("user_id = ? AND date >= ?", uid, time.Now().AddDate(0, 0, -days+1).Format("2006-01-02")).
		Group("date").Order("date asc").Scan(&rows).Error
	if err != nil {
		shared.Fail(c, err)
		return
	}
	httpx.OK(c, rows)
}

func parseID(c *gin.Context) (uint, error) {
	v, err := strconv.ParseUint(c.Param("id"), 10, 64)
	if err != nil || v == 0 {
		return 0, errors.New("非法 ID")
	}
	return uint(v), nil
}
