package userapi

import (
	"errors"
	"log"
	"strings"

	"github.com/gin-gonic/gin"

	"github.com/xiaoxin-zk/litetunnel/server/internal/handler/shared"
	"github.com/xiaoxin-zk/litetunnel/server/internal/httpx"
	"github.com/xiaoxin-zk/litetunnel/server/internal/service"
)

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

	// 链接只能由**服务端配置**的对外地址生成，绝不从请求里推断。
	//
	// 这里曾经在未配置 LT_USER_PUBLIC_URL 时用 Host 与 X-Forwarded-Proto 拼
	// 地址——而这两个头完全由请求方控制：攻击者往本接口提交伪造的 Host，
	// 服务端就会把「指向攻击者域名」的重置链接发到用户邮箱里，用户一点，
	// 链接里的重置令牌就交到了攻击者手上（Host 头投毒）。
	//
	// 未配置时不发信、但对外仍返回统一提示：一来不暴露「服务端配置有误」，
	// 二来本接口不能因为内部状态而变得可区分（否则又会退化成账号枚举工具）。
	// 配置问题通过启动期提示与这里的日志暴露给管理员。
	// 用设置里的面板域名（数据库优先）：管理员在「域名与证书」里改完域名后，
	// Caddy 已按新域名重建，而面板进程仍持有启动时的环境变量。
	baseURL := h.svc.UserPublicURL()
	if baseURL == "" {
		log.Printf("[reset] 未配置 LT_USER_PUBLIC_URL，无法生成重置链接，本次不发信")
		httpx.OK(c, gin.H{
			"message": "如果该账号存在且已绑定邮箱，我们已发送重置链接，请查收（30 分钟内有效）",
		})
		return
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
