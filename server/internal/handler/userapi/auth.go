package userapi

import (
	"errors"
	"strings"

	"github.com/gin-gonic/gin"

	"github.com/xiaoxin-zk/litetunnel/server/internal/handler/shared"
	"github.com/xiaoxin-zk/litetunnel/server/internal/httpx"
	"github.com/xiaoxin-zk/litetunnel/server/internal/model"
	"github.com/xiaoxin-zk/litetunnel/server/internal/service"
)

type registerReq struct {
	Username string `json:"username" binding:"required"`
	Password string `json:"password" binding:"required"`
	Email    string `json:"email"`

	Agreed        bool   `json:"agreed"`
	CaptchaTicket string `json:"captcha_ticket"`
	CaptchaAnswer string `json:"captcha_answer"`
	EmailCode     string `json:"email_code"`
}

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
	Account string `json:"account" binding:"required"`
}

func (h *Handler) ForgotPassword(c *gin.Context) {
	var req forgotPasswordReq
	if err := c.ShouldBindJSON(&req); err != nil {
		httpx.BadRequest(c, "请输入用户名或邮箱")
		return
	}

	baseURL := h.svc.UserPublicURL()

	if err := h.svc.RequestPasswordReset(req.Account, httpx.ClientIP(c), baseURL); err != nil {
		shared.Fail(c, err)
		return
	}
	httpx.OK(c, gin.H{
		"message": "找回请求已受理；若账号符合条件，将发送重置链接。若长时间未收到，请稍后重新申请",
	})
}

type resetPasswordReq struct {
	Token         string `json:"token"`
	Account       string `json:"account"`
	Password      string `json:"password" binding:"required"`
	OldPassword   string `json:"old_password"`
	EmailCode     string `json:"email_code"`
	CaptchaTicket string `json:"captcha_ticket"`
	CaptchaAnswer string `json:"captcha_answer"`
}

const resetCaptchaMessage = "该账号近期失败次数较多，为防止爆破已要求人机验证。" +
	"请等待约 30 分钟后重试；若急需使用，请联系管理员重置密码"

func (h *Handler) ResetPassword(c *gin.Context) {
	var req resetPasswordReq
	if err := c.ShouldBindJSON(&req); err != nil {
		httpx.BadRequest(c, "参数不完整")
		return
	}
	ip := httpx.ClientIP(c)
	const okMsg = "密码已重置，所有设备已下线，请用新密码登录"

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

	if !h.svc.MailEnabled() {
		attempt := service.LoginAttempt{
			Kind:     model.LoginKindUser,
			Username: account,
			Source:   model.LoginSourceWeb,
			Detail:   "通过旧密码重置密码",
		}
		if !shared.CheckLoginLock(c, h.svc.LoginGuard, shared.LoginLockScopeUnified, account, ip) {
			attempt.Result = model.LoginResultLocked
			attempt.Detail = "账号在当前网络下处于登录锁定期"
			h.recordLogin(c, attempt)
			return
		}
		switch shared.CheckLoginCaptcha(c, h.svc, account, req.CaptchaTicket, req.CaptchaAnswer, resetCaptchaMessage) {
		case shared.CaptchaGatePass:
		case shared.CaptchaGateWrong:
			shared.LoginFailed(h.svc.LoginGuard, shared.LoginLockScopeUnified, account, ip)
			attempt.Result = model.LoginResultBadCred
			attempt.Detail = "验证码不正确"
			h.recordLogin(c, attempt)
			return
		default:
			attempt.Result = model.LoginResultLocked
			attempt.Detail = "账号累计失败次数较多，要求人机验证"
			h.recordLogin(c, attempt)
			return
		}

		err := h.svc.ResetPasswordByOldPassword(req.Account, req.OldPassword, req.Password, ip)
		if err != nil {
			if errors.Is(err, service.ErrBadCredentials) {
				shared.LoginFailed(h.svc.LoginGuard, shared.LoginLockScopeUnified, account, ip)
				attempt.Result = model.LoginResultBadCred
				attempt.Detail = err.Error()
				h.recordLogin(c, attempt)
			}
			shared.Fail(c, err)
			return
		}
		shared.LoginSucceeded(h.svc.LoginGuard, shared.LoginLockScopeUnified, account, ip)
		attempt.Result = model.LoginResultSuccess
		h.recordLogin(c, attempt)
		httpx.OK(c, gin.H{"message": okMsg})
		return
	}

	if err := h.svc.ResetPasswordByEmailCode(req.Account, req.EmailCode, req.Password, ip); err != nil {
		shared.Fail(c, err)
		return
	}
	httpx.OK(c, gin.H{"message": okMsg})
}

type sendEmailCodeReq struct {
	Email string `json:"email" binding:"required"`
	Scene string `json:"scene" binding:"required"`
}

func (h *Handler) SendEmailCode(c *gin.Context) {
	var req sendEmailCodeReq
	if err := c.ShouldBindJSON(&req); err != nil {
		httpx.BadRequest(c, "请填写邮箱")
		return
	}
	if req.Scene != service.EmailSceneRegister && req.Scene != service.EmailSceneReset {
		httpx.BadRequest(c, "参数格式不正确")
		return
	}
	if err := h.svc.SendEmailCode(req.Email, req.Scene, httpx.ClientIP(c)); err != nil {
		shared.Fail(c, err)
		return
	}
	message := "验证码已发送，请查收（10 分钟内有效）"
	if req.Scene == service.EmailSceneReset {
		message = "找回请求已受理；若邮箱符合条件，将发送验证码。若长时间未收到，请稍后重新申请"
	}
	httpx.OK(c, gin.H{
		"message":   message,
		"expire_in": 600,
	})
}

func (h *Handler) ResetMailStatus(c *gin.Context) {
	httpx.OK(c, gin.H{"mail_enabled": h.svc.MailEnabled()})
}
