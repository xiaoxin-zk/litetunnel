package authapi

import (
	"errors"
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"

	"github.com/xiaoxin-zk/litetunnel/server/internal/auth"
	"github.com/xiaoxin-zk/litetunnel/server/internal/handler/shared"
	"github.com/xiaoxin-zk/litetunnel/server/internal/httpx"
	"github.com/xiaoxin-zk/litetunnel/server/internal/model"
	"github.com/xiaoxin-zk/litetunnel/server/internal/service"
)

type Handler struct {
	svc       *service.Services
	adminPath string
}

func New(svc *service.Services, adminPath string) *Handler {
	return &Handler{svc: svc, adminPath: adminPath}
}

func (h *Handler) record(c *gin.Context, kind, username, result, detail string) {
	h.svc.RecordLogin(service.LoginAttempt{
		Kind:      kind,
		Username:  username,
		IP:        httpx.ClientIP(c),
		UserAgent: c.GetHeader("User-Agent"),
		Source:    model.LoginSourceWeb,
		Result:    result,
		Detail:    detail,
	})
}

type loginReq struct {
	Username      string `json:"username" binding:"required"`
	Password      string `json:"password" binding:"required"`
	TOTPCode      string `json:"totp_code"`
	CaptchaTicket string `json:"captcha_ticket"`
	CaptchaAnswer string `json:"captcha_answer"`
}

func (h *Handler) Login(c *gin.Context) {
	var req loginReq
	if err := c.ShouldBindJSON(&req); err != nil {
		httpx.BadRequest(c, "请填写账号与密码")
		return
	}

	account := strings.ToLower(strings.TrimSpace(req.Username))
	ip := httpx.ClientIP(c)

	if !shared.CheckLoginLock(c, h.svc.LoginGuard, shared.LoginLockScopeUnified, account, ip) {
		h.record(c, model.LoginKindUser, account, model.LoginResultLocked,
			"账号在当前网络下处于登录锁定期")
		return
	}

	switch shared.CheckLoginCaptcha(c, h.svc, account, req.CaptchaTicket, req.CaptchaAnswer, "") {
	case shared.CaptchaGatePass:
	case shared.CaptchaGateWrong:
		shared.LoginFailed(h.svc.LoginGuard, shared.LoginLockScopeUnified, account, ip)
		h.record(c, model.LoginKindUser, account, model.LoginResultBadCred, "验证码不正确")
		return
	default:
		return
	}

	if u, err := h.svc.Authenticate(req.Username, req.Password, ip); err == nil {
		token, expireAt, err := auth.Issue(
			h.svc.Cfg.UserJWTSecret, auth.DomainUser,
			u.ID, u.Username, "", u.TokenVersion, h.svc.Cfg.UserJWTExpire,
		)
		if err != nil {
			shared.Fail(c, err)
			return
		}
		shared.LoginSucceeded(h.svc.LoginGuard, shared.LoginLockScopeUnified, account, ip)
		h.record(c, model.LoginKindUser, u.Username, model.LoginResultSuccess, "")
		httpx.OK(c, gin.H{
			"role":      "user",
			"token":     token,
			"expire_at": expireAt,
			"redirect":  "/",
			"username":  u.Username,
			"nickname":  u.Nickname,
		})
		return
	} else if errors.Is(err, service.ErrAccountDisabled) {
		shared.LoginFailed(h.svc.LoginGuard, shared.LoginLockScopeUnified, account, ip)
		h.record(c, model.LoginKindUser, account, model.LoginResultDisabled, err.Error())
		httpx.Forbidden(c, "账号已被禁用，请联系管理员")
		return
	}

	a, err := h.svc.AdminAuthenticate(req.Username, req.Password, req.TOTPCode, ip)
	if err == nil {
		token, expireAt, err := auth.Issue(
			h.svc.Cfg.AdminJWTSecret, auth.DomainAdmin,
			a.ID, a.Username, a.Role, a.TokenVersion, h.svc.Cfg.AdminJWTExpire,
		)
		if err != nil {
			shared.Fail(c, err)
			return
		}
		shared.LoginSucceeded(h.svc.LoginGuard, shared.LoginLockScopeUnified, account, ip)
		h.record(c, model.LoginKindAdmin, a.Username, model.LoginResultSuccess, "")
		httpx.OK(c, gin.H{
			"role":         "admin",
			"token":        token,
			"expire_at":    expireAt,
			"redirect":     h.adminPath + "/",
			"username":     a.Username,
			"nickname":     a.Nickname,
			"role_name":    a.Role,
			"totp_enabled": a.TOTPEnabled,
		})
		return
	}

	if errors.Is(err, service.ErrTOTPRequired) {
		c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{
			"code":    http.StatusUnauthorized,
			"message": err.Error(),
			"data":    gin.H{"totp_required": true},
		})
		return
	}
	if errors.Is(err, service.ErrAccountDisabled) {
		shared.LoginFailed(h.svc.LoginGuard, shared.LoginLockScopeUnified, account, ip)
		h.record(c, model.LoginKindAdmin, account, model.LoginResultDisabled, err.Error())
		httpx.Forbidden(c, "账号已被禁用，请联系管理员")
		return
	}

	shared.LoginFailed(h.svc.LoginGuard, shared.LoginLockScopeUnified, account, ip)
	h.record(c, model.LoginKindUser, account, model.LoginResultBadCred, "账号或密码不正确")
	httpx.Unauthorized(c, "账号或密码不正确")
}

func (h *Handler) PublicSettings(c *gin.Context) {
	s := h.svc.Settings
	httpx.OK(c, gin.H{
		"site_name":              s.Get(service.KeySiteName),
		"site_subtitle":          s.Get(service.KeySiteSubtitle),
		"site_logo":              s.Get(service.KeySiteLogo),
		"frontend_url":           h.svc.FrontendURL(),
		"home_content":           s.Get(service.KeySiteHomeContent),
		"announcement":           s.Get(service.KeySiteAnnouncement),
		"icp":                    s.Get(service.KeySiteICP),
		"register_enabled":       s.Bool(service.KeyRegisterEnabled),
		"register_need_invite":   s.Bool(service.KeyRegisterNeedInvite),
		"register_require_email": s.Bool(service.KeyRegisterRequireEmail),
		"register_captcha":       s.Bool(service.KeyRegisterCaptcha),
		"terms":                  s.Get(service.KeyRegisterTerms),
		"mail_enabled":           h.svc.MailEnabled(),
		"oauth_github":           h.svc.OAuthAvailable(service.OAuthProviderGitHub),
		"oauth_google":           h.svc.OAuthAvailable(service.OAuthProviderGoogle),
		"payment_enabled":        s.Bool(service.KeyPaymentEnabled),
		"payment_min":            s.Int(service.KeyPaymentMinAmount),
		"payment_max":            s.Int(service.KeyPaymentMaxAmount),
	})
}

func (h *Handler) Captcha(c *gin.Context) {
	ch, err := h.svc.NewCaptcha(httpx.ClientIP(c))
	if err != nil {
		shared.Fail(c, err)
		return
	}
	httpx.OK(c, ch)
}

type captchaVerifyReq struct {
	Ticket string `json:"ticket" binding:"required"`
	Answer string `json:"answer" binding:"required"`
}

func (h *Handler) VerifyCaptcha(c *gin.Context) {
	var req captchaVerifyReq
	if err := c.ShouldBindJSON(&req); err != nil {
		httpx.BadRequest(c, "参数不完整")
		return
	}
	if !h.svc.CheckCaptcha(req.Ticket, req.Answer) {
		httpx.Fail(c, http.StatusBadRequest, "验证码不正确或已过期")
		return
	}
	httpx.OK(c, gin.H{"ok": true})
}
