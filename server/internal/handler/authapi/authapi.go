// Package authapi 提供与账号类型无关的公共认证接口。
//
// 用户控制台与管理后台共用同一个登录入口：前端只提交一次账号密码，
// 后端按「先用户、后管理员」的顺序校验，返回角色与跳转目标。
// 用户不必先想清楚自己该进哪个页面——这也是合并入口的意义。
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

// Handler 公共认证处理器。
type Handler struct {
	svc *service.Services
	// adminPath 是管理员登录成功后的跳转目标，由路由层注入。
	adminPath string
}

// New 构造处理器。
//
// 登录锁不在这里自建：它来自 Services，全站唯一一份。每个入口各持一份
// 计数，等于给攻击者多份额度（见 Services.LoginGuard 的说明）。
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
	Username string `json:"username" binding:"required"`
	Password string `json:"password" binding:"required"`
	// TOTPCode 仅对已启用双因素的管理员必填。
	TOTPCode string `json:"totp_code"`
	// 账号累计失败较多时要求人机验证。
	CaptchaTicket string `json:"captcha_ticket"`
	CaptchaAnswer string `json:"captcha_answer"`
}

// Login 统一登录入口。
//
// 校验顺序与信息暴露控制：
//  1. 先按普通用户校验，成功即返回用户令牌；
//  2. 失败再按管理员校验（含动态口令）；
//  3. 两侧都失败时统一返回「账号或密码不正确」，不透露账号属于哪一侧。
//
// 这不构成账号枚举：未知账号与密码错误返回完全一致，且都执行了等价的哈希运算。
func (h *Handler) Login(c *gin.Context) {
	var req loginReq
	if err := c.ShouldBindJSON(&req); err != nil {
		httpx.BadRequest(c, "请填写账号与密码")
		return
	}

	// account 是**计数与校验共用**的键：锁定、验证码要求、登录日志都用它。
	//
	// 这里不能图省事在记录时用 req.Username（原始大小写）：验证码要求是按
	// 登录日志里的失败次数统计的，写入用一个写法、查询用另一个写法，脚本只要
	// 交替大小写就能把失败次数摊薄，账号级防线永远不触发。
	account := strings.ToLower(strings.TrimSpace(req.Username))
	ip := httpx.ClientIP(c)

	// 1. 硬锁：按「账号 + 来源 IP」计数，攻击者只能锁住自己。
	if !shared.CheckLoginLock(c, h.svc.LoginGuard, shared.LoginLockScopeUnified, account, ip) {
		h.record(c, model.LoginKindUser, account, model.LoginResultLocked,
			"账号在当前网络下处于登录锁定期")
		return
	}

	// 2. 账号累计失败达阈值 → 要求验证码，而不是硬锁。
	//
	//    这是「管理员不会被锁死」的关键：验证码由人解答，脚本无法继续爆破，
	//    而账号真正的所有者随时能登录进来。若改成硬锁，攻击者仅凭知道用户名
	//    就能把管理员永久挡在门外——这比爆破本身更廉价。
	switch shared.CheckLoginCaptcha(c, h.svc, account, req.CaptchaTicket, req.CaptchaAnswer, "") {
	case shared.CaptchaGatePass:
	case shared.CaptchaGateWrong:
		// 验证码错误也要计一次失败：验证码是一次性的（用错即作废），
		// 不计的话攻击者可以拿同一张票反复试，这道防线就变成了免费的密码配额。
		shared.LoginFailed(h.svc.LoginGuard, shared.LoginLockScopeUnified, account, ip)
		h.record(c, model.LoginKindUser, account, model.LoginResultBadCred, "验证码不正确")
		return
	default:
		// 没带验证码：响应已写出，本次不计失败（用户还没真正尝试密码）。
		return
	}

	// ---- 1. 普通用户 ----
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
		// 账号被禁用是明确的状态，直接告知比笼统报错更有用。
		shared.LoginFailed(h.svc.LoginGuard, shared.LoginLockScopeUnified, account, ip)
		h.record(c, model.LoginKindUser, account, model.LoginResultDisabled, err.Error())
		httpx.Forbidden(c, "账号已被禁用，请联系管理员")
		return
	}

	// ---- 2. 管理员 ----
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
			"role":          "admin",
			"token":         token,
			"expire_at":     expireAt,
			"redirect":      h.adminPath + "/",
			"username":      a.Username,
			"nickname":      a.Nickname,
			"role_name":     a.Role,
			"totp_enabled":  a.TOTPEnabled,
		})
		return
	}

	// 「未提交动态口令」只是交互未完成，不计入失败次数，
	// 否则用户每点一次登录都会被自己锁定。
	//
	// 这里额外带上机器可读标记，前端据此展开动态口令输入框，
	// 避免用文案匹配来判断。
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

// PublicSettings 返回登录/注册前就需要知道的站点信息。
//
// 只暴露非敏感字段：站点名、公告、注册开关、条款、是否支持邮件找回。
// 绝不包含任何密钥、SMTP 参数或用户数据。
func (h *Handler) PublicSettings(c *gin.Context) {
	s := h.svc.Settings
	httpx.OK(c, gin.H{
		"site_name":         s.Get(service.KeySiteName),
		"announcement":      s.Get(service.KeySiteAnnouncement),
		"icp":               s.Get(service.KeySiteICP),
		"register_enabled":  s.Bool(service.KeyRegisterEnabled),
		"register_need_invite": s.Bool(service.KeyRegisterNeedInvite),
		"register_require_email": s.Bool(service.KeyRegisterRequireEmail),
		"register_captcha":  s.Bool(service.KeyRegisterCaptcha),
		"terms":             s.Get(service.KeyRegisterTerms),
		"mail_enabled":      h.svc.MailEnabled(),
		"payment_enabled":   s.Bool(service.KeyPaymentEnabled),
		"payment_min":       s.Int(service.KeyPaymentMinAmount),
		"payment_max":       s.Int(service.KeyPaymentMaxAmount),
	})
}

// Captcha 生成一个算术验证码，返回题目与一次性票据。
//
// 为什么不用第三方图形验证码：那要么依赖外部服务，要么引入 cgo 依赖，
// 对一个轻量平台不划算。算术题配合「失败 N 次后才要求」已经能挡住绝大多数脚本。
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

// VerifyCaptcha 用于前端在提交前自检验证码（可选）。
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
