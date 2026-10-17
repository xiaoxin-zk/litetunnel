package userapi

import (
	"github.com/gin-gonic/gin"

	"github.com/xiaoxin-zk/litetunnel/server/internal/handler/shared"
	"github.com/xiaoxin-zk/litetunnel/server/internal/httpx"
	"github.com/xiaoxin-zk/litetunnel/server/internal/middleware"
	"github.com/xiaoxin-zk/litetunnel/server/internal/model"
	"github.com/xiaoxin-zk/litetunnel/server/internal/service"
)

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

type emailChangeCodeReq struct {
	Email    string `json:"email" binding:"required"`
	Password string `json:"password" binding:"required"`
}

// RequestEmailChange 更换邮箱的第一步：校验密码后给新地址发验证码。
func (h *Handler) RequestEmailChange(c *gin.Context) {
	var req emailChangeCodeReq
	if err := c.ShouldBindJSON(&req); err != nil {
		httpx.BadRequest(c, "请填写新邮箱与登录密码")
		return
	}
	err := h.svc.RequestEmailChange(middleware.CurrentUserID(c),
		req.Email, req.Password, httpx.ClientIP(c))
	if err != nil {
		shared.Fail(c, err)
		return
	}
	httpx.OK(c, gin.H{"message": "验证码已发送到新邮箱，请查收"})
}

type emailConfirmReq struct {
	Email string `json:"email" binding:"required"`
	Code  string `json:"code" binding:"required"`
}

// ConfirmEmailChange 更换邮箱的第二步：校验新地址的验证码并换绑。
func (h *Handler) ConfirmEmailChange(c *gin.Context) {
	var req emailConfirmReq
	if err := c.ShouldBindJSON(&req); err != nil {
		httpx.BadRequest(c, "请填写新邮箱与验证码")
		return
	}
	if err := h.svc.ConfirmEmailChange(middleware.CurrentUserID(c), req.Email, req.Code); err != nil {
		shared.Fail(c, err)
		return
	}
	httpx.OK(c, gin.H{"message": "邮箱已更换"})
}

// profileVO 用户信息视图对象。不包含口令与任何密钥字段。
func (h *Handler) profileVO(u *model.User) gin.H {
	g := h.svc.EffectiveGroup(u)
	quota := h.svc.EffectiveQuota(u)
	vo := gin.H{
		"id":                 u.ID,
		"username":           u.Username,
		"nickname":           u.Nickname,
		"email":              u.Email,
		"status":             u.Status,
		"traffic_used":       u.TrafficUsed,
		"traffic_quota":      quota,
		"traffic_reset_at":   u.TrafficResetAt,
		"traffic_exceeded":   h.svc.QuotaExceeded(u),
		"balance":            u.Balance,
		"group_expire_at":    u.GroupExpireAt,
		"api_key_prefix":     u.APIKeyPrefix,
		"api_key_created_at": u.APIKeyCreatedAt,
		"created_at":         u.CreatedAt,
		"last_login_at":      u.LastLoginAt,
	}
	if g != nil {
		vo["group"] = gin.H{
			"id":              g.ID,
			"name":            g.Name,
			"max_tunnels":     g.MaxTunnels,
			"max_ports":       g.MaxPorts,
			"traffic_quota":   g.TrafficQuota,
			"bandwidth_limit": g.BandwidthLimit,
			// 给用户看的文案用 Human 版本（Mbps 口径），
			// 与后台分组表单填写的数字保持一致。
			"bandwidth_limit_str": service.FormatBandwidthHuman(g.BandwidthLimit),
			"allow_protocols":     g.AllowProtocols,
			"allow_custom_domain": g.AllowCustomDomain,
			// HTTPS 隧道入口。不并入 allow_protocols，是因为它属于**平台能力**
			// 而不是分组权限：管理员随时可能切模式，分组配置不该被迫跟着改。
			// 前端据此隐藏 https 选项——否则用户选了它，只能拿到一句报错。
			"https_tunnel_enabled": h.svc.HTTPSProxyEntryEnabled(),
			"https_entry":          h.svc.HTTPSProxyEntry(),
		}
	}
	return vo
}
