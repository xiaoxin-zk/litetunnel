// Package adminapi 实现管理员后台 API。
//
// 该包只注册在「管理侧监听地址」上（默认 127.0.0.1），与用户侧端口物理隔离；
// 且使用独立的管理域 JWT，用户令牌在此处必然校验失败。
package adminapi

import (
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/gin-gonic/gin"

	"github.com/xiaoxin-zk/litetunnel/server/internal/auth"
	"github.com/xiaoxin-zk/litetunnel/server/internal/handler/shared"
	"github.com/xiaoxin-zk/litetunnel/server/internal/httpx"
	"github.com/xiaoxin-zk/litetunnel/server/internal/middleware"
	"github.com/xiaoxin-zk/litetunnel/server/internal/model"
	"github.com/xiaoxin-zk/litetunnel/server/internal/service"
)

// Handler 管理后台处理器。
type Handler struct {
	svc *service.Services
	// guard 按账号维度锁定连续登录失败。管理后台权限最高，锁定策略更严格。
	guard *middleware.LoginGuard
}

// New 构造处理器。
func New(svc *service.Services) *Handler {
	return &Handler{
		svc: svc,
		// 连续失败 3 次开始锁定，首次 30 分钟，上限 24 小时。
		guard: middleware.NewLoginGuard(3, 30*time.Minute, 24*time.Hour),
	}
}

// audit 记录一次管理操作。所有写操作都必须调用。
func (h *Handler) audit(c *gin.Context, action, target, targetID, detail string) {
	adminID, adminName, _ := middleware.CurrentAdminID(c)
	h.svc.WriteAudit(adminID, adminName, action, target, targetID, detail, httpx.ClientIP(c))
}

// ---- 认证 ----

type loginReq struct {
	Username string `json:"username" binding:"required"`
	Password string `json:"password" binding:"required"`
	// TOTPCode 为双因素动态口令，仅对已启用 TOTP 的账号必填。
	TOTPCode string `json:"totp_code"`
}

// Login 管理员登录，签发管理域令牌。
func (h *Handler) Login(c *gin.Context) {
	var req loginReq
	if err := c.ShouldBindJSON(&req); err != nil {
		httpx.BadRequest(c, "请填写用户名与密码")
		return
	}
	account := strings.ToLower(strings.TrimSpace(req.Username))
	if !shared.CheckLoginLock(c, h.guard, shared.LoginLockScopeAdmin, account) {
		// 锁定期间同样留痕，便于发现持续爆破。
		h.svc.WriteAudit(0, req.Username, "admin.login_locked", "admin", "", "账号处于登录锁定期", httpx.ClientIP(c))
		return
	}

	a, err := h.svc.AdminAuthenticate(req.Username, req.Password, req.TOTPCode, httpx.ClientIP(c))
	if err != nil {
		// 「未提交动态口令」只是交互未完成，不计入失败次数，
		// 否则用户每点一次登录都会被自己锁定。
		if errors.Is(err, service.ErrTOTPRequired) {
			shared.Fail(c, err)
			return
		}
		shared.LoginFailed(h.guard, shared.LoginLockScopeAdmin, account)
		// 管理员登录失败同样写入审计，便于发现暴力破解。
		h.svc.WriteAudit(0, req.Username, "admin.login_failed", "admin", "", err.Error(), httpx.ClientIP(c))
		shared.Fail(c, err)
		return
	}
	shared.LoginSucceeded(h.guard, shared.LoginLockScopeAdmin, account)
	token, expireAt, err := auth.Issue(
		h.svc.Cfg.AdminJWTSecret, auth.DomainAdmin,
		a.ID, a.Username, a.Role, h.svc.Cfg.AdminJWTExpire,
	)
	if err != nil {
		shared.Fail(c, err)
		return
	}
	h.svc.WriteAudit(a.ID, a.Username, "admin.login", "admin", strconv.Itoa(int(a.ID)), "", httpx.ClientIP(c))
	httpx.OK(c, gin.H{
		"token":      token,
		"expires_at": expireAt,
		"admin": gin.H{
			"id":       a.ID,
			"username": a.Username,
			"nickname": a.Nickname,
			"role":     a.Role,
		},
	})
}

// Profile 当前管理员信息。
func (h *Handler) Profile(c *gin.Context) {
	adminID, _, _ := middleware.CurrentAdminID(c)
	a, err := h.svc.LoadAdmin(adminID)
	if err != nil {
		shared.Fail(c, err)
		return
	}
	httpx.OK(c, gin.H{
		"id":               a.ID,
		"username":         a.Username,
		"nickname":         a.Nickname,
		"role":             a.Role,
		"totp_enabled":     a.TOTPEnabled,
		"totp_verified_at": a.TOTPVerifiedAt,
		"last_login_at":    a.LastLoginAt,
		"last_login_ip":    a.LastLoginIP,
	})
}

// ---- 双因素认证 ----

// TOTPSetup 生成新的 TOTP 密钥（此时尚未启用）。
func (h *Handler) TOTPSetup(c *gin.Context) {
	adminID, _, _ := middleware.CurrentAdminID(c)
	secret, otpauth, err := h.svc.AdminTOTPSetup(adminID)
	if err != nil {
		shared.Fail(c, err)
		return
	}
	httpx.OK(c, gin.H{
		"secret":      secret,
		"otpauth_url": otpauth,
		"message":     "请用认证器 App 扫描二维码或手动输入密钥，然后输入一次动态口令完成绑定",
	})
}

type totpCodeReq struct {
	Code string `json:"code" binding:"required"`
}

// TOTPEnable 用一次正确的动态口令确认绑定。
func (h *Handler) TOTPEnable(c *gin.Context) {
	var req totpCodeReq
	if err := c.ShouldBindJSON(&req); err != nil {
		httpx.BadRequest(c, "请输入动态口令")
		return
	}
	adminID, _, _ := middleware.CurrentAdminID(c)
	if err := h.svc.AdminTOTPEnable(adminID, req.Code); err != nil {
		shared.Fail(c, err)
		return
	}
	h.audit(c, "admin.totp_enable", "admin", strconv.Itoa(int(adminID)), "启用双因素认证")
	httpx.OK(c, gin.H{"message": "双因素认证已启用，下次登录需要输入动态口令"})
}

type totpDisableReq struct {
	Password string `json:"password" binding:"required"`
}

// TOTPDisable 关闭双因素认证，需重新验证登录口令。
func (h *Handler) TOTPDisable(c *gin.Context) {
	var req totpDisableReq
	if err := c.ShouldBindJSON(&req); err != nil {
		httpx.BadRequest(c, "请输入登录密码")
		return
	}
	adminID, _, _ := middleware.CurrentAdminID(c)
	if err := h.svc.AdminTOTPDisable(adminID, req.Password); err != nil {
		shared.Fail(c, err)
		return
	}
	h.audit(c, "admin.totp_disable", "admin", strconv.Itoa(int(adminID)), "关闭双因素认证")
	httpx.OK(c, gin.H{"message": "双因素认证已关闭"})
}

type adminPasswordReq struct {
	OldPassword string `json:"old_password" binding:"required"`
	NewPassword string `json:"new_password" binding:"required"`
}

// ChangePassword 管理员修改自己的登录密码。
//
// 放在只读组里：审计角色同样需要能改自己的密码，且本接口只能改自己。
func (h *Handler) ChangePassword(c *gin.Context) {
	var req adminPasswordReq
	if err := c.ShouldBindJSON(&req); err != nil {
		httpx.BadRequest(c, "请填写原密码与新密码")
		return
	}
	adminID, _, _ := middleware.CurrentAdminID(c)
	if err := h.svc.AdminChangePassword(adminID, req.OldPassword, req.NewPassword); err != nil {
		shared.Fail(c, err)
		return
	}
	h.audit(c, "admin.change_password", "admin", strconv.Itoa(int(adminID)), "修改自身登录密码")
	httpx.OK(c, gin.H{"message": "密码已更新，请重新登录"})
}

// ---- 概览 ----

// StatsOverview 后台首页概览。
func (h *Handler) StatsOverview(c *gin.Context) {
	var (
		userTotal    int64
		userActive   int64
		tunnelTotal  int64
		tunnelActive int64
		onlineClient int64
	)
	db := h.svc.DB
	if err := db.Model(&model.User{}).Count(&userTotal).Error; err != nil {
		shared.Fail(c, err)
		return
	}
	_ = db.Model(&model.User{}).Where("status = ?", model.UserStatusActive).Count(&userActive).Error
	_ = db.Model(&model.Tunnel{}).Count(&tunnelTotal).Error
	_ = db.Model(&model.Tunnel{}).Where("status = ?", model.TunnelStatusActive).Count(&tunnelActive).Error
	_ = db.Model(&model.ClientSession{}).Where("online = ?", true).Count(&onlineClient).Error

	var totalUsed int64
	var usedRow struct{ Total int64 }
	_ = db.Model(&model.User{}).Select("COALESCE(SUM(traffic_used),0) AS total").Scan(&usedRow).Error
	totalUsed = usedRow.Total

	httpx.OK(c, gin.H{
		"user_total":         userTotal,
		"user_active":        userActive,
		"tunnel_total":       tunnelTotal,
		"tunnel_active":      tunnelActive,
		"online_client":      onlineClient,
		"traffic_used_total": totalUsed,
	})
}

// ---- 用户管理 ----

// ListUsers 用户列表。
func (h *Handler) ListUsers(c *gin.Context) {
	page, pageSize, offset := httpx.Pagination(c)
	groupID, _ := strconv.ParseUint(c.Query("group_id"), 10, 64)
	list, total, err := h.svc.ListUsers(
		c.Query("keyword"), c.Query("status"), uint(groupID), offset, pageSize,
	)
	if err != nil {
		shared.Fail(c, err)
		return
	}
	out := make([]gin.H, 0, len(list))
	for i := range list {
		out = append(out, h.userVO(&list[i]))
	}
	httpx.PageOK(c, out, total, page, pageSize)
}

func (h *Handler) userVO(u *model.User) gin.H {
	vo := gin.H{
		"id":               u.ID,
		"username":         u.Username,
		"email":            u.Email,
		"nickname":         u.Nickname,
		"status":           u.Status,
		"group_id":         u.GroupID,
		"traffic_used":     u.TrafficUsed,
		"traffic_quota":    u.TrafficQuota,
		"effective_quota":  h.svc.EffectiveQuota(u),
		"traffic_reset_at": u.TrafficResetAt,
		"balance":          u.Balance,
		"group_expire_at":  u.GroupExpireAt,
		"remark":           u.Remark,
		"api_key_prefix":   u.APIKeyPrefix,
		"has_client_secret": u.ClientSecret != "",
		"last_login_at":    u.LastLoginAt,
		"last_login_ip":    u.LastLoginIP,
		"created_at":       u.CreatedAt,
	}
	if u.Group != nil {
		vo["group_name"] = u.Group.Name
	}
	return vo
}

// CreateUser 管理员建号。
func (h *Handler) CreateUser(c *gin.Context) {
	var in service.AdminCreateUserInput
	if err := c.ShouldBindJSON(&in); err != nil {
		httpx.BadRequest(c, "参数格式不正确")
		return
	}
	u, err := h.svc.AdminCreateUser(in)
	if err != nil {
		shared.Fail(c, err)
		return
	}
	h.audit(c, "user.create", "user", strconv.Itoa(int(u.ID)), "创建用户 "+u.Username)
	httpx.OK(c, h.userVO(u))
}

// UpdateUser 修改用户基础信息。
func (h *Handler) UpdateUser(c *gin.Context) {
	id, err := parseID(c)
	if err != nil {
		httpx.BadRequest(c, "用户 ID 非法")
		return
	}
	var in service.AdminUpdateUserInput
	if err := c.ShouldBindJSON(&in); err != nil {
		httpx.BadRequest(c, "参数格式不正确")
		return
	}
	if err := h.svc.AdminUpdateUser(id, in); err != nil {
		shared.Fail(c, err)
		return
	}
	h.audit(c, "user.update", "user", c.Param("id"), "修改用户资料")
	httpx.OK(c, gin.H{"message": "已保存"})
}

// DeleteUser 删除用户。
func (h *Handler) DeleteUser(c *gin.Context) {
	id, err := parseID(c)
	if err != nil {
		httpx.BadRequest(c, "用户 ID 非法")
		return
	}
	if err := h.svc.AdminDeleteUser(id); err != nil {
		shared.Fail(c, err)
		return
	}
	h.audit(c, "user.delete", "user", c.Param("id"), "删除用户及其全部隧道")
	httpx.OK(c, gin.H{"message": "用户已删除"})
}

type statusReq struct {
	Status string `json:"status" binding:"required"`
}

// SetUserStatus 禁用/启用/封禁用户。
func (h *Handler) SetUserStatus(c *gin.Context) {
	id, err := parseID(c)
	if err != nil {
		httpx.BadRequest(c, "用户 ID 非法")
		return
	}
	var req statusReq
	if err := c.ShouldBindJSON(&req); err != nil {
		httpx.BadRequest(c, "参数格式不正确")
		return
	}
	if err := h.svc.AdminSetUserStatus(id, req.Status); err != nil {
		shared.Fail(c, err)
		return
	}
	h.audit(c, "user.status", "user", c.Param("id"), "状态变更为 "+req.Status)
	httpx.OK(c, gin.H{"message": "状态已更新"})
}

type quotaReq struct {
	// TrafficQuota 单位字节，0 表示回落到分组配额
	TrafficQuota int64 `json:"traffic_quota"`
}

// SetUserQuota 设置用户流量配额。
func (h *Handler) SetUserQuota(c *gin.Context) {
	id, err := parseID(c)
	if err != nil {
		httpx.BadRequest(c, "用户 ID 非法")
		return
	}
	var req quotaReq
	if err := c.ShouldBindJSON(&req); err != nil {
		httpx.BadRequest(c, "参数格式不正确")
		return
	}
	if err := h.svc.AdminSetUserQuota(id, req.TrafficQuota); err != nil {
		shared.Fail(c, err)
		return
	}
	h.audit(c, "user.quota", "user", c.Param("id"),
		fmt.Sprintf("流量配额设为 %s", service.FormatBytes(req.TrafficQuota)))
	httpx.OK(c, gin.H{"message": "配额已更新"})
}

// ResetUserTraffic 清零用户已用流量。
func (h *Handler) ResetUserTraffic(c *gin.Context) {
	id, err := parseID(c)
	if err != nil {
		httpx.BadRequest(c, "用户 ID 非法")
		return
	}
	if err := h.svc.AdminResetUserTraffic(id); err != nil {
		shared.Fail(c, err)
		return
	}
	h.audit(c, "user.traffic_reset", "user", c.Param("id"), "清零已用流量")
	httpx.OK(c, gin.H{"message": "已清零"})
}

type groupReq struct {
	GroupID  uint       `json:"group_id" binding:"required"`
	ExpireAt *time.Time `json:"expire_at"`
}

// SetUserGroup 调整用户分组。
func (h *Handler) SetUserGroup(c *gin.Context) {
	id, err := parseID(c)
	if err != nil {
		httpx.BadRequest(c, "用户 ID 非法")
		return
	}
	var req groupReq
	if err := c.ShouldBindJSON(&req); err != nil {
		httpx.BadRequest(c, "参数格式不正确")
		return
	}
	if err := h.svc.AdminSetUserGroup(id, req.GroupID, req.ExpireAt); err != nil {
		shared.Fail(c, err)
		return
	}
	h.audit(c, "user.group", "user", c.Param("id"), fmt.Sprintf("分组调整为 %d", req.GroupID))
	httpx.OK(c, gin.H{"message": "分组已更新"})
}

type passwordReq struct {
	Password string `json:"password" binding:"required"`
}

// ResetUserPassword 重置用户密码。
func (h *Handler) ResetUserPassword(c *gin.Context) {
	id, err := parseID(c)
	if err != nil {
		httpx.BadRequest(c, "用户 ID 非法")
		return
	}
	var req passwordReq
	if err := c.ShouldBindJSON(&req); err != nil {
		httpx.BadRequest(c, "参数格式不正确")
		return
	}
	if err := h.svc.AdminResetUserPassword(id, req.Password); err != nil {
		shared.Fail(c, err)
		return
	}
	h.audit(c, "user.reset_password", "user", c.Param("id"), "重置登录密码")
	httpx.OK(c, gin.H{"message": "密码已重置"})
}

// ResetUserSecret 重置用户客户端凭据。
func (h *Handler) ResetUserSecret(c *gin.Context) {
	id, err := parseID(c)
	if err != nil {
		httpx.BadRequest(c, "用户 ID 非法")
		return
	}
	secret, err := h.svc.AdminResetUserSecret(id)
	if err != nil {
		shared.Fail(c, err)
		return
	}
	h.audit(c, "user.reset_secret", "user", c.Param("id"), "重置客户端接入凭据")
	httpx.OK(c, gin.H{"client_secret": secret, "message": "凭据已重置，旧客户端立即失效"})
}

// ---- 分组管理 ----

// ListGroups 分组列表。
func (h *Handler) ListGroups(c *gin.Context) {
	list, err := h.svc.ListGroups()
	if err != nil {
		shared.Fail(c, err)
		return
	}
	httpx.OK(c, list)
}

// CreateGroup 新建分组。
func (h *Handler) CreateGroup(c *gin.Context) {
	var in service.GroupInput
	if err := c.ShouldBindJSON(&in); err != nil {
		httpx.BadRequest(c, "参数格式不正确")
		return
	}
	g, err := h.svc.CreateGroup(in)
	if err != nil {
		shared.Fail(c, err)
		return
	}
	h.audit(c, "group.create", "group", strconv.Itoa(int(g.ID)), "创建分组 "+g.Name)
	httpx.OK(c, g)
}

// UpdateGroup 更新分组。
func (h *Handler) UpdateGroup(c *gin.Context) {
	id, err := parseID(c)
	if err != nil {
		httpx.BadRequest(c, "分组 ID 非法")
		return
	}
	var in service.GroupInput
	if err := c.ShouldBindJSON(&in); err != nil {
		httpx.BadRequest(c, "参数格式不正确")
		return
	}
	g, err := h.svc.UpdateGroup(id, in)
	if err != nil {
		shared.Fail(c, err)
		return
	}
	h.audit(c, "group.update", "group", c.Param("id"), "更新分组 "+g.Name)
	httpx.OK(c, g)
}

// DeleteGroup 删除分组。
func (h *Handler) DeleteGroup(c *gin.Context) {
	id, err := parseID(c)
	if err != nil {
		httpx.BadRequest(c, "分组 ID 非法")
		return
	}
	if err := h.svc.DeleteGroup(id); err != nil {
		shared.Fail(c, err)
		return
	}
	h.audit(c, "group.delete", "group", c.Param("id"), "删除分组")
	httpx.OK(c, gin.H{"message": "分组已删除"})
}

// ---- 隧道管理 ----

// ListTunnels 全部隧道。
func (h *Handler) ListTunnels(c *gin.Context) {
	page, pageSize, offset := httpx.Pagination(c)
	userID, _ := strconv.ParseUint(c.Query("user_id"), 10, 64)
	list, total, err := h.svc.ListAllTunnels(
		c.Query("keyword"), c.Query("status"), uint(userID), offset, pageSize,
	)
	if err != nil {
		shared.Fail(c, err)
		return
	}
	out := make([]gin.H, 0, len(list))
	for i := range list {
		out = append(out, gin.H{
			"id":          list[i].ID,
			"user_id":     list[i].UserID,
			"name":        list[i].Name,
			"type":        list[i].Type,
			"local_ip":    list[i].LocalIP,
			"local_port":  list[i].LocalPort,
			"remote_port": list[i].RemotePort,
			"domain":      list[i].Domain,
			"subdomain":   list[i].Subdomain,
			"status":      list[i].Status,
			"online":      h.svc.Runtime.IsTunnelOnline(list[i].ID),
			"traffic_used": list[i].TrafficUsed,
			"created_at":  list[i].CreatedAt,
		})
	}
	httpx.PageOK(c, out, total, page, pageSize)
}

// SetTunnelStatus 启用/停用隧道。
func (h *Handler) SetTunnelStatus(c *gin.Context) {
	id, err := parseID(c)
	if err != nil {
		httpx.BadRequest(c, "隧道 ID 非法")
		return
	}
	var req statusReq
	if err := c.ShouldBindJSON(&req); err != nil {
		httpx.BadRequest(c, "参数格式不正确")
		return
	}
	if err := h.svc.AdminSetTunnelStatus(id, req.Status); err != nil {
		shared.Fail(c, err)
		return
	}
	h.audit(c, "tunnel.status", "tunnel", c.Param("id"), "状态变更为 "+req.Status)
	httpx.OK(c, gin.H{"message": "状态已更新"})
}

// DeleteTunnel 删除隧道。
func (h *Handler) DeleteTunnel(c *gin.Context) {
	id, err := parseID(c)
	if err != nil {
		httpx.BadRequest(c, "隧道 ID 非法")
		return
	}
	if err := h.svc.AdminDeleteTunnel(id); err != nil {
		shared.Fail(c, err)
		return
	}
	h.audit(c, "tunnel.delete", "tunnel", c.Param("id"), "删除隧道")
	httpx.OK(c, gin.H{"message": "隧道已删除"})
}

// ---- 兑换码 ----

// ListRedeemCodes 兑换码列表。
func (h *Handler) ListRedeemCodes(c *gin.Context) {
	page, pageSize, offset := httpx.Pagination(c)
	list, total, err := h.svc.ListRedeemCodes(c.Query("keyword"), c.Query("status"), c.Query("batch_no"), offset, pageSize)
	if err != nil {
		shared.Fail(c, err)
		return
	}
	httpx.PageOK(c, list, total, page, pageSize)
}

// GenerateRedeemCodes 批量生成兑换码。
func (h *Handler) GenerateRedeemCodes(c *gin.Context) {
	var in service.GenerateCodesInput
	if err := c.ShouldBindJSON(&in); err != nil {
		httpx.BadRequest(c, "参数格式不正确")
		return
	}
	adminID, _, _ := middleware.CurrentAdminID(c)
	codes, err := h.svc.GenerateCodes(adminID, in)
	if err != nil {
		shared.Fail(c, err)
		return
	}
	plain := make([]string, 0, len(codes))
	for i := range codes {
		plain = append(plain, codes[i].Code)
	}
	h.audit(c, "redeem.generate", "redeem_code", codes[0].BatchNo,
		fmt.Sprintf("生成 %d 个兑换码，类型 %s", len(codes), in.Type))
	httpx.OK(c, gin.H{
		"batch_no": codes[0].BatchNo,
		"count":    len(codes),
		"codes":    plain,
	})
}

// SetRedeemCodeStatus 禁用/启用兑换码。
func (h *Handler) SetRedeemCodeStatus(c *gin.Context) {
	id, err := parseID(c)
	if err != nil {
		httpx.BadRequest(c, "兑换码 ID 非法")
		return
	}
	var req statusReq
	if err := c.ShouldBindJSON(&req); err != nil {
		httpx.BadRequest(c, "参数格式不正确")
		return
	}
	if err := h.svc.SetRedeemCodeStatus(id, req.Status); err != nil {
		shared.Fail(c, err)
		return
	}
	h.audit(c, "redeem.status", "redeem_code", c.Param("id"), "状态变更为 "+req.Status)
	httpx.OK(c, gin.H{"message": "状态已更新"})
}

// DeleteRedeemCode 删除兑换码。
func (h *Handler) DeleteRedeemCode(c *gin.Context) {
	id, err := parseID(c)
	if err != nil {
		httpx.BadRequest(c, "兑换码 ID 非法")
		return
	}
	if err := h.svc.DeleteRedeemCode(id); err != nil {
		shared.Fail(c, err)
		return
	}
	h.audit(c, "redeem.delete", "redeem_code", c.Param("id"), "删除兑换码")
	httpx.OK(c, gin.H{"message": "已删除"})
}

// ListRedeemRecords 兑换流水。
func (h *Handler) ListRedeemRecords(c *gin.Context) {
	page, pageSize, offset := httpx.Pagination(c)
	userID, _ := strconv.ParseUint(c.Query("user_id"), 10, 64)
	list, total, err := h.svc.ListRedeemRecords(uint(userID), offset, pageSize)
	if err != nil {
		shared.Fail(c, err)
		return
	}
	httpx.PageOK(c, list, total, page, pageSize)
}

// ---- 客户端会话与审计 ----

// ListClients 客户端会话列表。
func (h *Handler) ListClients(c *gin.Context) {
	page, pageSize, offset := httpx.Pagination(c)
	userID, _ := strconv.ParseUint(c.Query("user_id"), 10, 64)
	list, total, err := h.svc.ListClientSessions(uint(userID), offset, pageSize)
	if err != nil {
		shared.Fail(c, err)
		return
	}
	httpx.PageOK(c, list, total, page, pageSize)
}

// ListAuditLogs 审计日志。
func (h *Handler) ListAuditLogs(c *gin.Context) {
	page, pageSize, offset := httpx.Pagination(c)
	list, total, err := h.svc.ListAuditLogs(c.Query("action"), offset, pageSize)
	if err != nil {
		shared.Fail(c, err)
		return
	}
	httpx.PageOK(c, list, total, page, pageSize)
}

func parseID(c *gin.Context) (uint, error) {
	v, err := strconv.ParseUint(c.Param("id"), 10, 64)
	if err != nil || v == 0 {
		return 0, errors.New("非法 ID")
	}
	return uint(v), nil
}
