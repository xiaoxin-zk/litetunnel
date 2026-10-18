package adminapi

import (
	"errors"
	"io"
	"strconv"

	"github.com/gin-gonic/gin"

	"github.com/xiaoxin-zk/litetunnel/server/internal/handler/shared"
	"github.com/xiaoxin-zk/litetunnel/server/internal/httpx"
	"github.com/xiaoxin-zk/litetunnel/server/internal/middleware"
	"github.com/xiaoxin-zk/litetunnel/server/internal/service"
)

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

// UpdateProfile 管理员修改自己的登录账号与昵称。
//
// 放在只读权限组：本接口只能改自己，审计角色同样需要能改。
func (h *Handler) UpdateProfile(c *gin.Context) {
	var in service.AdminProfileInput
	if err := c.ShouldBindJSON(&in); err != nil {
		httpx.BadRequest(c, "参数格式不正确")
		return
	}
	adminID, _, _ := middleware.CurrentAdminID(c)
	a, err := h.svc.AdminUpdateProfile(adminID, in)
	if err != nil {
		shared.Fail(c, err)
		return
	}
	h.audit(c, "admin.update_profile", "admin", strconv.Itoa(int(adminID)), "修改自身账号资料")
	httpx.OK(c, gin.H{
		"id":       a.ID,
		"username": a.Username,
		"nickname": a.Nickname,
		"message":  "已保存。登录账号已变更，下次登录请使用新账号。",
	})
}

// TOTPSetup 生成新的 TOTP 密钥（此时尚未启用）。
//
// 已启用双因素时属于「换绑」，需要提供**当前生效的动态口令**（见 service 层
// 的说明）。因此这里接受一个可选字段：未启用时前端不带任何参数，空 body
// 也要能正常处理。
func (h *Handler) TOTPSetup(c *gin.Context) {
	var req struct {
		Code string `json:"code"`
	}
	// 空 body 不是错误：首次绑定时前端不会传任何参数，这一点必须保留。
	//
	// 但**只有 EOF 算空**。以前这里忽略了一切解析错误，于是「忘了带
	// Content-Type」「JSON 写错了」「字段名拼错」与「没传参数」在处理流程里
	// 无法区分：接口照常生成新密钥并返回成功。调用方以为参数生效了，实际
	// 被静默丢弃——对一个会改变双因素认证状态的接口，这种沉默比报错更危险。
	if err := c.ShouldBindJSON(&req); err != nil && !errors.Is(err, io.EOF) {
		httpx.BadRequest(c, "参数格式不正确")
		return
	}

	adminID, _, _ := middleware.CurrentAdminID(c)
	secret, otpauth, err := h.svc.AdminTOTPSetup(adminID, req.Code)
	if err != nil {
		shared.Fail(c, err)
		return
	}
	// 换绑是安全相关的操作，记一条审计（首次绑定也会记，代价可以忽略）。
	h.audit(c, "admin.totp_setup", "admin", strconv.Itoa(int(adminID)), "生成动态口令密钥")
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
