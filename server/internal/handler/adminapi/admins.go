package adminapi

import (
	"fmt"
	"strconv"

	"github.com/gin-gonic/gin"

	"github.com/xiaoxin-zk/litetunnel/server/internal/handler/shared"
	"github.com/xiaoxin-zk/litetunnel/server/internal/httpx"
	"github.com/xiaoxin-zk/litetunnel/server/internal/middleware"
	"github.com/xiaoxin-zk/litetunnel/server/internal/model"
	"github.com/xiaoxin-zk/litetunnel/server/internal/service"
)

func adminVO(a *model.Admin) gin.H {
	return gin.H{
		"id":               a.ID,
		"username":         a.Username,
		"nickname":         a.Nickname,
		"role":             a.Role,
		"status":           a.Status,
		"totp_enabled":     a.TOTPEnabled,
		"totp_verified_at": a.TOTPVerifiedAt,
		"last_login_at":    a.LastLoginAt,
		"last_login_ip":    a.LastLoginIP,
		"created_at":       a.CreatedAt,
	}
}

func (h *Handler) ListAdmins(c *gin.Context) {
	list, err := h.svc.ListAdmins()
	if err != nil {
		shared.Fail(c, err)
		return
	}
	out := make([]gin.H, 0, len(list))
	for i := range list {
		out = append(out, adminVO(&list[i]))
	}
	httpx.OK(c, out)
}

func (h *Handler) CreateAdmin(c *gin.Context) {
	var in service.AdminCreateInput
	if err := c.ShouldBindJSON(&in); err != nil {
		httpx.BadRequest(c, "参数格式不正确")
		return
	}
	a, err := h.svc.CreateAdmin(in)
	if err != nil {
		shared.Fail(c, err)
		return
	}
	h.audit(c, "admin.create", "admin", strconv.Itoa(int(a.ID)),
		fmt.Sprintf("新建管理员 %s（角色 %s）", a.Username, a.Role))
	httpx.OK(c, adminVO(a))
}

func (h *Handler) UpdateAdmin(c *gin.Context) {
	id, err := parseID(c)
	if err != nil {
		httpx.BadRequest(c, "管理员 ID 非法")
		return
	}
	var in service.AdminUpdateInput
	if err := c.ShouldBindJSON(&in); err != nil {
		httpx.BadRequest(c, "参数格式不正确")
		return
	}
	operatorID, _, _ := middleware.CurrentAdminID(c)
	if err := h.svc.UpdateAdmin(id, operatorID, in); err != nil {
		shared.Fail(c, err)
		return
	}
	h.audit(c, "admin.update", "admin", c.Param("id"), "修改管理员资料")
	httpx.OK(c, gin.H{"message": "已保存"})
}

func (h *Handler) DeleteAdmin(c *gin.Context) {
	id, err := parseID(c)
	if err != nil {
		httpx.BadRequest(c, "管理员 ID 非法")
		return
	}
	operatorID, _, _ := middleware.CurrentAdminID(c)
	if err := h.svc.DeleteAdmin(id, operatorID); err != nil {
		shared.Fail(c, err)
		return
	}
	h.audit(c, "admin.delete", "admin", c.Param("id"), "删除管理员")
	httpx.OK(c, gin.H{"message": "管理员已删除"})
}

func (h *Handler) SetAdminPassword(c *gin.Context) {
	id, err := parseID(c)
	if err != nil {
		httpx.BadRequest(c, "管理员 ID 非法")
		return
	}
	var req passwordReq
	if err := c.ShouldBindJSON(&req); err != nil {
		httpx.BadRequest(c, "参数格式不正确")
		return
	}
	if err := h.svc.AdminSetPassword(id, req.Password); err != nil {
		shared.Fail(c, err)
		return
	}
	h.audit(c, "admin.set_password", "admin", c.Param("id"), "重置管理员登录密码")
	httpx.OK(c, gin.H{"message": "密码已重置，该账号所有会话已下线"})
}

func (h *Handler) ClearAdminTOTP(c *gin.Context) {
	id, err := parseID(c)
	if err != nil {
		httpx.BadRequest(c, "管理员 ID 非法")
		return
	}
	if err := h.svc.AdminClearTOTP(id); err != nil {
		shared.Fail(c, err)
		return
	}
	h.audit(c, "admin.clear_totp", "admin", c.Param("id"), "清除管理员双因素绑定")
	httpx.OK(c, gin.H{"message": "双因素绑定已清除"})
}
