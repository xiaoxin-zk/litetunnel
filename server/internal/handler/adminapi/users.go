package adminapi

import (
	"fmt"
	"strconv"
	"time"

	"github.com/gin-gonic/gin"

	"github.com/xiaoxin-zk/litetunnel/server/internal/handler/shared"
	"github.com/xiaoxin-zk/litetunnel/server/internal/httpx"
	"github.com/xiaoxin-zk/litetunnel/server/internal/model"
	"github.com/xiaoxin-zk/litetunnel/server/internal/service"
)

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
