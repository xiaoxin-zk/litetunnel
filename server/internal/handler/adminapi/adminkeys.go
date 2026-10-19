package adminapi

import (
	"strconv"

	"github.com/gin-gonic/gin"

	"github.com/xiaoxin-zk/litetunnel/server/internal/handler/shared"
	"github.com/xiaoxin-zk/litetunnel/server/internal/httpx"
	"github.com/xiaoxin-zk/litetunnel/server/internal/middleware"
	"github.com/xiaoxin-zk/litetunnel/server/internal/service"
)

func (h *Handler) ListAdminAPIKeys(c *gin.Context) {
	items, err := h.svc.ListAdminAPIKeys()
	if err != nil {
		shared.Fail(c, err)
		return
	}
	httpx.OK(c, items)
}

func (h *Handler) CreateAdminAPIKey(c *gin.Context) {
	var in service.AdminAPIKeyInput
	if err := c.ShouldBindJSON(&in); err != nil {
		httpx.BadRequest(c, "参数格式不正确")
		return
	}
	adminID, _, _ := middleware.CurrentAdminID(c)
	plain, view, err := h.svc.CreateAdminAPIKey(adminID, in)
	if err != nil {
		shared.Fail(c, err)
		return
	}
	h.audit(c, "admin_api_key.create", "admin_api_key", strconv.Itoa(int(view.ID)), "创建只读 Key："+view.Name)
	httpx.OK(c, gin.H{
		"key":     plain,
		"item":    view,
		"message": "请立刻复制保存：明文只显示这一次",
	})
}

func (h *Handler) RevokeAdminAPIKey(c *gin.Context) {
	id, err := parseID(c)
	if err != nil {
		httpx.BadRequest(c, "Key ID 非法")
		return
	}
	if err := h.svc.RevokeAdminAPIKey(id); err != nil {
		shared.Fail(c, err)
		return
	}
	h.audit(c, "admin_api_key.revoke", "admin_api_key", strconv.Itoa(int(id)), "吊销只读 Key")
	httpx.OK(c, gin.H{"message": "已吊销"})
}
