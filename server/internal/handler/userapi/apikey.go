package userapi

import (
	"github.com/gin-gonic/gin"

	"github.com/xiaoxin-zk/litetunnel/server/internal/handler/shared"
	"github.com/xiaoxin-zk/litetunnel/server/internal/httpx"
	"github.com/xiaoxin-zk/litetunnel/server/internal/middleware"
)

// GetAPIKey 返回 API Key 的元信息（不含明文）。
func (h *Handler) GetAPIKey(c *gin.Context) {
	u, err := h.svc.LoadUser(middleware.CurrentUserID(c))
	if err != nil {
		shared.Fail(c, err)
		return
	}
	httpx.OK(c, gin.H{
		"prefix":     u.APIKeyPrefix,
		"created_at": u.APIKeyCreatedAt,
		"exists":     u.APIKeyHash != "",
	})
}

// RevealAPIKey 解密回显 API Key 明文，供用户复制到客户端。
func (h *Handler) RevealAPIKey(c *gin.Context) {
	u, err := h.svc.LoadUser(middleware.CurrentUserID(c))
	if err != nil {
		shared.Fail(c, err)
		return
	}
	plain, err := h.svc.RevealAPIKey(u)
	if err != nil {
		httpx.BadRequest(c, "尚未生成 API Key，请先重置生成")
		return
	}
	httpx.OK(c, gin.H{"api_key": plain})
}

// RotateAPIKey 重置 API Key，旧 Key 立即失效。
func (h *Handler) RotateAPIKey(c *gin.Context) {
	uid := middleware.CurrentUserID(c)
	plain, prefix, err := h.svc.RotateAPIKey(uid)
	if err != nil {
		shared.Fail(c, err)
		return
	}
	httpx.OK(c, gin.H{
		"api_key": plain,
		"prefix":  prefix,
		"message": "API Key 已重置，请妥善保存，旧 Key 已失效",
	})
}
