package userapi

import (
	"net/http"

	"github.com/gin-gonic/gin"

	"github.com/xiaoxin-zk/litetunnel/server/internal/httpx"
)

// ClientVersion 供桌面客户端检查更新：返回最新版本、下载地址与校验和。
func (h *Handler) ClientVersion(c *gin.Context) {
	current := c.Query("current")
	info, err := h.svc.LatestClientPackage(c.Request.Context(), current)
	if err != nil {
		httpx.Fail(c, http.StatusBadGateway, "暂时无法检查更新，请稍后再试")
		return
	}
	httpx.OK(c, info)
}
