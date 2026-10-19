package adminapi

import (
	"github.com/gin-gonic/gin"

	"github.com/xiaoxin-zk/litetunnel/server/internal/httpx"
)

// HealthReport 返回健康分、分项明细与待办清单。
// 只读接口：审计只读角色也能看，用于判断「现在要不要处理」。
func (h *Handler) HealthReport(c *gin.Context) {
	httpx.OK(c, h.svc.HealthReport())
}
