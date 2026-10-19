package adminapi

import (
	"time"

	"github.com/gin-gonic/gin"

	"github.com/xiaoxin-zk/litetunnel/server/internal/handler/shared"
	"github.com/xiaoxin-zk/litetunnel/server/internal/httpx"
	"github.com/xiaoxin-zk/litetunnel/server/internal/middleware"
)

type stepUpReq struct {
	Code string `json:"code" binding:"required"`
}

// StepUpVerify 为当前登录会话发放一次 15 分钟的二次验证授权。
func (h *Handler) StepUpVerify(c *gin.Context) {
	var req stepUpReq
	if err := c.ShouldBindJSON(&req); err != nil {
		httpx.BadRequest(c, "请输入动态口令")
		return
	}
	adminID, _, _ := middleware.CurrentAdminID(c)
	expires, err := h.svc.VerifyAdminStepUp(adminID, req.Code, c.GetString(middleware.CtxSessionID))
	if err != nil {
		shared.Fail(c, err)
		return
	}
	h.audit(c, "admin.step_up", "admin", "", "敏感操作二次验证通过")
	httpx.OK(c, gin.H{
		"verified":   true,
		"expires_in": int(time.Until(expires).Seconds()),
	})
}
