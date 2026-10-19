package middleware

import (
	"net/http"

	"github.com/gin-gonic/gin"

	"github.com/xiaoxin-zk/litetunnel/server/internal/httpx"
)

// StepUpChecker 由 service 层实现：开关状态与「当前会话是否已通过二次验证」。
type StepUpChecker interface {
	StepUpEnabled() bool
	HasStepUpGrant(adminID uint, sessionKey string) bool
}

// StepUp 是敏感操作门控：开启后要求本次登录会话在有效期内完成过一次 TOTP 二次验证。
// 未通过时返回 step_up_required，前端弹出动态口令输入后重试原请求，无需回传凭证。
func StepUp(checker StepUpChecker) gin.HandlerFunc {
	return func(c *gin.Context) {
		if checker == nil || !checker.StepUpEnabled() {
			c.Next()
			return
		}
		adminID := c.GetUint(CtxAdminID)
		if adminID == 0 {
			httpx.Unauthorized(c, "缺少访问令牌")
			return
		}
		if checker.HasStepUpGrant(adminID, c.GetString(CtxSessionID)) {
			c.Next()
			return
		}
		c.AbortWithStatusJSON(http.StatusForbidden, gin.H{
			"code":    http.StatusForbidden,
			"message": "该操作需二次验证：请输入认证器中的 6 位动态口令",
			"data":    gin.H{"step_up_required": true},
		})
	}
}
