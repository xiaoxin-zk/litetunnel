// Package shared 提供处理器层的公共辅助函数。
package shared

import (
	"errors"
	"log"

	"github.com/gin-gonic/gin"

	"github.com/xiaoxin-zk/litetunnel/server/internal/httpx"
	"github.com/xiaoxin-zk/litetunnel/server/internal/service"
)

// Fail 把业务错误统一映射为 HTTP 响应。
//
// 未识别的错误一律返回 500 且不回显内部细节，避免泄露实现信息。
func Fail(c *gin.Context, err error) {
	switch {
	case err == nil:
		return

	case errors.Is(err, service.ErrNotFound):
		httpx.NotFound(c, err.Error())

	case errors.Is(err, service.ErrBadCredentials),
		errors.Is(err, service.ErrAccountDisabled):
		httpx.Unauthorized(c, err.Error())

	case errors.Is(err, service.ErrUsernameTaken):
		httpx.Conflict(c, err.Error())

	case errors.Is(err, service.ErrQuotaExceeded),
		errors.Is(err, service.ErrTunnelLimit),
		errors.Is(err, service.ErrPortLimit),
		errors.Is(err, service.ErrProtocolDenied),
		errors.Is(err, service.ErrDomainDenied),
		errors.Is(err, service.ErrCodeDisabled):
		httpx.Forbidden(c, err.Error())

	case errors.Is(err, service.ErrInvalidParam),
		errors.Is(err, service.ErrPortInUse),
		errors.Is(err, service.ErrNoPortAvailable),
		errors.Is(err, service.ErrCodeInvalid),
		errors.Is(err, service.ErrCodeUsed),
		errors.Is(err, service.ErrCodeExpired):
		httpx.BadRequest(c, err.Error())

	default:
		log.Printf("[api] %s %s 处理失败: %v", c.Request.Method, c.Request.URL.Path, err)
		httpx.ServerError(c, "服务内部错误，请稍后重试")
	}
}
