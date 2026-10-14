// Package shared 提供处理器层的公共辅助函数。
package shared

import (
	"errors"
	"fmt"
	"log"
	"net/http"

	"github.com/gin-gonic/gin"

	"github.com/xiaoxin-zk/litetunnel/server/internal/httpx"
	"github.com/xiaoxin-zk/litetunnel/server/internal/middleware"
	"github.com/xiaoxin-zk/litetunnel/server/internal/model"
	"github.com/xiaoxin-zk/litetunnel/server/internal/service"
)

// LoginLockScope 用于区分不同登录入口的锁定计数，互不影响。
const (
	LoginLockScopeUser  = "user"
	LoginLockScopeAdmin = "admin"
	// LoginLockScopeUnified 用于统一登录入口：提交时无法预判账号属于哪一侧，
	// 因此单独计数并采用最严的策略。
	LoginLockScopeUnified = "unified"
)

// CheckLoginLock 检查账号是否处于登录锁定期。
//
// 与按 IP 的令牌桶互补：令牌桶挡不住代理池对单一账号的慢速爆破，
// 账号级指数退避锁定可以。返回 false 时已写出响应，调用方直接 return。
func CheckLoginLock(c *gin.Context, g *middleware.LoginGuard, scope, account string) bool {
	ok, wait := g.Check(scope, account)
	if ok {
		return true
	}
	minutes := int(wait.Minutes()) + 1
	httpx.Fail(c, http.StatusTooManyRequests,
		fmt.Sprintf("该账号因连续登录失败已被临时锁定，请约 %d 分钟后重试", minutes))
	return false
}

// LoginFailed 记录一次登录失败。
func LoginFailed(g *middleware.LoginGuard, scope, account string) {
	g.Fail(scope, account)
}

// LoginSucceeded 清除该账号的失败记录。
func LoginSucceeded(g *middleware.LoginGuard, scope, account string) {
	g.Reset(scope, account)
}

// LoginResultOf 把登录错误归类为日志用的结果码。
//
// 归类而非直接记录错误文本，是为了让后台可以按结果聚合统计，
// 例如「近 24 小时 totp_failed 次数」这类风控视图。
func LoginResultOf(err error) string {
	switch {
	case err == nil:
		return model.LoginResultSuccess
	case errors.Is(err, service.ErrAccountDisabled):
		return model.LoginResultDisabled
	case errors.Is(err, service.ErrTOTPInvalid):
		return model.LoginResultTOTPFail
	default:
		return model.LoginResultBadCred
	}
}

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
