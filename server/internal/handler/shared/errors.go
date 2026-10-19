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

const LoginLockScopeUnified = "unified"

func CheckLoginLock(c *gin.Context, g *middleware.LoginGuard, scope, account, ip string) bool {
	ok, wait := g.Check(scope, account, ip)
	if ok {
		return true
	}
	minutes := int(wait.Minutes()) + 1
	httpx.Fail(c, http.StatusTooManyRequests,
		fmt.Sprintf("该账号在当前网络下因连续登录失败已被临时锁定，请约 %d 分钟后重试", minutes))
	return false
}

func LoginFailed(g *middleware.LoginGuard, scope, account, ip string) {
	g.Fail(scope, account, ip)
}

func LoginSucceeded(g *middleware.LoginGuard, scope, account, ip string) {
	g.Reset(scope, account, ip)
}

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

func Fail(c *gin.Context, err error) {
	switch {
	case err == nil:
		return

	case errors.Is(err, service.ErrNotFound):
		httpx.NotFound(c, err.Error())

	case errors.Is(err, service.ErrEmailCodeCheckFailed):
		httpx.Fail(c, http.StatusServiceUnavailable, err.Error())

	case errors.Is(err, service.ErrBadCredentials),
		errors.Is(err, service.ErrAccountDisabled):
		httpx.Unauthorized(c, err.Error())

	case errors.Is(err, service.ErrTOTPRequired),
		errors.Is(err, service.ErrTOTPInvalid),
		errors.Is(err, service.ErrTOTPReplay),
		errors.Is(err, service.ErrEmailCodeWrong),
		errors.Is(err, service.ErrResetTokenInvalid),
		errors.Is(err, service.ErrResetTokenExpired):
		httpx.Unauthorized(c, err.Error())

	case errors.Is(err, service.ErrUsernameTaken),
		errors.Is(err, service.ErrEmailTaken):
		httpx.Conflict(c, err.Error())

	case errors.Is(err, service.ErrEmailCodeTooSoon),
		errors.Is(err, service.ErrEmailCodeTooMany),
		errors.Is(err, service.ErrEmailCodeAttempts),
		errors.Is(err, service.ErrRegisterLimited),
		errors.Is(err, service.ErrDomainRegisterLimited),
		errors.Is(err, service.ErrMailQueueFull):
		httpx.Fail(c, http.StatusTooManyRequests, err.Error())

	case errors.Is(err, service.ErrPortScanUnavailable):
		httpx.Fail(c, http.StatusServiceUnavailable, err.Error())

	case errors.Is(err, service.ErrQuotaExceeded),
		errors.Is(err, service.ErrTunnelLimit),
		errors.Is(err, service.ErrPortLimit),
		errors.Is(err, service.ErrProtocolDenied),
		errors.Is(err, service.ErrDomainDenied),
		errors.Is(err, service.ErrCodeDisabled),
		errors.Is(err, service.ErrDomainNotTrusted):
		httpx.Forbidden(c, err.Error())

	case errors.Is(err, service.ErrInvalidParam),
		errors.Is(err, service.ErrNoHTTPSProxyEntry),
		errors.Is(err, service.ErrPortInUse),
		errors.Is(err, service.ErrNoPortAvailable),
		errors.Is(err, service.ErrCodeInvalid),
		errors.Is(err, service.ErrCodeUsed),
		errors.Is(err, service.ErrCodeExpired),
		errors.Is(err, service.ErrMembershipExpired),
		errors.Is(err, service.ErrRegisterClosed),
		errors.Is(err, service.ErrCaptchaInvalid),
		errors.Is(err, service.ErrEmailRequired),
		errors.Is(err, service.ErrEmailNotAllowed),
		errors.Is(err, service.ErrEmailCodeNeeded),
		errors.Is(err, service.ErrMailDisabled):
		httpx.BadRequest(c, err.Error())

	default:
		log.Printf("[api] %s %s 处理失败: %v", c.Request.Method, c.Request.URL.Path, err)
		httpx.ServerError(c, "服务内部错误，请稍后重试")
	}
}
