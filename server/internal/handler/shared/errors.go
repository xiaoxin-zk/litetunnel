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

// CheckLoginLock 检查「账号 + 来源 IP」是否处于登录锁定期。
//
// 维度选择说明：锁定按账号与 IP 的组合计数，而不是单纯按账号。
// 纯账号维度会变成一个廉价的拒绝服务——攻击者知道管理员用户名后，
// 每隔一段时间发几次错误密码就能让管理员永远登不进来。
// 组合维度下攻击者只能锁住自己那个 IP，而分布式爆破由验证码兜底。
//
// 返回 false 时已写出响应，调用方直接 return。
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

// LoginFailed 记录一次登录失败。
func LoginFailed(g *middleware.LoginGuard, scope, account, ip string) {
	g.Fail(scope, account, ip)
}

// LoginSucceeded 清除该账号在当前 IP 下的失败记录。
func LoginSucceeded(g *middleware.LoginGuard, scope, account, ip string) {
	g.Reset(scope, account, ip)
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

	// 校验本身没法完成（例如失败次数写不进库）：这是服务端的问题，不是
	// 「你填错了」，用 503 让客户端知道可以稍后重试。
	case errors.Is(err, service.ErrEmailCodeCheckFailed):
		httpx.Fail(c, http.StatusServiceUnavailable, err.Error())

	case errors.Is(err, service.ErrBadCredentials),
		errors.Is(err, service.ErrAccountDisabled):
		httpx.Unauthorized(c, err.Error())

	// 认证类失败：双因素与验证码都算「你没通过验证」，用 401 更贴切。
	// 漏掉映射的话这些会掉进 default 分支变成 500「服务内部错误」，
	// 用户看到的是系统故障而不是「验证码填错了」。
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

	// 限流类：这类提示必须明确告知「稍后再试」，
	// 混进 400 会让用户以为是自己填错了。
	case errors.Is(err, service.ErrEmailCodeTooSoon),
		errors.Is(err, service.ErrEmailCodeTooMany),
		errors.Is(err, service.ErrEmailCodeAttempts),
		errors.Is(err, service.ErrRegisterLimited),
		errors.Is(err, service.ErrDomainRegisterLimited),
		// 队列满属于「过一会儿再来」，不是用户填错了。
		errors.Is(err, service.ErrMailQueueFull):
		httpx.Fail(c, http.StatusTooManyRequests, err.Error())

	case errors.Is(err, service.ErrQuotaExceeded),
		errors.Is(err, service.ErrTunnelLimit),
		errors.Is(err, service.ErrPortLimit),
		errors.Is(err, service.ErrProtocolDenied),
		errors.Is(err, service.ErrDomainDenied),
		errors.Is(err, service.ErrCodeDisabled),
		errors.Is(err, service.ErrDomainNotTrusted):
		httpx.Forbidden(c, err.Error())

	case errors.Is(err, service.ErrInvalidParam),
		// 这类「选了但本站没有对应能力」的提示要原样返回前端：
		// 换成笼统的错误，用户只会反复重试同一个选项。
		errors.Is(err, service.ErrNoHTTPSProxyEntry),
		errors.Is(err, service.ErrPortInUse),
		errors.Is(err, service.ErrNoPortAvailable),
		errors.Is(err, service.ErrCodeInvalid),
		errors.Is(err, service.ErrCodeUsed),
		errors.Is(err, service.ErrCodeExpired),
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
