package shared

import (
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"

	"github.com/xiaoxin-zk/litetunnel/server/internal/service"
)

// CaptchaGate 描述「账号级人机验证」这一关的结果。
type CaptchaGate int

const (
	// CaptchaGatePass 表示不需要验证码，或验证码已通过，可以继续校验密码。
	CaptchaGatePass CaptchaGate = iota
	// CaptchaGateMissing 表示需要验证码但请求里没带。
	CaptchaGateMissing
	// CaptchaGateWrong 表示带了验证码但不对（或已过期）。
	CaptchaGateWrong
)

// CheckLoginCaptcha 是登录类接口的**账号级**防线。
//
// 与 CheckLoginLock 的分工必须分清，两者缺一不可：
//
//	CheckLoginLock：按「账号 + 来源 IP」计数。它只能挡住单点爆破，
//	                因为分布式来源每个 IP 各拿一份额度；
//	CheckLoginCaptcha：按账号累计失败计数。这正是分布式爆破的唯一克星——
//	                失败次数攒够之后，不给验证码就再也不接受密码校验。
//
// 所以它必须出现在**每一个校验密码的入口**上。漏掉一个，那条路径就是
// 完整的爆破通道：攻击者攒够失败次数后继续在漏掉的那个入口上慢慢猜，
// 而账号级要求对它毫无影响（/api/user/client/auth 就曾经是这样）。
//
// 返回值不是 bool：调用方需要区分「没带验证码」与「验证码错了」——
// 后者要计入一次失败（否则攻击者可以无限刷验证码），前者不必。
// 返回非 Pass 时响应已经写出，调用方直接 return 即可。
func CheckLoginCaptcha(c *gin.Context, svc *service.Services, account, ticket, answer, message string) CaptchaGate {
	if !svc.CaptchaRequired("login", account) {
		return CaptchaGatePass
	}
	if strings.TrimSpace(message) == "" {
		message = "该账号连续登录失败次数较多，请输入验证码后重试"
	}
	if strings.TrimSpace(ticket) == "" {
		respondCaptchaRequired(c, message)
		return CaptchaGateMissing
	}
	if !svc.CheckCaptcha(ticket, answer) {
		respondCaptchaRequired(c, "验证码不正确或已过期，请重新获取")
		return CaptchaGateWrong
	}
	return CaptchaGatePass
}

// respondCaptchaRequired 要求客户端先通过人机验证。
//
// 用 401 + 机器可读标记，而不是 429：
// 429 的语义是「你被限流了，等着」，而这里是「请先证明你是人」。
// 两者前端处理方式完全不同——前者只能等，后者可以立刻重试。
func respondCaptchaRequired(c *gin.Context, message string) {
	c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{
		"code":    http.StatusUnauthorized,
		"message": message,
		"data":    gin.H{"captcha_required": true},
	})
}
