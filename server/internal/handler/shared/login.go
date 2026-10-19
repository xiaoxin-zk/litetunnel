package shared

import (
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"

	"github.com/xiaoxin-zk/litetunnel/server/internal/service"
)

type CaptchaGate int

const (
	CaptchaGatePass CaptchaGate = iota
	CaptchaGateMissing
	CaptchaGateWrong
)

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

func respondCaptchaRequired(c *gin.Context, message string) {
	c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{
		"code":    http.StatusUnauthorized,
		"message": message,
		"data":    gin.H{"captcha_required": true},
	})
}
