// Package userapi 实现用户控制台 API。
//
// 该包只注册在「用户侧监听地址」上，与管理后台在物理端口上隔离：
// 即使管理路由被误注册，也无法从公网端口访问。

package userapi

import (
	"errors"
	"strconv"
	"time"

	"github.com/gin-gonic/gin"

	"github.com/xiaoxin-zk/litetunnel/server/internal/httpx"
	"github.com/xiaoxin-zk/litetunnel/server/internal/middleware"
	"github.com/xiaoxin-zk/litetunnel/server/internal/service"
)

// Handler 用户控制台处理器。
type Handler struct {
	svc *service.Services
	// guard 按账号维度锁定连续登录失败，抵御代理池对单一账号的慢速爆破。
	guard *middleware.LoginGuard
}

// New 构造处理器。
func New(svc *service.Services) *Handler {
	return &Handler{
		svc: svc,
		// 连续失败 5 次开始锁定，首次 15 分钟，之后逐次翻倍，上限 24 小时。
		guard: middleware.NewLoginGuard(5, 15*time.Minute, 24*time.Hour),
	}
}

// recordLogin 写入登录日志，自动补齐 IP 与 UA。
func (h *Handler) recordLogin(c *gin.Context, a service.LoginAttempt) {
	a.IP = httpx.ClientIP(c)
	a.UserAgent = c.GetHeader("User-Agent")
	h.svc.RecordLogin(a)
}

func parseID(c *gin.Context) (uint, error) {
	v, err := strconv.ParseUint(c.Param("id"), 10, 64)
	if err != nil || v == 0 {
		return 0, errors.New("非法 ID")
	}
	return uint(v), nil
}
