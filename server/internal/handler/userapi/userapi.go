// Package userapi 实现用户控制台 API。
//
// 该包只注册在「用户侧监听地址」上，与管理后台在物理端口上隔离：
// 即使管理路由被误注册，也无法从公网端口访问。

package userapi

import (
	"errors"
	"strconv"

	"github.com/gin-gonic/gin"

	"github.com/xiaoxin-zk/litetunnel/server/internal/httpx"
	"github.com/xiaoxin-zk/litetunnel/server/internal/service"
)

// Handler 用户控制台处理器。
type Handler struct {
	svc *service.Services
}

// New 构造处理器。
//
// 登录锁来自 Services（全站唯一一份），本包不再自建：每个入口各持一份
// 计数，等于给攻击者多份额度——在网页端撞几次、再换客户端接口撞几次，
// 两边都不触发锁定。详见 Services.LoginGuard 与 shared.CheckLoginCaptcha。
func New(svc *service.Services) *Handler {
	return &Handler{svc: svc}
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
