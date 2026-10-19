package userapi

import (
	"errors"
	"strconv"

	"github.com/gin-gonic/gin"

	"github.com/xiaoxin-zk/litetunnel/server/internal/httpx"
	"github.com/xiaoxin-zk/litetunnel/server/internal/service"
)

type Handler struct {
	svc *service.Services
}

func New(svc *service.Services) *Handler {
	return &Handler{svc: svc}
}

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
