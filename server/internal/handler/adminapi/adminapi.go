package adminapi

import (
	"errors"
	"net/http"
	"strconv"

	"github.com/gin-gonic/gin"

	"github.com/xiaoxin-zk/litetunnel/server/internal/httpx"
	"github.com/xiaoxin-zk/litetunnel/server/internal/middleware"
	"github.com/xiaoxin-zk/litetunnel/server/internal/service"
)

type Handler struct {
	svc *service.Services
}

func New(svc *service.Services) *Handler { return &Handler{svc: svc} }

func (h *Handler) audit(c *gin.Context, action, target, targetID, detail string) error {
	adminID, adminName, _ := middleware.CurrentAdminID(c)
	return h.svc.WriteAudit(adminID, adminName, action, target, targetID, detail, httpx.ClientIP(c))
}

func failWithReason(c *gin.Context, err error) {
	if errors.Is(err, service.ErrInvalidParam) {
		httpx.Fail(c, http.StatusBadRequest, err.Error())
		return
	}
	httpx.Fail(c, http.StatusBadGateway, err.Error())
}

func parseID(c *gin.Context) (uint, error) {
	v, err := strconv.ParseUint(c.Param("id"), 10, 64)
	if err != nil || v == 0 {
		return 0, errors.New("非法 ID")
	}
	return uint(v), nil
}
