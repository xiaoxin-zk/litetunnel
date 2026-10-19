package adminapi

import (
	"errors"
	"fmt"
	"io"
	"strings"

	"github.com/gin-gonic/gin"

	"github.com/xiaoxin-zk/litetunnel/server/internal/httpx"
)

func (h *Handler) DomainStatus(c *gin.Context) {
	httpx.OK(c, h.svc.DomainStatus())
}

func (h *Handler) DomainApply(c *gin.Context) {
	var req struct {
		Apply *bool `json:"apply"`
	}
	if c.Request.Body != nil {
		if err := c.ShouldBindJSON(&req); err != nil && !errors.Is(err, io.EOF) {
			httpx.BadRequest(c, "请求体不是合法 JSON")
			return
		}
	}
	apply := true
	if req.Apply != nil {
		apply = *req.Apply
	}

	res, err := h.svc.ApplyDomainConfig(c.Request.Context(), apply)
	if err != nil {
		h.audit(c, "domain.apply_failed", "domain", "", err.Error())
		failWithReason(c, err)
		return
	}
	h.audit(c, "domain.apply", "domain", "",
		fmt.Sprintf("下发域名与证书配置（变化文件：%s）", strings.Join(res.Changed, ", ")))
	httpx.OK(c, res)
}

func (h *Handler) DomainDNSCheck(c *gin.Context) {
	records, err := h.svc.DomainDNSCheck(c.Request.Context())
	if err != nil {
		failWithReason(c, err)
		return
	}
	httpx.OK(c, gin.H{"records": records})
}
