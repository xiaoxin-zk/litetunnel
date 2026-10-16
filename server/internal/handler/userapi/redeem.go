package userapi

import (
	"github.com/gin-gonic/gin"

	"github.com/xiaoxin-zk/litetunnel/server/internal/handler/shared"
	"github.com/xiaoxin-zk/litetunnel/server/internal/httpx"
	"github.com/xiaoxin-zk/litetunnel/server/internal/middleware"
)

type redeemReq struct {
	Code string `json:"code" binding:"required"`
}

// Redeem 兑换码核销。
func (h *Handler) Redeem(c *gin.Context) {
	var req redeemReq
	if err := c.ShouldBindJSON(&req); err != nil {
		httpx.BadRequest(c, "请输入兑换码")
		return
	}
	res, err := h.svc.Redeem(middleware.CurrentUserID(c), req.Code, httpx.ClientIP(c))
	if err != nil {
		shared.Fail(c, err)
		return
	}
	httpx.OK(c, res)
}

// RedeemRecords 我的兑换记录。
func (h *Handler) RedeemRecords(c *gin.Context) {
	page, pageSize, offset := httpx.Pagination(c)
	list, total, err := h.svc.ListRedeemRecords(middleware.CurrentUserID(c), offset, pageSize)
	if err != nil {
		shared.Fail(c, err)
		return
	}
	httpx.PageOK(c, list, total, page, pageSize)
}
