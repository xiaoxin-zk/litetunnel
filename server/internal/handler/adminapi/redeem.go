package adminapi

import (
	"fmt"
	"strconv"

	"github.com/gin-gonic/gin"

	"github.com/xiaoxin-zk/litetunnel/server/internal/handler/shared"
	"github.com/xiaoxin-zk/litetunnel/server/internal/httpx"
	"github.com/xiaoxin-zk/litetunnel/server/internal/middleware"
	"github.com/xiaoxin-zk/litetunnel/server/internal/service"
)

func (h *Handler) ListRedeemCodes(c *gin.Context) {
	page, pageSize, offset := httpx.Pagination(c)
	list, total, err := h.svc.ListRedeemCodes(c.Query("keyword"), c.Query("status"), c.Query("batch_no"), offset, pageSize)
	if err != nil {
		shared.Fail(c, err)
		return
	}
	httpx.PageOK(c, list, total, page, pageSize)
}

func (h *Handler) GenerateRedeemCodes(c *gin.Context) {
	var in service.GenerateCodesInput
	if err := c.ShouldBindJSON(&in); err != nil {
		httpx.BadRequest(c, "参数格式不正确")
		return
	}
	adminID, _, _ := middleware.CurrentAdminID(c)
	codes, err := h.svc.GenerateCodes(adminID, in)
	if err != nil {
		shared.Fail(c, err)
		return
	}
	plain := make([]string, 0, len(codes))
	for i := range codes {
		plain = append(plain, codes[i].Code)
	}
	h.audit(c, "redeem.generate", "redeem_code", codes[0].BatchNo,
		fmt.Sprintf("生成 %d 个兑换码，类型 %s", len(codes), in.Type))
	httpx.OK(c, gin.H{
		"batch_no": codes[0].BatchNo,
		"count":    len(codes),
		"codes":    plain,
	})
}

func (h *Handler) SetRedeemCodeStatus(c *gin.Context) {
	id, err := parseID(c)
	if err != nil {
		httpx.BadRequest(c, "兑换码 ID 非法")
		return
	}
	var req statusReq
	if err := c.ShouldBindJSON(&req); err != nil {
		httpx.BadRequest(c, "参数格式不正确")
		return
	}
	if err := h.svc.SetRedeemCodeStatus(id, req.Status); err != nil {
		shared.Fail(c, err)
		return
	}
	h.audit(c, "redeem.status", "redeem_code", c.Param("id"), "状态变更为 "+req.Status)
	httpx.OK(c, gin.H{"message": "状态已更新"})
}

func (h *Handler) DeleteRedeemCode(c *gin.Context) {
	id, err := parseID(c)
	if err != nil {
		httpx.BadRequest(c, "兑换码 ID 非法")
		return
	}
	if err := h.svc.DeleteRedeemCode(id); err != nil {
		shared.Fail(c, err)
		return
	}
	h.audit(c, "redeem.delete", "redeem_code", c.Param("id"), "删除兑换码")
	httpx.OK(c, gin.H{"message": "已删除"})
}

func (h *Handler) ListRedeemRecords(c *gin.Context) {
	page, pageSize, offset := httpx.Pagination(c)
	userID, _ := strconv.ParseUint(c.Query("user_id"), 10, 64)
	list, total, err := h.svc.ListRedeemRecords(uint(userID), offset, pageSize)
	if err != nil {
		shared.Fail(c, err)
		return
	}
	httpx.PageOK(c, list, total, page, pageSize)
}
