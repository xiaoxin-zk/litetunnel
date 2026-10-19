package adminapi

import (
	"github.com/gin-gonic/gin"

	"github.com/xiaoxin-zk/litetunnel/server/internal/handler/shared"
	"github.com/xiaoxin-zk/litetunnel/server/internal/httpx"
)

func (h *Handler) ListMailTemplates(c *gin.Context) {
	items, err := h.svc.ListMailTemplates()
	if err != nil {
		shared.Fail(c, err)
		return
	}
	httpx.OK(c, items)
}

type mailTemplateReq struct {
	Subject string `json:"subject"`
	Body    string `json:"body"`
}

func (h *Handler) SaveMailTemplate(c *gin.Context) {
	event := c.Param("event")
	var req mailTemplateReq
	if err := c.ShouldBindJSON(&req); err != nil {
		httpx.BadRequest(c, "参数格式不正确")
		return
	}
	if err := h.svc.SaveMailTemplate(event, req.Subject, req.Body); err != nil {
		shared.Fail(c, err)
		return
	}
	h.audit(c, "mail_template.update", "mail_template", event, "更新邮件模板")
	httpx.OK(c, gin.H{"message": "已保存，下一次发信即生效"})
}

func (h *Handler) ResetMailTemplate(c *gin.Context) {
	event := c.Param("event")
	if err := h.svc.ResetMailTemplate(event); err != nil {
		shared.Fail(c, err)
		return
	}
	h.audit(c, "mail_template.reset", "mail_template", event, "恢复内置默认模板")
	httpx.OK(c, gin.H{"message": "已恢复内置默认模板"})
}

func (h *Handler) PreviewMailTemplate(c *gin.Context) {
	event := c.Param("event")
	var req mailTemplateReq
	if err := c.ShouldBindJSON(&req); err != nil {
		httpx.BadRequest(c, "参数格式不正确")
		return
	}
	subject, body, err := h.svc.PreviewMailTemplate(event, req.Subject, req.Body)
	if err != nil {
		shared.Fail(c, err)
		return
	}
	httpx.OK(c, gin.H{"subject": subject, "body": body})
}
