package adminapi

import (
	"context"
	"fmt"
	"net/http"
	"time"

	"github.com/gin-gonic/gin"

	"github.com/xiaoxin-zk/litetunnel/server/internal/handler/shared"
	"github.com/xiaoxin-zk/litetunnel/server/internal/httpx"
	"github.com/xiaoxin-zk/litetunnel/server/internal/service"
)

func (h *Handler) GetSettings(c *gin.Context) {
	httpx.OK(c, h.svc.Settings.AllForAdmin())
}

func (h *Handler) UpdateSettings(c *gin.Context) {
	var raw map[string]string
	if err := c.ShouldBindJSON(&raw); err != nil {
		httpx.BadRequest(c, "参数格式不正确")
		return
	}
	in := make(map[service.SettingKey]string, len(raw))
	for k, v := range raw {
		in[service.SettingKey(k)] = v
	}
	if err := h.svc.UpdateSettings(in); err != nil {
		shared.Fail(c, err)
		return
	}
	h.audit(c, "settings.update", "settings", "", fmt.Sprintf("更新 %d 项系统设置", len(in)))
	httpx.OK(c, gin.H{"message": "已保存，配置即时生效"})
}

type testMailReq struct {
	To string `json:"to" binding:"required"`
}

func (h *Handler) TestMail(c *gin.Context) {
	var req testMailReq
	if err := c.ShouldBindJSON(&req); err != nil {
		httpx.BadRequest(c, "请填写收件地址")
		return
	}
	if !h.svc.MailEnabled() {
		httpx.Fail(c, http.StatusBadRequest, "邮件功能未启用或参数不完整，请先保存配置")
		return
	}

	siteName := h.svc.Settings.Get(service.KeySiteName)
	if siteName == "" {
		siteName = "LiteTunnel"
	}
	body := fmt.Sprintf(`<div style="font-family:-apple-system,'Microsoft YaHei',sans-serif;padding:20px">
  <h2 style="margin:0 0 10px;font-size:17px">%s 邮件配置测试</h2>
  <p style="color:#4b5563;line-height:1.8">
    如果你收到这封邮件，说明 SMTP 配置正确，注册验证码与找回密码功能可以正常使用。
  </p>
  <p style="color:#9ca3af;font-size:12px">发送时间：%s</p>
</div>`, siteName, time.Now().Format("2006-01-02 15:04:05"))

	sendCtx, cancel := context.WithTimeout(c.Request.Context(), service.MailSendTimeout)
	defer cancel()
	if err := h.svc.Mailer().Send(sendCtx, req.To, fmt.Sprintf("【%s】邮件配置测试", siteName), body); err != nil {
		h.audit(c, "settings.test_mail_failed", "settings", "", err.Error())
		httpx.Fail(c, http.StatusBadGateway, "发送失败："+err.Error())
		return
	}
	h.audit(c, "settings.test_mail", "settings", "", "测试收件人 "+req.To)
	httpx.OK(c, gin.H{"message": "测试邮件已发送，请查收"})
}
