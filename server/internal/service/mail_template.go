package service

import (
	"fmt"
	"log"
	"regexp"
	"strings"
	"time"

	"gorm.io/gorm/clause"

	"github.com/xiaoxin-zk/litetunnel/server/internal/model"
)

const (
	MailEventEmailCode     = "email_code"
	MailEventPasswordReset = "password_reset"
	MailEventAlertFiring   = "alert_firing"
	MailEventAlertResolved = "alert_resolved"
	MailEventReportSummary = "report_summary"
)

const (
	mailTemplateSubjectMax = 200
	mailTemplateBodyMax    = 20000
)

// MailEvent 描述一类可自定义的邮件：变量白名单决定模板里能写什么占位符。
type MailEvent struct {
	Event          string   `json:"event"`
	Name           string   `json:"name"`
	Vars           []string `json:"vars"`
	DefaultSubject string   `json:"default_subject"`
	DefaultBody    string   `json:"default_body"`
}

// MailTemplateView 是管理端看到的一条模板：未自定义时回落到内置默认值。
type MailTemplateView struct {
	Event          string     `json:"event"`
	Name           string     `json:"name"`
	Vars           []string   `json:"vars"`
	Subject        string     `json:"subject"`
	Body           string     `json:"body"`
	DefaultSubject string     `json:"default_subject"`
	DefaultBody    string     `json:"default_body"`
	Custom         bool       `json:"custom"`
	UpdatedAt      *time.Time `json:"updated_at"`
}

const emailCodeMailTemplate = `<!doctype html>
<html><body style="margin:0;padding:24px;background:#f5f7fb;font-family:-apple-system,BlinkMacSystemFont,'Segoe UI','Microsoft YaHei',sans-serif;">
  <div style="max-width:520px;margin:0 auto;background:#fff;border-radius:14px;padding:28px;">
    <h2 style="margin:0 0 8px;font-size:18px;color:#1f2937;">邮箱验证码</h2>
    <p style="color:#4b5563;line-height:1.8;margin:0 0 20px;">
      你正在使用 {{site_name}}。请在页面中填写下面的验证码：
    </p>
    <p style="margin:0 0 20px;">
      <span style="display:inline-block;background:#f3f4f6;border-radius:10px;
        padding:14px 26px;font-size:30px;letter-spacing:8px;font-weight:600;
        color:#111827;font-family:ui-monospace,Menlo,Consolas,monospace;">{{code}}</span>
    </p>
    <p style="color:#6b7280;font-size:13px;line-height:1.8;margin:0 0 18px;">
      验证码 {{minutes}} 分钟内有效，且只能使用一次。
    </p>
    <hr style="border:none;border-top:1px solid #eef1f6;margin:18px 0;">
    <p style="color:#9ca3af;font-size:12px;line-height:1.8;margin:0;">
      如果这不是你本人的操作，请忽略本邮件。<br>
      请勿把验证码告诉任何人，包括自称客服的人。
    </p>
  </div>
</body></html>`

const passwordResetMailTemplate = `<!doctype html>
<html><body style="margin:0;padding:24px;background:#f5f7fb;font-family:-apple-system,BlinkMacSystemFont,'Segoe UI','Microsoft YaHei',sans-serif;">
  <div style="max-width:520px;margin:0 auto;background:#fff;border-radius:14px;padding:28px;">
    <h2 style="margin:0 0 8px;font-size:18px;color:#1f2937;">重置登录密码</h2>
    <p style="color:#4b5563;line-height:1.8;margin:0 0 18px;">
      你好 {{username}}，我们收到了 {{site_name}} 的密码重置请求。<br>
      点击下面的按钮设置新密码，链接 {{minutes}} 分钟内有效。
    </p>
    <p style="margin:0 0 22px;">
      <a href="{{link}}" style="display:inline-block;background:#2563eb;color:#fff;text-decoration:none;
         padding:11px 22px;border-radius:9px;font-weight:500;">设置新密码</a>
    </p>
    <p style="color:#6b7280;font-size:13px;line-height:1.8;margin:0 0 14px;">
      按钮无法点击时，请复制下面的链接到浏览器打开：
    </p>
    <p style="word-break:break-all;color:#2563eb;font-size:13px;margin:0 0 18px;">{{link}}</p>
    <hr style="border:none;border-top:1px solid #eef1f6;margin:18px 0;">
    <p style="color:#9ca3af;font-size:12px;line-height:1.8;margin:0;">
      如果这不是你本人的操作，请忽略本邮件，你的密码不会发生变化。<br>
      为保障账号安全，重置成功后所有已登录设备都将下线。
    </p>
  </div>
</body></html>`

const alertFiringMailTemplate = `<!doctype html>
<html><body style="margin:0;padding:24px;background:#f5f7fb;font-family:-apple-system,BlinkMacSystemFont,'Segoe UI','Microsoft YaHei',sans-serif;">
  <div style="max-width:560px;margin:0 auto;background:#fff;border-radius:14px;padding:28px;">
    <h2 style="margin:0 0 8px;font-size:18px;color:#b91c1c;">{{level_label}}：{{kind_label}}</h2>
    <p style="color:#4b5563;line-height:1.8;margin:0 0 16px;">{{message}}</p>
    <p style="color:#6b7280;font-size:13px;line-height:1.8;margin:0 0 16px;">
      当前值 <b>{{value}}</b>，阈值 <b>{{threshold}}</b>；首次触发 {{fired_at}}。
    </p>
    <hr style="border:none;border-top:1px solid #eef1f6;margin:18px 0;">
    <p style="color:#9ca3af;font-size:12px;line-height:1.8;margin:0;">
      来自 {{site_name}} 的告警通知。问题恢复后会再发一封「已恢复」；<br>
      同一事件每 30 分钟提醒一次，可在管理端「告警与监控」中处理或静默。
    </p>
  </div>
</body></html>`

const alertResolvedMailTemplate = `<!doctype html>
<html><body style="margin:0;padding:24px;background:#f5f7fb;font-family:-apple-system,BlinkMacSystemFont,'Segoe UI','Microsoft YaHei',sans-serif;">
  <div style="max-width:560px;margin:0 auto;background:#fff;border-radius:14px;padding:28px;">
    <h2 style="margin:0 0 8px;font-size:18px;color:#15803d;">已恢复：{{kind_label}}</h2>
    <p style="color:#4b5563;line-height:1.8;margin:0 0 16px;">{{message}}</p>
    <p style="color:#6b7280;font-size:13px;line-height:1.8;margin:0 0 16px;">
      触发于 {{fired_at}}，恢复于 {{resolved_at}}，持续 {{duration}}。
    </p>
    <hr style="border:none;border-top:1px solid #eef1f6;margin:18px 0;">
    <p style="color:#9ca3af;font-size:12px;line-height:1.8;margin:0;">来自 {{site_name}} 的告警恢复通知。</p>
  </div>
</body></html>`

const reportSummaryMailTemplate = `<!doctype html>
<html><body style="margin:0;padding:24px;background:#f5f7fb;font-family:-apple-system,BlinkMacSystemFont,'Segoe UI','Microsoft YaHei',sans-serif;">
  <div style="max-width:600px;margin:0 auto;background:#fff;border-radius:14px;padding:28px;">
    <h2 style="margin:0 0 6px;font-size:18px;color:#1f2937;">{{report_name}}</h2>
    <p style="color:#9ca3af;font-size:12px;margin:0 0 18px;">统计区间 {{period}} · 生成于 {{generated_at}}</p>
    <table style="width:100%;border-collapse:collapse;font-size:13px;color:#374151;">
      <tr><td style="padding:6px 0;">用户</td><td style="padding:6px 0;text-align:right;">{{users_total}}（新增 {{users_new}}）</td></tr>
      <tr><td style="padding:6px 0;">隧道</td><td style="padding:6px 0;text-align:right;">{{tunnels_total}}（在线 {{tunnels_online}}）</td></tr>
      <tr><td style="padding:6px 0;">流量</td><td style="padding:6px 0;text-align:right;">{{traffic}}</td></tr>
      <tr><td style="padding:6px 0;">平均错误率</td><td style="padding:6px 0;text-align:right;">{{error_rate}}%</td></tr>
      <tr><td style="padding:6px 0;">磁盘使用率</td><td style="padding:6px 0;text-align:right;">{{disk}}%</td></tr>
      <tr><td style="padding:6px 0;">最近备份</td><td style="padding:6px 0;text-align:right;">{{last_backup}}</td></tr>
    </table>
    <hr style="border:none;border-top:1px solid #eef1f6;margin:18px 0;">
    <p style="color:#374151;font-size:13px;margin:0 0 10px;">
      本期新增告警 {{alerts_firing}} 条，恢复 {{alerts_resolved}} 条。
    </p>
    <ul style="margin:0;padding-left:18px;color:#4b5563;font-size:13px;line-height:1.9;">{{alert_lines}}</ul>
    <hr style="border:none;border-top:1px solid #eef1f6;margin:18px 0;">
    <p style="color:#9ca3af;font-size:12px;line-height:1.8;margin:0;">来自 {{site_name}} 的运维摘要。可在管理端「告警与监控」中调整发送频率。</p>
  </div>
</body></html>`

var mailEvents = []MailEvent{
	{
		Event:          MailEventEmailCode,
		Name:           "邮箱验证码",
		Vars:           []string{"site_name", "code", "minutes", "email"},
		DefaultSubject: "【{{site_name}}】邮箱验证码",
		DefaultBody:    emailCodeMailTemplate,
	},
	{
		Event:          MailEventPasswordReset,
		Name:           "重置登录密码",
		Vars:           []string{"site_name", "username", "link", "minutes", "email"},
		DefaultSubject: "【{{site_name}}】重置登录密码",
		DefaultBody:    passwordResetMailTemplate,
	},
	{
		Event:          MailEventAlertFiring,
		Name:           "告警通知",
		Vars:           []string{"site_name", "kind_label", "level_label", "message", "value", "threshold", "fired_at"},
		DefaultSubject: "【{{site_name}}】{{level_label}}：{{kind_label}}",
		DefaultBody:    alertFiringMailTemplate,
	},
	{
		Event:          MailEventAlertResolved,
		Name:           "告警恢复通知",
		Vars:           []string{"site_name", "kind_label", "message", "fired_at", "resolved_at", "duration"},
		DefaultSubject: "【{{site_name}}】已恢复：{{kind_label}}",
		DefaultBody:    alertResolvedMailTemplate,
	},
	{
		Event: MailEventReportSummary,
		Name:  "运维摘要（日报/周报）",
		Vars: []string{
			"site_name", "report_name", "period", "generated_at",
			"users_total", "users_new", "tunnels_total", "tunnels_online",
			"traffic", "error_rate", "disk", "last_backup",
			"alerts_firing", "alerts_resolved", "alert_lines",
		},
		DefaultSubject: "【{{site_name}}】{{report_name}}（{{period}}）",
		DefaultBody:    reportSummaryMailTemplate,
	},
}

func mailEventSpec(event string) (MailEvent, bool) {
	for _, e := range mailEvents {
		if e.Event == event {
			return e, true
		}
	}
	return MailEvent{}, false
}

var mailPlaceholder = regexp.MustCompile(`\{\{\s*([a-zA-Z][a-zA-Z0-9_]*)\s*\}\}`)

// renderMailText 做占位符替换。变量必须在事件白名单内，否则报错交由调用方回退默认模板，
// 避免管理员写错的模板把验证码邮件直接卡死。
func renderMailText(tpl string, spec MailEvent, vars map[string]string) (string, error) {
	allowed := make(map[string]bool, len(spec.Vars))
	for _, v := range spec.Vars {
		allowed[v] = true
	}
	var bad []string
	out := mailPlaceholder.ReplaceAllStringFunc(strings.TrimSpace(tpl), func(m string) string {
		name := mailPlaceholder.FindStringSubmatch(m)[1]
		if !allowed[name] {
			bad = append(bad, name)
			return m
		}
		return vars[name]
	})
	if len(bad) > 0 {
		return "", fmt.Errorf("模板包含未知变量 %s，仅支持 %s",
			strings.Join(bad, "、"), strings.Join(spec.Vars, "、"))
	}
	return out, nil
}

// ListMailTemplates 返回全部事件及其当前生效的模板（含内置默认值）。
func (s *Services) ListMailTemplates() ([]MailTemplateView, error) {
	var rows []model.MailTemplate
	if err := s.DB.Find(&rows).Error; err != nil {
		return nil, err
	}
	stored := make(map[string]model.MailTemplate, len(rows))
	for _, r := range rows {
		stored[r.Event] = r
	}

	views := make([]MailTemplateView, 0, len(mailEvents))
	for _, e := range mailEvents {
		v := MailTemplateView{
			Event: e.Event, Name: e.Name, Vars: e.Vars,
			Subject: e.DefaultSubject, Body: e.DefaultBody,
			DefaultSubject: e.DefaultSubject, DefaultBody: e.DefaultBody,
		}
		if r, ok := stored[e.Event]; ok && r.Subject != "" && r.Body != "" {
			v.Subject, v.Body, v.Custom = r.Subject, r.Body, true
			updated := r.UpdatedAt
			v.UpdatedAt = &updated
		}
		views = append(views, v)
	}
	return views, nil
}

// SaveMailTemplate 校验并保存自定义模板；变量越界、长度超限一律拒绝。
func (s *Services) SaveMailTemplate(event, subject, body string) error {
	spec, ok := mailEventSpec(event)
	if !ok {
		return fmt.Errorf("%w: 未知的邮件类型 %s", ErrInvalidParam, event)
	}
	subject = strings.TrimSpace(subject)
	body = strings.TrimSpace(body)
	if subject == "" || body == "" {
		return fmt.Errorf("%w: 邮件标题与正文都不能为空", ErrInvalidParam)
	}
	if len([]rune(subject)) > mailTemplateSubjectMax {
		return fmt.Errorf("%w: 邮件标题不能超过 %d 字", ErrInvalidParam, mailTemplateSubjectMax)
	}
	if len(body) > mailTemplateBodyMax {
		return fmt.Errorf("%w: 邮件正文不能超过 %d 字节", ErrInvalidParam, mailTemplateBodyMax)
	}
	for _, tpl := range []string{subject, body} {
		if _, err := renderMailText(tpl, spec, sampleMailVars()); err != nil {
			return fmt.Errorf("%w: %s", ErrInvalidParam, err.Error())
		}
	}

	row := model.MailTemplate{Event: event, Subject: subject, Body: body}
	return s.DB.Clauses(clause.OnConflict{
		Columns:   []clause.Column{{Name: "event"}},
		DoUpdates: clause.AssignmentColumns([]string{"subject", "body", "updated_at"}),
	}).Create(&row).Error
}

// ResetMailTemplate 删除自定义模板，恢复内置默认。
func (s *Services) ResetMailTemplate(event string) error {
	if _, ok := mailEventSpec(event); !ok {
		return fmt.Errorf("%w: 未知的邮件类型 %s", ErrInvalidParam, event)
	}
	return s.DB.Where("event = ?", event).Delete(&model.MailTemplate{}).Error
}

// PreviewMailTemplate 用示例变量渲染，供管理端保存前预览。
func (s *Services) PreviewMailTemplate(event, subject, body string) (string, string, error) {
	spec, ok := mailEventSpec(event)
	if !ok {
		return "", "", fmt.Errorf("%w: 未知的邮件类型 %s", ErrInvalidParam, event)
	}
	vars := sampleMailVars()
	if strings.TrimSpace(subject) == "" {
		subject = spec.DefaultSubject
	}
	if strings.TrimSpace(body) == "" {
		body = spec.DefaultBody
	}
	sub, err := renderMailText(subject, spec, vars)
	if err != nil {
		return "", "", fmt.Errorf("%w: 邮件标题 %s", ErrInvalidParam, err.Error())
	}
	html, err := renderMailText(body, spec, vars)
	if err != nil {
		return "", "", fmt.Errorf("%w: 邮件正文 %s", ErrInvalidParam, err.Error())
	}
	return sub, html, nil
}

// renderMail 返回实际发送用的标题与正文：优先自定义模板，渲染失败或未配置时回退内置模板。
func (s *Services) renderMail(event string, vars map[string]string) (string, string) {
	spec, ok := mailEventSpec(event)
	if !ok {
		return "", ""
	}
	subject, body := spec.DefaultSubject, spec.DefaultBody

	var row model.MailTemplate
	err := s.DB.Where("event = ?", event).Take(&row).Error
	if err == nil && row.Subject != "" && row.Body != "" {
		sub, serr := renderMailText(row.Subject, spec, vars)
		html, berr := renderMailText(row.Body, spec, vars)
		if serr == nil && berr == nil {
			return sub, html
		}
		log.Printf("[mail] 自定义模板 %s 渲染失败，已回退内置模板: %v %v", event, serr, berr)
	}

	sub, serr := renderMailText(subject, spec, vars)
	html, berr := renderMailText(body, spec, vars)
	if serr != nil || berr != nil {
		log.Printf("[mail] 内置模板 %s 渲染异常: %v %v", event, serr, berr)
	}
	return sub, html
}

func sampleMailVars() map[string]string {
	return map[string]string{
		"site_name": "LiteTunnel",
		"code":      "123456",
		"minutes":   "10",
		"username":  "demo",
		"link":      "https://panel.example.com/reset-password?token=example",
		"email":     "demo@example.com",

		"kind_label":  "磁盘水位",
		"level_label": "严重",
		"message":     "磁盘使用率 95.0%（阈值 90%）",
		"value":       "95.0",
		"threshold":   "90",
		"fired_at":    "2026-10-20 10:00:00",
		"resolved_at": "2026-10-20 12:15:00",
		"duration":    "2 小时 15 分",

		"report_name":     "日报",
		"period":          "2026-10-19 09:00 ~ 2026-10-20 09:00",
		"generated_at":    "2026-10-20 09:00:05",
		"users_total":     "12",
		"users_new":       "1",
		"tunnels_total":   "8",
		"tunnels_online":  "6",
		"traffic":         "3.2 GB",
		"error_rate":      "0.4",
		"disk":            "62.5",
		"last_backup":     "6 小时前",
		"alerts_firing":   "1",
		"alerts_resolved": "2",
		"alert_lines":     "<li>严重 · 磁盘水位：磁盘使用率 95.0%</li>",
	}
}
