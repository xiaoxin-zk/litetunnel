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
	}
}
