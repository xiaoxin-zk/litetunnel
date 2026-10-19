package service

import (
	"errors"
	"strings"
	"testing"
)

func TestMailTemplateRenderFallback(t *testing.T) {
	svc := newTestServices(t, nil)

	subject, body := svc.renderMail(MailEventEmailCode, map[string]string{
		"site_name": "内网穿透", "code": "654321", "minutes": "10", "email": "a@b.com",
	})
	if !strings.Contains(subject, "内网穿透") {
		t.Fatalf("默认标题应包含站点名，实际 %q", subject)
	}
	if !strings.Contains(body, "654321") || !strings.Contains(body, "10") {
		t.Fatalf("默认正文应渲染验证码与有效期")
	}
	if strings.Contains(body, "{{") {
		t.Fatalf("渲染后不该残留占位符: %s", body)
	}

	subject, body = svc.renderMail(MailEventPasswordReset, map[string]string{
		"site_name": "内网穿透", "username": "alice",
		"link": "https://panel.example.com/reset-password?token=abc", "minutes": "30",
	})
	if !strings.Contains(subject, "重置登录密码") {
		t.Fatalf("默认主题应是重置登录密码，实际 %q", subject)
	}
	if !strings.Contains(body, "alice") || !strings.Contains(body, "token=abc") {
		t.Fatalf("默认正文应渲染用户名与链接")
	}
}

func TestSaveMailTemplateValidatesPlaceholders(t *testing.T) {
	svc := newTestServices(t, nil)

	if err := svc.SaveMailTemplate(MailEventEmailCode, "主题", "验证码是 {{code}}，{{admin_password}} 不该可用"); !errors.Is(err, ErrInvalidParam) {
		t.Fatalf("未知变量应被拒绝，实际 %v", err)
	}
	if err := svc.SaveMailTemplate("no_such_event", "主题", "正文"); !errors.Is(err, ErrInvalidParam) {
		t.Fatalf("未知事件应被拒绝，实际 %v", err)
	}
	if err := svc.SaveMailTemplate(MailEventEmailCode, "  ", "正文"); !errors.Is(err, ErrInvalidParam) {
		t.Fatalf("空标题应被拒绝，实际 %v", err)
	}
	if err := svc.SaveMailTemplate(MailEventEmailCode, "【{{site_name}}】验证码", "你的验证码：{{code}}"); err != nil {
		t.Fatalf("合法模板应保存成功: %v", err)
	}
}

func TestCustomMailTemplateTakesEffectAndResets(t *testing.T) {
	svc := newTestServices(t, nil)

	if err := svc.SaveMailTemplate(MailEventEmailCode,
		"【{{site_name}}】自定义验证码", "<p>自定义模板 {{code}}</p>"); err != nil {
		t.Fatalf("保存模板失败: %v", err)
	}

	subject, body := svc.renderMail(MailEventEmailCode, map[string]string{
		"site_name": "LT", "code": "111111", "minutes": "10", "email": "a@b.com",
	})
	if subject != "【LT】自定义验证码" {
		t.Fatalf("应使用自定义标题，实际 %q", subject)
	}
	if body != "<p>自定义模板 111111</p>" {
		t.Fatalf("应使用自定义正文，实际 %q", body)
	}

	items, err := svc.ListMailTemplates()
	if err != nil {
		t.Fatalf("读取模板失败: %v", err)
	}
	for _, it := range items {
		if it.Event == MailEventEmailCode && !it.Custom {
			t.Fatal("已保存的自定义模板应标记为 custom")
		}
	}

	if err := svc.ResetMailTemplate(MailEventEmailCode); err != nil {
		t.Fatalf("恢复默认失败: %v", err)
	}
	_, body = svc.renderMail(MailEventEmailCode, map[string]string{
		"site_name": "LT", "code": "222222", "minutes": "10", "email": "a@b.com",
	})
	if strings.Contains(body, "自定义模板") {
		t.Fatalf("恢复默认后应回到内置模板，实际 %q", body)
	}
	if !strings.Contains(body, "222222") {
		t.Fatalf("内置模板应正常渲染验证码")
	}
}

func TestPreviewMailTemplate(t *testing.T) {
	svc := newTestServices(t, nil)

	subject, body, err := svc.PreviewMailTemplate(MailEventPasswordReset, "", "")
	if err != nil {
		t.Fatalf("空内容预览应回落到默认模板: %v", err)
	}
	if !strings.Contains(subject, "LiteTunnel") || !strings.Contains(body, "demo") {
		t.Fatalf("预览应使用示例变量渲染，实际主题 %q", subject)
	}

	if _, _, err := svc.PreviewMailTemplate(MailEventPasswordReset, "主题", "{{nope}}"); !errors.Is(err, ErrInvalidParam) {
		t.Fatalf("预览也应拒绝未知变量，实际 %v", err)
	}
}
