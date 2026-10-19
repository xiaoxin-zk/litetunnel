package service

import (
	"errors"
	"strings"
	"testing"
)

func TestSiteLogoValidation(t *testing.T) {
	svc := newTestServices(t, nil)

	cases := []struct {
		name string
		logo string
		ok   bool
	}{
		{"png data URL", "data:image/png;base64,iVBORw0KGgo=", true},
		{"webp data URL", "data:image/webp;base64,UklGRg==", true},
		{"外链", "https://cdn.example.com/logo.png", false},
		{"svg", "data:image/svg+xml;base64,PHN2Zz48L3N2Zz4=", false},
		{"非图片", "data:text/html;base64,PGI+", false},
		{"超限", "data:image/png;base64," + strings.Repeat("A", siteLogoDataURLMax), false},
	}
	for _, c := range cases {
		err := svc.UpdateSettings(map[SettingKey]string{KeySiteLogo: c.logo})
		if c.ok && err != nil {
			t.Fatalf("%s 应允许保存，实际 %v", c.name, err)
		}
		if !c.ok && !errors.Is(err, ErrInvalidParam) {
			t.Fatalf("%s 应被拒绝，实际 %v", c.name, err)
		}
	}
}

func TestSiteSubtitleAndHomeContentLimits(t *testing.T) {
	svc := newTestServices(t, nil)

	if err := svc.UpdateSettings(map[SettingKey]string{
		KeySiteSubtitle:    "内网穿透控制台",
		KeySiteHomeContent: "## 欢迎\n\n这里可以放部署说明",
	}); err != nil {
		t.Fatalf("正常内容应保存成功: %v", err)
	}
	if got := svc.Settings.Get(KeySiteSubtitle); got != "内网穿透控制台" {
		t.Fatalf("副标题未生效，实际 %q", got)
	}

	if err := svc.UpdateSettings(map[SettingKey]string{
		KeySiteSubtitle: strings.Repeat("长", siteSubtitleMax+1),
	}); !errors.Is(err, ErrInvalidParam) {
		t.Fatalf("超长副标题应被拒绝，实际 %v", err)
	}
	if err := svc.UpdateSettings(map[SettingKey]string{
		KeySiteHomeContent: strings.Repeat("a", siteHomeContentMax+1),
	}); !errors.Is(err, ErrInvalidParam) {
		t.Fatalf("超长首页内容应被拒绝，实际 %v", err)
	}
}
