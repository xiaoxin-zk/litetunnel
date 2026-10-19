package service

import (
	"encoding/base64"
	"errors"
	"strings"
	"testing"
)

func svgDataURL(body string) string {
	return siteSVGPrefix + base64.StdEncoding.EncodeToString([]byte(body))
}

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
		{
			"svg 静态图",
			svgDataURL(`<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 10 10"><rect width="10" height="10"/></svg>`),
			true,
		},
		{"svg 内联脚本", svgDataURL(`<svg xmlns="http://www.w3.org/2000/svg"><script>alert(1)</script></svg>`), false},
		{"svg 事件属性", svgDataURL(`<svg xmlns="http://www.w3.org/2000/svg" onload="alert(1)"></svg>`), false},
		{"svg foreignObject", svgDataURL(`<svg xmlns="http://www.w3.org/2000/svg"><foreignObject><body/></foreignObject></svg>`), false},
		{"svg 外链引用", svgDataURL(`<svg xmlns="http://www.w3.org/2000/svg"><image href="https://evil.example/x.png"/></svg>`), false},
		{"svg 实体声明", svgDataURL(`<!DOCTYPE svg [<!ENTITY x "y">]><svg>&x;</svg>`), false},
		{"svg 非法 base64", siteSVGPrefix + "!!!not-base64!!!", false},
		{"非图片", "data:text/html;base64,PGI+", false},
		{"超限", "data:image/png;base64," + strings.Repeat("A", siteLogoDataURLMax), false},
		{"svg 超限", svgDataURL(strings.Repeat("<svg></svg>", siteSVGSourceMax/11+10)), false},
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

func TestSettingsCanBeCleared(t *testing.T) {
	svc := newTestServices(t, nil)

	if err := svc.UpdateSettings(map[SettingKey]string{
		KeySiteLogo: "data:image/png;base64,iVBORw0KGgo=",
	}); err != nil {
		t.Fatalf("设置 Logo 失败: %v", err)
	}
	if svc.Settings.Get(KeySiteLogo) == "" {
		t.Fatal("Logo 应已保存")
	}

	if err := svc.UpdateSettings(map[SettingKey]string{KeySiteLogo: ""}); err != nil {
		t.Fatalf("清空 Logo 失败: %v", err)
	}
	if got := svc.Settings.Get(KeySiteLogo); got != "" {
		t.Fatalf("清空后不该残留旧值，实际 %q", got)
	}

	if err := svc.UpdateSettings(map[SettingKey]string{KeyIPBlacklist: "10.0.0.0/8"}); err != nil {
		t.Fatalf("设置黑名单失败: %v", err)
	}
	if err := svc.UpdateSettings(map[SettingKey]string{KeyIPBlacklist: ""}); err != nil {
		t.Fatalf("清空黑名单失败: %v", err)
	}
	if got := svc.Settings.Get(KeyIPBlacklist); got != "" {
		t.Fatalf("黑名单清空后不该残留，实际 %q", got)
	}
	if len(svc.BlockedPrefixes()) != 0 {
		t.Fatal("黑名单清空后不应继续拦截")
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
