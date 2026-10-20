package main

import "strings"

var buildServerURL = ""

var buildVersion = "dev"

// Version 返回纯版本号（不带 v 前缀）。CI 注入的是 tag 原文（v1.2.3），
// 界面统一自己加 v 展示；这里不去前缀就会出现 vv1.2.3。
func Version() string {
	v := strings.TrimPrefix(strings.TrimSpace(buildVersion), "v")
	if v != "" {
		return v
	}
	return "dev"
}

func defaultServerURL() string {
	return strings.TrimRight(strings.TrimSpace(buildServerURL), "/")
}

func serverFixed() bool {
	return defaultServerURL() != ""
}
