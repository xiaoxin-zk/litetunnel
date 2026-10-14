package main

import "strings"

// buildServerURL 是构建时注入的平台地址，例如 https://panel.example.com。
//
// 注入方式：
//
//	go build -ldflags "-X main.buildServerURL=https://panel.example.com"
//
// 为什么要注入而不是让用户填：
//  1. 这个客户端本来就是为特定平台构建的，地址是固定的；
//  2. 用户少填一个字段，接入步骤从「地址 + 账号 + 密码」变成「粘贴一个 Key」；
//  3. 源码里不出现任何真实地址，符合「不在源码暴露公网信息」的要求。
//
// 留空时（本地调试构建）界面会显示地址输入框作为兜底。
var buildServerURL = ""

// defaultServerURL 返回构建时注入的地址，已去掉结尾斜杠。
func defaultServerURL() string {
	return strings.TrimRight(strings.TrimSpace(buildServerURL), "/")
}

// serverFixed 表示地址是否由构建注入。为 true 时界面不允许修改。
func serverFixed() bool {
	return defaultServerURL() != ""
}
