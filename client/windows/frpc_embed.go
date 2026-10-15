//go:build embedfrpc

package main

import _ "embed"

// embeddedFrpc 是内嵌进主程序的 frpc 可执行文件。
//
// 只在带 `-tags embedfrpc` 构建时启用，因为 go:embed 要求文件在
// **构建时**就存在，而仓库里不适合放一个十几 MB 的二进制。
// 正式发布流程会先下载 frpc.exe 到 assets/ 再带标签构建。
//
// assets/frpc.exe 来自官方 frp 发布包（Apache-2.0），
// 对应的许可文件随包分发。
//
//go:embed assets/frpc.exe
var embeddedFrpc []byte
