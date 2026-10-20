//go:build embedfrpc

package main

import _ "embed"

// 内嵌的是 gzip 压缩后的 frpc：go:embed 不做任何压缩，官方 frpc.exe 有
// ~16MB，原样打进去客户端体积直接翻倍。压缩后约 6MB，运行时释放时解压。
//
//go:embed assets/frpc.exe.gz
var embeddedFrpcGz []byte

// 构建时写入 frpc.exe 的 sha256。释放前用它判断磁盘上的文件是否已是同一份，
// 避免每次启动都解压 16MB 只为了做一次比较。
//
//go:embed assets/frpc.sha256
var embeddedFrpcSum string
