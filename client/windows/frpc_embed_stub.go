//go:build !embedfrpc

package main

// embeddedFrpc 在未内嵌的构建里为空。
//
// 保留这个占位而不是给 ensureFrpc 加条件编译，
// 是为了让两种构建走**同一条代码路径**——只有数据来源不同。
// 否则「发布版能用、开发版崩」这类问题会一直存在。
var embeddedFrpc []byte
