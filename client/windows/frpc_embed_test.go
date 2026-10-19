//go:build embedfrpc

package main

import (
	"bytes"
	"encoding/binary"
	"testing"
)

// TestEmbeddedFrpc 验证内嵌的 frpc 确实是一个完整的 Windows 可执行文件。
//
// 为什么需要这条测试：`-tags embedfrpc` 只在发布流程里启用，日常 CI 根本
// 走不到这条构建路径。而 go:embed 对内容不做任何校验——下载得到的空文件、
// 代理返回的 HTML 错误页、被截断的 zip，全都能顺利编译进客户端。产物照样
// 能启动，只有用户点「连接」准备释放内置 frpc 时才失败，而那时发布已经发出去了。
//
// 检查项刻意选成「与文件大小无关」的硬证据：PE 头（MZ + e_lfanew 处的
// PE\0\0）。再加一条体积下限，挡住「头对但内容被截断」的情况。
func TestEmbeddedFrpc(t *testing.T) {
	const minSize = 1 << 20 // 1 MiB：官方 frpc.exe 约 14 MB

	if len(embeddedFrpc) == 0 {
		t.Fatal("内嵌 frpc 为空：assets/frpc.exe 不存在或下载失败")
	}
	if len(embeddedFrpc) < minSize {
		t.Fatalf("内嵌 frpc 只有 %d 字节，远小于 %d 字节下限：下载很可能被截断或拿到的不是发布包",
			len(embeddedFrpc), minSize)
	}
	if !bytes.HasPrefix(embeddedFrpc, []byte("MZ")) {
		t.Fatalf("内嵌 frpc 缺少 MZ 头（前 4 字节 %x）：这不是一个 Windows 可执行文件",
			firstBytes(embeddedFrpc, 4))
	}
	if len(embeddedFrpc) < 0x40 {
		t.Fatal("内嵌 frpc 太小，连 DOS 头都不完整")
	}
	off := int(binary.LittleEndian.Uint32(embeddedFrpc[0x3c:0x40]))
	if off <= 0 || off+4 > len(embeddedFrpc) {
		t.Fatalf("内嵌 frpc 的 e_lfanew 越界（%d），PE 头损坏", off)
	}
	if !bytes.Equal(embeddedFrpc[off:off+4], []byte{'P', 'E', 0, 0}) {
		t.Fatalf("内嵌 frpc 在偏移 %d 处不是 PE\\0\\0 签名：%x", off, embeddedFrpc[off:off+4])
	}
}

// firstBytes 返回 b 的前 n 个字节（不足时返回全部），用于错误信息。
func firstBytes(b []byte, n int) []byte {
	if len(b) < n {
		return b
	}
	return b[:n]
}
