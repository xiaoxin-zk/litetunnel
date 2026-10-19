//go:build embedfrpc

package main

import (
	"bytes"
	"encoding/binary"
	"testing"
)

func TestEmbeddedFrpc(t *testing.T) {
	const minSize = 1 << 20

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

func firstBytes(b []byte, n int) []byte {
	if len(b) < n {
		return b
	}
	return b[:n]
}
