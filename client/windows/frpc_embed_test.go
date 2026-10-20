//go:build embedfrpc

package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"strings"
	"testing"
)

// 发布包里内嵌的是 gzip 压缩的 frpc；这里解压后逐项检查：
// 构建脚本写入的 sha256、体积下限、PE 头。压缩包被截断、assets 里
// 留了上次构建的旧文件、或者下载到的不是官方包，都会在这里失败。
func TestEmbeddedFrpc(t *testing.T) {
	const minSize = 1 << 20

	if len(embeddedFrpcGz) == 0 {
		t.Fatal("内嵌 frpc 为空：assets/frpc.exe.gz 不存在或下载失败")
	}

	raw, err := gunzipFrpc(embeddedFrpcGz)
	if err != nil {
		t.Fatalf("解压内嵌 frpc 失败: %v", err)
	}
	if len(raw) < minSize {
		t.Fatalf("内嵌 frpc 只有 %d 字节，远小于 %d 字节下限：下载很可能被截断或拿到的不是发布包",
			len(raw), minSize)
	}

	want := strings.ToLower(strings.TrimSpace(embeddedFrpcSum))
	if want == "" {
		t.Fatal("缺少 assets/frpc.sha256：构建脚本没有记录 frpc 校验和")
	}
	sum := sha256.Sum256(raw)
	if got := hex.EncodeToString(sum[:]); got != want {
		t.Fatalf("内嵌 frpc 校验和不符：期望 %s，实际 %s", want, got)
	}

	if !bytes.HasPrefix(raw, []byte("MZ")) {
		t.Fatalf("内嵌 frpc 缺少 MZ 头（前 4 字节 %x）：这不是一个 Windows 可执行文件",
			firstBytes(raw, 4))
	}
	if len(raw) < 0x40 {
		t.Fatal("内嵌 frpc 太小，连 DOS 头都不完整")
	}
	off := int(binary.LittleEndian.Uint32(raw[0x3c:0x40]))
	if off <= 0 || off+4 > len(raw) {
		t.Fatalf("内嵌 frpc 的 e_lfanew 越界（%d），PE 头损坏", off)
	}
	if !bytes.Equal(raw[off:off+4], []byte{'P', 'E', 0, 0}) {
		t.Fatalf("内嵌 frpc 在偏移 %d 处不是 PE\\0\\0 签名：%x", off, raw[off:off+4])
	}
}

func firstBytes(b []byte, n int) []byte {
	if len(b) < n {
		return b
	}
	return b[:n]
}
