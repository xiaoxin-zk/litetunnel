package service

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"os"
	"path/filepath"
	"testing"
)

func writePanelArchive(t *testing.T, dir string) string {
	t.Helper()
	path := filepath.Join(dir, "panel.tar.gz")
	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gz)

	entries := []struct {
		name    string
		body    string
		typeflg byte
	}{
		{"../evil.sh", "echo pwned", tar.TypeReg},
		{"docs/readme.txt", "hello", tar.TypeReg},
		{panelBinaryName, "#!/bin/sh\necho panel", tar.TypeReg},
		{"litetunnel-panel.old", "old", tar.TypeReg},
	}
	for _, e := range entries {
		if err := tw.WriteHeader(&tar.Header{
			Name: e.name, Mode: 0o644, Size: int64(len(e.body)), Typeflag: e.typeflg,
		}); err != nil {
			t.Fatalf("写 tar header 失败: %v", err)
		}
		if _, err := tw.Write([]byte(e.body)); err != nil {
			t.Fatalf("写 tar 内容失败: %v", err)
		}
	}
	if err := tw.Close(); err != nil {
		t.Fatalf("关闭 tar 失败: %v", err)
	}
	if err := gz.Close(); err != nil {
		t.Fatalf("关闭 gzip 失败: %v", err)
	}
	if err := os.WriteFile(path, buf.Bytes(), 0o644); err != nil {
		t.Fatalf("写压缩包失败: %v", err)
	}
	return path
}

func TestExtractPanelBinaryOnlyTakesExactFile(t *testing.T) {
	dir := t.TempDir()
	archive := writePanelArchive(t, dir)
	target := filepath.Join(dir, "panel.new")

	if err := extractPanelBinary(archive, target); err != nil {
		t.Fatalf("解包失败: %v", err)
	}
	body, err := os.ReadFile(target)
	if err != nil {
		t.Fatalf("读取解出的文件失败: %v", err)
	}
	if string(body) != "#!/bin/sh\necho panel" {
		t.Fatalf("解出的不是面板二进制: %q", string(body))
	}
	if _, err := os.Stat(filepath.Join(dir, "..", "evil.sh")); err == nil {
		t.Fatal("压缩包里的 ../ 路径不该被写出")
	}
	if _, err := os.Stat(filepath.Join(dir, "litetunnel-panel.old")); err == nil {
		t.Fatal("只应解出 litetunnel-panel 一个文件")
	}
}

func TestExtractPanelBinaryMissingEntry(t *testing.T) {
	dir := t.TempDir()
	archive := filepath.Join(dir, "empty.tar.gz")
	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gz)
	_ = tw.WriteHeader(&tar.Header{Name: "readme.txt", Mode: 0o644, Size: 2, Typeflag: tar.TypeReg})
	_, _ = tw.Write([]byte("hi"))
	_ = tw.Close()
	_ = gz.Close()
	if err := os.WriteFile(archive, buf.Bytes(), 0o644); err != nil {
		t.Fatalf("写压缩包失败: %v", err)
	}

	if err := extractPanelBinary(archive, filepath.Join(dir, "panel.new")); err == nil {
		t.Fatal("没有面板二进制时应当报错")
	}
}

func TestSelfUpdateUnavailableInContainer(t *testing.T) {
	t.Setenv("LT_CONTAINER", "1")
	t.Setenv("LT_SELF_UPDATE", "1")
	svc := newTestServices(t, nil)

	ok, mode := svc.SelfUpdateState()
	if ok || mode != "docker" {
		t.Fatalf("容器里必须禁止在线更新，实际 ok=%v mode=%q", ok, mode)
	}
	if _, err := svc.ApplyPanelUpdate(t.Context()); err == nil {
		t.Fatal("容器里调用更新应当直接拒绝")
	}
}

func TestSelfUpdateRequiresOptIn(t *testing.T) {
	t.Setenv("LT_CONTAINER", "")
	t.Setenv("LT_SELF_UPDATE", "")
	svc := newTestServices(t, nil)

	if ok, _ := svc.SelfUpdateState(); ok {
		t.Fatal("没有显式开启 LT_SELF_UPDATE 时不应允许替换二进制")
	}
}
