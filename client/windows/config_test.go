package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// 这一组守的是本地凭据文件的两个行为：写入必须是原子的，损坏时必须留下
// 证据而不是被静默清空。
//
// 为什么值得单独测：这两种情况都只在异常路径上出现（写到一半被打断、
// 文件被别的程序改坏），而它们的后果是「用户发现自己被登出了，且不知道
// 为什么」——没有任何崩溃、没有任何日志，只靠人工复现几乎抓不到。

// withTempConfigDir 把配置目录指到临时目录。
//
// dataDir() 走 os.UserConfigDir()，在 Windows 上就是 %APPDATA%；
// 这里覆盖环境变量，避免测试碰到真实用户的凭据文件。
func withTempConfigDir(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	if os.Getenv("APPDATA") != "" || os.Getenv("XDG_CONFIG_HOME") != "" {
		t.Setenv("APPDATA", dir)
		t.Setenv("XDG_CONFIG_HOME", dir)
	} else {
		// 兜底：两个都没设时也设上，让 dataDir 落在临时目录里。
		t.Setenv("APPDATA", dir)
		t.Setenv("XDG_CONFIG_HOME", dir)
	}
	sub := filepath.Join(dir, appDirName)
	if err := os.MkdirAll(sub, 0o700); err != nil {
		t.Fatalf("建临时配置目录失败: %v", err)
	}
	return sub
}

// TestSaveConfigIsAtomic 断言保存过程中不会在目标路径上出现半截内容。
//
// 直接覆盖写的话，写到一半被打断会留下不完整的 JSON；下次启动读不动它，
// 客户端就会当成「没有配置」。这里能验证的是「先写临时文件再替换」这个
// 做法本身：替换完成后临时文件不应残留，且内容完整可读。
func TestSaveConfigIsAtomic(t *testing.T) {
	dir := withTempConfigDir(t)

	cfg := &Config{APIKey: "lt_test_key", ServerURL: "https://example.invalid"}
	if err := saveConfig(cfg); err != nil {
		t.Fatalf("保存配置失败: %v", err)
	}

	path := filepath.Join(dir, "config.json")
	if _, err := os.Stat(path + ".tmp"); !os.IsNotExist(err) {
		t.Errorf("替换完成后不应残留临时文件: %v", err)
	}

	got, err := loadConfig()
	if err != nil {
		t.Fatalf("读取配置失败: %v", err)
	}
	if got.APIKey != cfg.APIKey || got.ServerURL != cfg.ServerURL {
		t.Fatalf("读回来的配置与写入不一致: %+v", got)
	}

	// 覆盖写一次：替换已存在的文件在 Windows 上也必须成功
	// （os.Rename 走 MoveFileEx + MOVEFILE_REPLACE_EXISTING）。
	cfg.APIKey = "lt_second_key"
	if err := saveConfig(cfg); err != nil {
		t.Fatalf("覆盖保存失败: %v", err)
	}
	got, err = loadConfig()
	if err != nil {
		t.Fatalf("覆盖后读取失败: %v", err)
	}
	if got.APIKey != "lt_second_key" {
		t.Fatalf("覆盖后的 Key = %q，期望 lt_second_key", got.APIKey)
	}
}

// TestLoadConfigKeepsCorruptFile 断言损坏的配置不会被静默丢弃。
func TestLoadConfigKeepsCorruptFile(t *testing.T) {
	dir := withTempConfigDir(t)
	path := filepath.Join(dir, "config.json")

	corrupt := []byte(`{"api_key": "lt_abc", `) // 半截 JSON
	if err := os.WriteFile(path, corrupt, 0o600); err != nil {
		t.Fatalf("写入损坏配置失败: %v", err)
	}

	cfg, err := loadConfig()
	if err == nil {
		t.Fatal("配置损坏时必须返回错误，而不是静默当成空配置")
	}
	if cfg == nil {
		t.Fatal("损坏时也应返回一个可用的空配置，避免调用方拿到 nil")
	}
	if cfg.APIKey != "" {
		t.Fatalf("损坏配置不应被解析出内容: %+v", cfg)
	}

	// 原文件必须被保留下来供人工恢复。
	backup := path + ".corrupt"
	saved, rerr := os.ReadFile(backup)
	if rerr != nil {
		t.Fatalf("损坏的配置应被保留为 %s: %v", backup, rerr)
	}
	if string(saved) != string(corrupt) {
		t.Fatalf("备份内容与原文不一致: %q", string(saved))
	}
	// 错误信息要能告诉用户去哪儿找原文件。
	if !strings.Contains(err.Error(), backup) {
		t.Errorf("错误信息里应包含备份路径，实际: %v", err)
	}
}

// TestLoadConfigMissingFileIsNotAnError 断言「首次启动」不算异常。
func TestLoadConfigMissingFileIsNotAnError(t *testing.T) {
	withTempConfigDir(t)

	cfg, err := loadConfig()
	if err != nil {
		t.Fatalf("配置文件不存在时不应报错: %v", err)
	}
	if cfg == nil || cfg.APIKey != "" {
		t.Fatalf("期望拿到一个空配置，实际: %+v", cfg)
	}
}
