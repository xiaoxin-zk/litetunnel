package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func withTempConfigDir(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	if os.Getenv("APPDATA") != "" || os.Getenv("XDG_CONFIG_HOME") != "" {
		t.Setenv("APPDATA", dir)
		t.Setenv("XDG_CONFIG_HOME", dir)
	} else {
		t.Setenv("APPDATA", dir)
		t.Setenv("XDG_CONFIG_HOME", dir)
	}
	sub := filepath.Join(dir, appDirName)
	if err := os.MkdirAll(sub, 0o700); err != nil {
		t.Fatalf("建临时配置目录失败: %v", err)
	}
	return sub
}

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

func TestLoadConfigKeepsCorruptFile(t *testing.T) {
	dir := withTempConfigDir(t)
	path := filepath.Join(dir, "config.json")

	corrupt := []byte(`{"api_key": "lt_abc", `)
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

	backup := path + ".corrupt"
	saved, rerr := os.ReadFile(backup)
	if rerr != nil {
		t.Fatalf("损坏的配置应被保留为 %s: %v", backup, rerr)
	}
	if string(saved) != string(corrupt) {
		t.Fatalf("备份内容与原文不一致: %q", string(saved))
	}
	if !strings.Contains(err.Error(), backup) {
		t.Errorf("错误信息里应包含备份路径，实际: %v", err)
	}
}

func TestLoadConfigNeverReturnsNil(t *testing.T) {
	t.Setenv("APPDATA", "")
	t.Setenv("XDG_CONFIG_HOME", "")

	cfg, err := loadConfig()
	if cfg == nil {
		t.Fatal("无论成功与否都必须返回非 nil 配置，否则渲染状态时会 panic")
	}
	if err == nil {
		t.Skip("当前平台未定义配置目录，构造不出这个失败场景")
	}
}

func TestLoadConfigNonNotExistErrorStillReturnsConfig(t *testing.T) {
	dir := withTempConfigDir(t)
	if err := os.Mkdir(filepath.Join(dir, "config.json"), 0o700); err != nil {
		t.Fatalf("构造失败场景失败: %v", err)
	}

	cfg, err := loadConfig()
	if cfg == nil {
		t.Fatal("读取失败时也必须返回非 nil 配置")
	}
	if err == nil {
		t.Fatal("读取失败应返回错误，界面才能显示原因")
	}
}

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

func TestClearConfigRemovesSiblings(t *testing.T) {
	withTempConfigDir(t)

	path, err := configFilePath()
	if err != nil {
		t.Fatalf("取配置路径失败: %v", err)
	}
	files := []string{path, path + ".corrupt", path + ".tmp"}
	for _, p := range files {
		if werr := os.WriteFile(p, []byte(`{"api_key":"secret"}`), 0o600); werr != nil {
			t.Fatalf("写入 %s 失败: %v", p, werr)
		}
	}

	if err := clearConfig(); err != nil {
		t.Fatalf("清理配置失败: %v", err)
	}
	for _, p := range files {
		if _, serr := os.Stat(p); !os.IsNotExist(serr) {
			t.Errorf("%s 应被删除（其中含 API Key）", filepath.Base(p))
		}
	}
}

func TestRemoveFrpcConfigDeletesDir(t *testing.T) {
	withTempConfigDir(t)

	if err := writeFrpcConfig(7, "serverAddr = \"127.0.0.1\"\ntoken = \"secret\"\n"); err != nil {
		t.Fatalf("写隧道配置失败: %v", err)
	}
	path, err := frpcConfigPath(7)
	if err != nil {
		t.Fatalf("取隧道配置路径失败: %v", err)
	}
	if _, err := os.Stat(path); err != nil {
		t.Fatalf("前置条件：隧道配置应已落盘: %v", err)
	}

	if err := removeFrpcConfig(7); err != nil {
		t.Fatalf("删除隧道配置失败: %v", err)
	}
	if _, err := os.Stat(filepath.Dir(path)); !os.IsNotExist(err) {
		t.Error("隧道配置目录应被删除（其中含接入密钥）")
	}

	if err := removeFrpcConfig(7); err != nil {
		t.Errorf("删除不存在的配置不应报错: %v", err)
	}
}

func TestRemoveAllFrpcConfigsDeletesAllTunnels(t *testing.T) {
	withTempConfigDir(t)

	for _, id := range []uint{1, 2, 3} {
		if err := writeFrpcConfig(id, "token = \"secret\"\n"); err != nil {
			t.Fatalf("写隧道 %d 配置失败: %v", id, err)
		}
	}
	dir, err := frpcTunnelsDir()
	if err != nil {
		t.Fatalf("取隧道目录失败: %v", err)
	}

	if err := removeAllFrpcConfigs(); err != nil {
		t.Fatalf("清理隧道配置失败: %v", err)
	}
	if _, err := os.Stat(dir); !os.IsNotExist(err) {
		t.Error("登出后应删除全部隧道配置（其中含接入密钥）")
	}
}
