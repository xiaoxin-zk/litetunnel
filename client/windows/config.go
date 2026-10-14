package main

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
)

const appDirName = "LiteTunnel"

// Config 是客户端本地配置。
//
// 这里只保存服务端地址与「客户端接入凭据」，不保存账号密码：
// 凭据可在服务端单独吊销，泄露风险远低于留存口令。
type Config struct {
	ServerURL string `json:"server_url"`
	Token     string `json:"token"`
	Username  string `json:"username"`
	AutoStart bool   `json:"auto_start"`
}

// dataDir 返回应用数据目录（Windows 下为 %AppData%\LiteTunnel）。
func dataDir() (string, error) {
	base, err := os.UserConfigDir()
	if err != nil {
		return "", err
	}
	dir := filepath.Join(base, appDirName)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return "", err
	}
	return dir, nil
}

func configFilePath() (string, error) {
	dir, err := dataDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(dir, "config.json"), nil
}

// frpcConfigPath 返回下发给 frpc 的配置文件路径。
func frpcConfigPath() (string, error) {
	dir, err := dataDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(dir, "frpc.toml"), nil
}

func loadConfig() (*Config, error) {
	path, err := configFilePath()
	if err != nil {
		return nil, err
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return &Config{}, nil
		}
		return nil, err
	}
	cfg := &Config{}
	if err := json.Unmarshal(raw, cfg); err != nil {
		// 配置损坏时重置，避免客户端彻底无法启动。
		return &Config{}, nil
	}
	return cfg, nil
}

func saveConfig(cfg *Config) error {
	path, err := configFilePath()
	if err != nil {
		return err
	}
	raw, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		return err
	}
	// 0600：仅当前用户可读写。
	if err := os.WriteFile(path, raw, 0o600); err != nil {
		return fmt.Errorf("保存配置失败: %w", err)
	}
	return nil
}

func clearConfig() error {
	path, err := configFilePath()
	if err != nil {
		return err
	}
	if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
		return err
	}
	return nil
}
