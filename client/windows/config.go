package main

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
)

const appDirName = "LiteTunnel"

type Config struct {
	APIKey string `json:"api_key"`

	ServerURL string `json:"server_url,omitempty"`
}

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

func frpcConfigPath(tunnelID uint) (string, error) {
	dir, err := dataDir()
	if err != nil {
		return "", err
	}
	sub := filepath.Join(dir, "tunnels", strconv.FormatUint(uint64(tunnelID), 10))
	if err := os.MkdirAll(sub, 0o700); err != nil {
		return "", err
	}
	return filepath.Join(sub, "frpc.toml"), nil
}

func frpcTunnelsDir() (string, error) {
	dir, err := dataDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(dir, "tunnels"), nil
}

func loadConfig() (*Config, error) {
	path, err := configFilePath()
	if err != nil {
		return &Config{}, err
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return &Config{}, nil
		}
		return &Config{}, err
	}
	cfg := &Config{}
	if err := json.Unmarshal(raw, cfg); err != nil {
		backup := path + ".corrupt"
		if rerr := os.Rename(path, backup); rerr != nil {
			backup = path
		}
		return &Config{}, fmt.Errorf("本地配置已损坏（%v），原文件保留为 %s，请重新填写 API Key", err, backup)
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

	if err := writeFileAtomic(path, raw, 0o600); err != nil {
		return fmt.Errorf("保存配置失败: %w", err)
	}
	return nil
}

func clearConfig() error {
	path, err := configFilePath()
	if err != nil {
		return err
	}
	var firstErr error
	for _, p := range []string{path, path + ".corrupt", path + ".tmp"} {
		if err := os.Remove(p); err != nil && !os.IsNotExist(err) && firstErr == nil {
			firstErr = err
		}
	}
	return firstErr
}

func removeFrpcConfig(tunnelID uint) error {
	dir, err := dataDir()
	if err != nil {
		return err
	}
	sub := filepath.Join(dir, "tunnels", strconv.FormatUint(uint64(tunnelID), 10))
	if err := os.RemoveAll(sub); err != nil && !os.IsNotExist(err) {
		return err
	}
	return nil
}

func removeAllFrpcConfigs() error {
	dir, err := frpcTunnelsDir()
	if err != nil {
		return err
	}
	if err := os.RemoveAll(dir); err != nil && !os.IsNotExist(err) {
		return err
	}
	return nil
}
