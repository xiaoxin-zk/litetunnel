package main

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
)

const appDirName = "LiteTunnel"

// Config 是客户端本地配置。
//
// 只保存 API Key：它是用户在控制台获取的唯一凭据，可在服务端单独吊销，
// 泄露风险远低于在本地留存账号密码。
type Config struct {
	// APIKey 是接入平台的唯一凭据。客户端不保存口令。
	APIKey string `json:"api_key"`

	// ServerURL 只在「构建时未注入平台地址」的情况下使用（本地调试）。
	// 正式发布的客户端该字段始终为空，地址由 build.go 注入。
	ServerURL string `json:"server_url,omitempty"`

	// 这里曾经有个 AutoStart（「启动客户端后自动连接」）。
	//
	// 它已经没有意义：连接与否由每条隧道自己的开关决定，而开关状态存在
	// 服务端，客户端一打开就会同步跟上。留着这个字段只会多出一个
	// 「不勾就不会连」的假象。
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

// frpcConfigPath 返回某条隧道专属的配置文件路径。
//
// 每条隧道一个子目录，而不是共用一个 frpc.toml：
//   - 配置文件里 log.to 是相对路径（./frpc.log），frpc 的工作目录就是
//     配置文件所在目录。共用一个目录的话，多个进程会往同一个 frpc.log
//     里写，日志互相覆盖，出事时没法排查；
//   - 出问题时可以直接把某个目录下的配置发给别人看，不会连带泄露其他隧道。
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

// frpcTunnelsDir 返回存放各隧道配置的目录（界面上展示，便于用户找到）。
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
	// 0600：仅当前用户可读写。API Key 等同于账号凭据。
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
