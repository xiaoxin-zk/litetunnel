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
		// 配置损坏：把原文件留一份，并把原因返回给上层。
		//
		// 这里曾经是「静默重置为空配置」——用户下次打开客户端会发现自己
		// 被登出了，而磁盘上那份或许还能人工救回来的文件已经被覆盖掉了，
		// 也没有任何地方说明发生过什么。
		backup := path + ".corrupt"
		if rerr := os.Rename(path, backup); rerr != nil {
			// 备份失败就留在原地：宁可下次还报同一个错，也别把用户的文件弄丢。
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

	// 先写临时文件再原子替换。
	//
	// 直接覆盖的话，写到一半断电 / 被强杀会留下半截 JSON，而下次启动读不动
	// 它时客户端会当成「没有配置」——用户看到的是自己莫名其妙被登出了。
	// 同目录下改名在同一文件系统内是原子的（Windows 上 os.Rename 走
	// MoveFileEx + MOVEFILE_REPLACE_EXISTING，可以直接替换已存在的目标）。
	//
	// 0600：仅当前用户可读写。API Key 等同于账号凭据。
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, raw, 0o600); err != nil {
		return fmt.Errorf("保存配置失败: %w", err)
	}
	if err := os.Rename(tmp, path); err != nil {
		_ = os.Remove(tmp)
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
