package service

import (
	"fmt"

	"github.com/xiaoxin-zk/litetunnel/server/internal/config"
	"github.com/xiaoxin-zk/litetunnel/server/internal/controlplane"
)

func mustControlPlane(cfg *config.Config) *controlplane.Client {
	c, err := controlplane.New(cfg.RedisAddr, cfg.RedisPassword, cfg.RedisDB, cfg.RedisPrefix)
	if err != nil {
		panic(fmt.Sprintf("初始化 Redis 控制面失败: %v", err))
	}
	return c
}
