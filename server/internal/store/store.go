// Package store 负责数据库连接、结构迁移与初始数据播种。
package store

import (
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/glebarez/sqlite"
	"gorm.io/driver/postgres"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"

	"github.com/xiaoxin-zk/litetunnel/server/internal/config"
	"github.com/xiaoxin-zk/litetunnel/server/internal/model"
)

// Open 建立数据库连接并完成迁移。
func Open(cfg *config.Config) (*gorm.DB, error) {
	logLevel := logger.Warn
	if cfg.LogLevel == "debug" {
		logLevel = logger.Info
	}
	gormCfg := &gorm.Config{
		Logger:                                   logger.Default.LogMode(logLevel),
		DisableForeignKeyConstraintWhenMigrating: true,
	}

	var (
		db  *gorm.DB
		err error
	)
	switch cfg.DBDriver {
	case "sqlite":
		if dir := filepath.Dir(cfg.DBDSN); dir != "" && dir != "." {
			if mkErr := os.MkdirAll(dir, 0o750); mkErr != nil {
				return nil, fmt.Errorf("创建数据目录失败: %w", mkErr)
			}
		}
		// _pragma 参数启用 WAL 与忙等待，显著提升并发读写表现。
		dsn := cfg.DBDSN
		if !strings.Contains(dsn, "_pragma") {
			dsn = dsn + "?_pragma=journal_mode(WAL)&_pragma=busy_timeout(5000)&_pragma=synchronous(NORMAL)&_pragma=foreign_keys(1)"
		}
		db, err = gorm.Open(sqlite.Open(dsn), gormCfg)
	case "postgres":
		db, err = gorm.Open(postgres.Open(cfg.DBDSN), gormCfg)
	default:
		return nil, fmt.Errorf("不支持的数据库驱动: %s", cfg.DBDriver)
	}
	if err != nil {
		return nil, fmt.Errorf("连接数据库失败: %w", err)
	}

	sqlDB, err := db.DB()
	if err != nil {
		return nil, err
	}
	if cfg.DBDriver == "sqlite" {
		// SQLite 单写者模型，连接数过多反而增加锁竞争。
		sqlDB.SetMaxOpenConns(1)
		sqlDB.SetMaxIdleConns(1)
	} else {
		sqlDB.SetMaxOpenConns(50)
		sqlDB.SetMaxIdleConns(10)
		sqlDB.SetConnMaxLifetime(time.Hour)
	}

	if err := db.AutoMigrate(
		&model.Group{},
		&model.User{},
		&model.Admin{},
		&model.Tunnel{},
		&model.RedeemCode{},
		&model.RedeemRecord{},
		&model.AuditLog{},
		&model.ClientSession{},
		&model.TrafficDaily{},
		&model.Setting{},
	); err != nil {
		return nil, fmt.Errorf("数据库迁移失败: %w", err)
	}

	// 端口唯一性由数据库兜底：并发分配同一端口时会被这里直接拒绝。
	// 使用部分唯一索引是因为 HTTP/HTTPS 隧道的 remote_port 恒为 0，允许重复。
	if err := db.Exec(
		`CREATE UNIQUE INDEX IF NOT EXISTS idx_lt_tunnels_remote_port
		 ON lt_tunnels(remote_port) WHERE remote_port > 0`,
	).Error; err != nil {
		return nil, fmt.Errorf("创建端口唯一索引失败: %w", err)
	}

	return db, nil
}

// Seed 播种默认分组与初始管理员（幂等）。
//
// 返回 createdAdmin 表示本次是否真的创建了初始管理员：
// 只有在首次创建时，调用方才应把初始密码打印出来，否则重启后会打印出无效密码。
func Seed(db *gorm.DB, cfg *config.Config, hashPassword func(string) (string, error)) (createdAdmin bool, err error) {
	var groupCount int64
	if err := db.Model(&model.Group{}).Count(&groupCount).Error; err != nil {
		return false, err
	}
	if groupCount == 0 {
		groups := []model.Group{
			{
				Name:           "免费版",
				Description:    "默认分组，适合个人测试与轻量使用",
				MaxTunnels:     2,
				MaxPorts:       2,
				TrafficQuota:   20 * 1024 * 1024 * 1024, // 20 GiB
				BandwidthLimit: 4 * 1024 * 1024,         // 4 Mbps
				AllowProtocols: "tcp,udp",
				Priority:       0,
				IsDefault:      true,
			},
			{
				Name:                "标准版",
				Description:         "支持网站与自定义域名",
				MaxTunnels:          10,
				MaxPorts:            10,
				TrafficQuota:        200 * 1024 * 1024 * 1024, // 200 GiB
				BandwidthLimit:      20 * 1024 * 1024,         // 20 Mbps
				AllowProtocols:      "tcp,udp,http,https",
				AllowCustomDomain:   true,
				AllowPrivilegedPort: false,
				Priority:            10,
			},
			{
				Name:                "专业版",
				Description:         "不限隧道数，高带宽，适合游戏开服与生产环境",
				MaxTunnels:          0,
				MaxPorts:            30,
				TrafficQuota:        0,
				BandwidthLimit:      100 * 1024 * 1024, // 100 Mbps
				AllowProtocols:      "tcp,udp,http,https",
				AllowCustomDomain:   true,
				AllowPrivilegedPort: false,
				Priority:            20,
			},
		}
		if err := db.Create(&groups).Error; err != nil {
			return false, fmt.Errorf("初始化分组失败: %w", err)
		}
		log.Printf("[seed] 已创建 %d 个默认分组", len(groups))
	}

	var adminCount int64
	if err := db.Model(&model.Admin{}).Count(&adminCount).Error; err != nil {
		return false, err
	}
	if adminCount == 0 {
		hashed, err := hashPassword(cfg.BootstrapAdminPassword)
		if err != nil {
			return false, err
		}
		admin := model.Admin{
			Username: cfg.BootstrapAdminUser,
			Password: hashed,
			Nickname: "超级管理员",
			Role:     "super",
			Status:   "active",
		}
		if err := db.Create(&admin).Error; err != nil {
			return false, fmt.Errorf("初始化管理员失败: %w", err)
		}
		return true, nil
	}

	return false, nil
}
