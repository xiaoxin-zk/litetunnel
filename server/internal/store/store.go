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
		// 隧道清单修订号：客户端分页同步时靠它判断多页之间有没有发生变化。
		// 由触发器维护，见 ensureTunnelListRevTriggers。
		&model.TunnelListRev{},
		&model.RedeemCode{},
		&model.RedeemRecord{},
		&model.AuditLog{},
		&model.ClientSession{},
		&model.TrafficDaily{},
		&model.LoginLog{},
		&model.PasswordResetToken{},
		&model.EmailCode{},
		&model.Setting{},
		// 待重试的防火墙端口操作：必须落库，否则进程重启后丢失，
		// 那条本该收回的规则会一直留在宿主机上。
		&model.FirewallPending{},
		// 流量采样基线：必须落库，否则控制面重启后会把当天已有流量
		// 重复计入一遍（frps 没重启时它的当日累计值还在）。
		&model.TrafficBaseline{},
		// 发件箱：必须落库，否则重启丢信、失败即弃，而验证码与重置链接
		// 会在「信进队列」时就作废旧凭据——用户就再也找不回账号了。
		&model.MailOutbox{},
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

	// 邮箱唯一性由数据库兜底：邮箱是「找回密码」的寻址依据，两条记录共用
	// 同一个邮箱时，验证码可能发到别人手里。
	//
	// 索引建在 lower(email) 上，与查账号时的大小写归一一致；
	// 用部分索引排除空邮箱（允许没填邮箱的账号）。
	//
	// 这里是**尽力而为**：老库里可能已经有重复邮箱（早期没有约束），
	// 建不上只记警告、不阻断启动——否则升级时整个服务起不来。
	// 注册与换绑路径上都还有代码级检查，正常运行不会产生新的重复。
	if err := db.Exec(
		`CREATE UNIQUE INDEX IF NOT EXISTS idx_lt_users_email_unique
		 ON lt_users(lower(email)) WHERE email <> ''`,
	).Error; err != nil {
		log.Printf("[store] 邮箱唯一索引未建立（历史数据可能存在重复邮箱，请人工清理后重启）：%v", err)
	}

	// 清理旧版本遗留的邮件草稿，见 purgeLegacyMailDrafts 的说明。
	if err := purgeLegacyMailDrafts(db); err != nil {
		// 不阻断启动：这些行最多是「多占一点额度、多留一段敏感内容」，
		// 而启动失败是整个服务不可用。下次启动会再试一次（幂等）。
		log.Printf("[store] 清理遗留邮件草稿失败（下次启动重试）：%v", err)
	}

	// 隧道清单修订号由触发器维护，见 ensureTunnelListRevTriggers 的说明。
	if err := ensureTunnelListRevTriggers(db, cfg.DBDriver); err != nil {
		return nil, fmt.Errorf("创建隧道清单修订号触发器失败: %w", err)
	}

	return db, nil
}

// purgeLegacyMailDrafts 把旧版本遗留的邮件草稿按失败处理，并清空敏感内容。
//
// 某个中间版本用 status='draft' 表示「已写好、待复核额度」：复核通过转
// pending，超限则作废。进程若在两步之间崩溃，库里就会留下这种行——正文与
// 参数里是**明文验证码或重置链接**，而清理任务只回收 failed / sent，
// 这些内容会永久留在库里；同时它们还会被发信额度统计算进去。
//
// 现在的流程已不再写 draft（复核在写入之前），所以这是一次性的数据订正：
// 升级后第一次启动清掉，之后每次启动匹配不到任何行。幂等。
func purgeLegacyMailDrafts(db *gorm.DB) error {
	res := db.Exec(
		`UPDATE lt_mail_outbox
		    SET status = ?, body = '', payload = '', last_err = ?
		  WHERE status = ?`,
		model.MailFailed, "升级遗留的草稿邮件，已作废", model.MailDraft,
	)
	if res.Error != nil {
		return res.Error
	}
	if res.RowsAffected > 0 {
		log.Printf("[store] 已作废 %d 封升级遗留的邮件草稿（清空正文与参数）", res.RowsAffected)
	}
	return nil
}

// tunnelListRevColumns 是参与清单版本的隧道字段，必须与客户端对账时
// 用到的字段一致（model.Tunnel 里改动这些字段时同步改这里）。
//
// 刻意**不含** traffic_used / last_online_at / remark / updated_at：
// 采集器每轮都写流量与在线时间，把它们计入版本会让客户端的多页同步
// 被无谓地反复打断。user_id 在列里是为了「隧道改归属」也能被看见。
var tunnelListRevColumns = []string{
	"status", "name", "type",
	"local_ip", "local_port", "remote_port",
	"domain", "subdomain",
	"bandwidth_limit",
	"use_encryption", "use_compression",
	"user_id",
}

// ensureTunnelListRevTriggers 创建维护 lt_tunnel_list_revs 的触发器。
//
// 为什么用触发器而不是在业务代码里递增：写隧道的入口有十来处（建、改、
// 删、启停、批量、管理员改归属、兑换改套餐、删除用户），漏掉任何一处都
// 只会让客户端「少发现一次变更」，而且很难测出来。触发器覆盖所有写入
// （包括将来新增的路径与批量 SQL），且与数据变更在同一个事务里。
//
// 两个驱动都不支持对方的触发器语法，所以分驱动写。语句都是幂等的
// （IF NOT EXISTS / CREATE OR REPLACE + DROP IF EXISTS），每次启动重放无妨。
func ensureTunnelListRevTriggers(db *gorm.DB, driver string) error {
	cols := strings.Join(tunnelListRevColumns, ", ")

	var stmts []string
	switch driver {
	case "sqlite":
		stmts = []string{
			`CREATE TRIGGER IF NOT EXISTS lt_tunnels_rev_ins AFTER INSERT ON lt_tunnels
BEGIN
	INSERT INTO lt_tunnel_list_revs (user_id, rev) VALUES (NEW.user_id, 1)
		ON CONFLICT (user_id) DO UPDATE SET rev = rev + 1;
END`,
			fmt.Sprintf(`CREATE TRIGGER IF NOT EXISTS lt_tunnels_rev_upd AFTER UPDATE OF %s ON lt_tunnels
BEGIN
	INSERT INTO lt_tunnel_list_revs (user_id, rev) VALUES (NEW.user_id, 1)
		ON CONFLICT (user_id) DO UPDATE SET rev = rev + 1;
END`, cols),
			// 改归属时，旧用户那一侧也要变：否则旧用户的清单版本不动，
			// 客户端会把「少了一条」当成还没同步完。
			`CREATE TRIGGER IF NOT EXISTS lt_tunnels_rev_mv AFTER UPDATE OF user_id ON lt_tunnels
WHEN OLD.user_id <> NEW.user_id
BEGIN
	INSERT INTO lt_tunnel_list_revs (user_id, rev) VALUES (OLD.user_id, 1)
		ON CONFLICT (user_id) DO UPDATE SET rev = rev + 1;
END`,
			`CREATE TRIGGER IF NOT EXISTS lt_tunnels_rev_del AFTER DELETE ON lt_tunnels
BEGIN
	INSERT INTO lt_tunnel_list_revs (user_id, rev) VALUES (OLD.user_id, 1)
		ON CONFLICT (user_id) DO UPDATE SET rev = rev + 1;
END`,
		}
	case "postgres":
		stmts = []string{
			`CREATE OR REPLACE FUNCTION lt_tunnels_rev_bump() RETURNS trigger AS $lt$
BEGIN
	IF TG_OP = 'DELETE' THEN
		INSERT INTO lt_tunnel_list_revs (user_id, rev) VALUES (OLD.user_id, 1)
			ON CONFLICT (user_id) DO UPDATE SET rev = lt_tunnel_list_revs.rev + 1;
		RETURN OLD;
	END IF;
	INSERT INTO lt_tunnel_list_revs (user_id, rev) VALUES (NEW.user_id, 1)
		ON CONFLICT (user_id) DO UPDATE SET rev = lt_tunnel_list_revs.rev + 1;
	IF TG_OP = 'UPDATE' AND OLD.user_id IS DISTINCT FROM NEW.user_id THEN
		INSERT INTO lt_tunnel_list_revs (user_id, rev) VALUES (OLD.user_id, 1)
			ON CONFLICT (user_id) DO UPDATE SET rev = lt_tunnel_list_revs.rev + 1;
	END IF;
	RETURN NEW;
END
$lt$ LANGUAGE plpgsql`,
			`DROP TRIGGER IF EXISTS lt_tunnels_rev_ins ON lt_tunnels`,
			`CREATE TRIGGER lt_tunnels_rev_ins AFTER INSERT ON lt_tunnels
	FOR EACH ROW EXECUTE FUNCTION lt_tunnels_rev_bump()`,
			`DROP TRIGGER IF EXISTS lt_tunnels_rev_upd ON lt_tunnels`,
			fmt.Sprintf(`CREATE TRIGGER lt_tunnels_rev_upd AFTER UPDATE OF %s ON lt_tunnels
	FOR EACH ROW EXECUTE FUNCTION lt_tunnels_rev_bump()`, cols),
			`DROP TRIGGER IF EXISTS lt_tunnels_rev_del ON lt_tunnels`,
			`CREATE TRIGGER lt_tunnels_rev_del AFTER DELETE ON lt_tunnels
	FOR EACH ROW EXECUTE FUNCTION lt_tunnels_rev_bump()`,
		}
	default:
		return fmt.Errorf("不支持的数据库驱动: %s", driver)
	}

	for _, stmt := range stmts {
		if err := db.Exec(stmt).Error; err != nil {
			return err
		}
	}
	return nil
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
