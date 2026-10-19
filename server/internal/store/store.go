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
	"gorm.io/gorm/clause"
	"gorm.io/gorm/logger"

	"github.com/xiaoxin-zk/litetunnel/server/internal/config"
	"github.com/xiaoxin-zk/litetunnel/server/internal/model"
)

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
	opened := false
	defer func() {
		if !opened {
			_ = sqlDB.Close()
		}
	}()
	if cfg.DBDriver == "sqlite" {
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
		&model.TunnelListRev{},
		&model.RedeemCode{},
		&model.RedeemRecord{},
		&model.AuditLog{},
		&model.ClientSession{},
		&model.TrafficDaily{},
		&model.LoginLog{},
		&model.MailTemplate{},
		&model.StepUpGrant{},
		&model.AdminAPIKey{},
		&model.PasswordResetToken{},
		&model.EmailCode{},
		&model.Setting{},
		&model.FirewallPending{},
		&model.FirewallSeq{},
		&model.TrafficBaseline{},
		&model.TrafficResetMark{},
		&model.MailOutbox{},
		&model.RuntimeLease{},
		&model.ProxyDrainPending{},
		&model.LoginFailCounter{},
	); err != nil {
		return nil, fmt.Errorf("数据库迁移失败: %w", err)
	}

	row := db.Model(&model.FirewallPending{}).Select("COALESCE(MAX(generation), 0)").Row()
	var maxGen int64
	if err := row.Scan(&maxGen); err != nil {
		return nil, fmt.Errorf("读取防火墙待办最大代次失败: %w", err)
	}
	if err := db.Clauses(clause.OnConflict{
		Columns:   []clause.Column{{Name: "id"}},
		DoNothing: true,
	}).Create(&model.FirewallSeq{ID: 1, Next: maxGen + 1}).Error; err != nil {
		return nil, fmt.Errorf("初始化防火墙序列失败: %w", err)
	}

	if err := db.Exec(
		`CREATE UNIQUE INDEX IF NOT EXISTS idx_lt_tunnels_remote_port
		 ON lt_tunnels(remote_port) WHERE remote_port > 0`,
	).Error; err != nil {
		return nil, fmt.Errorf("创建端口唯一索引失败: %w", err)
	}

	if err := db.Exec(
		`CREATE UNIQUE INDEX IF NOT EXISTS idx_lt_users_email_unique
		 ON lt_users(lower(email)) WHERE email <> ''`,
	).Error; err != nil {
		log.Printf("[store] 邮箱唯一索引未建立（历史数据可能存在重复邮箱，请人工清理后重启）：%v", err)
	}

	if !db.Migrator().HasIndex(&model.EmailCode{}, "idx_lt_email_codes_mail_uniq") ||
		!db.Migrator().HasIndex(&model.PasswordResetToken{}, "idx_lt_reset_tokens_mail_uniq") {
		if err := dedupeMailCredentials(db); err != nil {
			return nil, fmt.Errorf("清理重复的邮件凭据失败（请先人工修复 lt_email_codes / "+
				"lt_password_reset_tokens 中重复的 mail_id）: %w", err)
		}
	}
	if err := db.Exec(
		`CREATE UNIQUE INDEX IF NOT EXISTS idx_lt_email_codes_mail_uniq
		 ON lt_email_codes(mail_id) WHERE mail_id > 0`,
	).Error; err != nil {
		return nil, fmt.Errorf("创建验证码来源唯一索引失败（请清理 lt_email_codes 中重复的 mail_id 后重启）: %w", err)
	}
	if err := db.Exec(
		`CREATE UNIQUE INDEX IF NOT EXISTS idx_lt_reset_tokens_mail_uniq
		 ON lt_password_reset_tokens(mail_id) WHERE mail_id > 0`,
	).Error; err != nil {
		return nil, fmt.Errorf("创建重置令牌来源唯一索引失败（请清理 lt_password_reset_tokens 中重复的 mail_id 后重启）: %w", err)
	}

	if err := purgeLegacyMailDrafts(db); err != nil {
		log.Printf("[store] 清理遗留邮件草稿失败（下次启动重试）：%v", err)
	}

	if err := model.BackfillIncarnations(db); err != nil {
		return nil, fmt.Errorf("回填账号生命周期标识失败: %w", err)
	}

	if err := ensureTunnelListRevTriggers(db, cfg.DBDriver); err != nil {
		return nil, fmt.Errorf("创建隧道清单修订号触发器失败: %w", err)
	}

	opened = true
	return db, nil
}

func dedupeMailCredentials(db *gorm.DB) error {
	tables := []struct{ name, label string }{
		{"lt_email_codes", "验证码"},
		{"lt_password_reset_tokens", "重置令牌"},
	}
	for _, tb := range tables {
		res := db.Exec(fmt.Sprintf(
			`DELETE FROM %s
			  WHERE mail_id > 0
			    AND id NOT IN (
			        SELECT MAX(id) FROM %s WHERE mail_id > 0 GROUP BY mail_id
			    )`, tb.name, tb.name))
		if res.Error != nil {
			return fmt.Errorf("清理重复%s失败: %w", tb.label, res.Error)
		}
		if res.RowsAffected > 0 {
			log.Printf("[store] 已清理 %d 条重复的邮件%s（同一封邮件只保留最新一条）",
				res.RowsAffected, tb.label)
		}
	}
	return nil
}

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

var tunnelListRevColumns = []string{
	"status", "name", "type",
	"local_ip", "local_port", "remote_port",
	"domain", "subdomain",
	"bandwidth_limit",
	"use_encryption", "use_compression",
	"user_id",
}

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
				TrafficQuota:   20 * 1024 * 1024 * 1024,
				BandwidthLimit: 4 * 1024 * 1024,
				AllowProtocols: "tcp,udp",
				Priority:       0,
				IsDefault:      true,
			},
			{
				Name:                "标准版",
				Description:         "支持网站与自定义域名",
				MaxTunnels:          10,
				MaxPorts:            10,
				TrafficQuota:        200 * 1024 * 1024 * 1024,
				BandwidthLimit:      20 * 1024 * 1024,
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
				BandwidthLimit:      100 * 1024 * 1024,
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
