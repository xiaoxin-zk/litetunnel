package service

import (
	"context"
	"errors"
	"fmt"
	"log"
	"sync/atomic"
	"time"

	"gorm.io/gorm"
	"gorm.io/gorm/clause"

	"github.com/xiaoxin-zk/litetunnel/server/internal/model"
)

const (
	loginFailDBTimeout = 1500 * time.Millisecond

	loginFailLogInterval = time.Minute
)

var errLoginFailCounterDegraded = errors.New("账号级失败计数已降级：跨实例计数不可读")

type dbLoginFailureCounter struct {
	db *gorm.DB

	missed *memoryLoginFailureCounter

	lastWriteErrAt atomic.Int64
	lastReadErrAt  atomic.Int64

	degraded atomic.Bool

	degradedTotal atomic.Int64
}

func newLoginFailureCounter(db *gorm.DB) loginFailCounter {
	if db == nil {
		return newMemoryLoginFailureCounter()
	}
	return &dbLoginFailureCounter{db: db, missed: newMemoryLoginFailureCounter()}
}

func (c *dbLoginFailureCounter) record(account string, now time.Time) {
	account = normalizeAccount(account)
	if account == "" {
		return
	}
	if err := c.bump(account, now); err != nil {
		c.missed.record(account, now)
		c.logThrottled(&c.lastWriteErrAt, "写入", err)
	}
}

func (c *dbLoginFailureCounter) bump(account string, now time.Time) error {
	ctx, cancel := context.WithTimeout(context.Background(), loginFailDBTimeout)
	defer cancel()

	cutoff := now.Add(-loginFailWindow).Unix()
	row := model.LoginFailCounter{Account: account, Count: 1, Since: now.Unix()}
	return c.db.WithContext(ctx).Clauses(clause.OnConflict{
		Columns: []clause.Column{{Name: "account"}},
		DoUpdates: clause.Assignments(map[string]any{
			"count": gorm.Expr(
				`CASE WHEN "since" <= ? THEN 1 ELSE "count" + 1 END`, cutoff),
			"since": gorm.Expr(
				`CASE WHEN "since" <= ? THEN ? ELSE "since" END`, cutoff, now.Unix()),
			"updated_at": now,
		}),
	}).Create(&row).Error
}

func (c *dbLoginFailureCounter) count(account string, now time.Time) (int, bool) {
	account = normalizeAccount(account)
	if account == "" {
		return 0, true
	}
	missed, _ := c.missed.count(account, now)
	n, err := c.read(account, now)
	if err != nil {
		c.markDegraded()
		c.logDegradedThrottled(err)
		return missed, false
	}
	c.markRecovered()
	return n + missed, true
}

func (c *dbLoginFailureCounter) markDegraded() {
	c.degraded.Store(true)
	c.degradedTotal.Add(1)
}

func (c *dbLoginFailureCounter) markRecovered() {
	c.degraded.Store(false)
}

func (c *dbLoginFailureCounter) read(account string, now time.Time) (int, error) {
	ctx, cancel := context.WithTimeout(context.Background(), loginFailDBTimeout)
	defer cancel()

	var row model.LoginFailCounter
	err := c.db.WithContext(ctx).Where("account = ?", account).Take(&row).Error
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return 0, nil
	}
	if err != nil {
		return 0, err
	}
	if now.Sub(time.Unix(row.Since, 0)) >= loginFailWindow {
		return 0, nil
	}
	return row.Count, nil
}

func (c *dbLoginFailureCounter) reset(account string) {
	account = normalizeAccount(account)
	if account == "" {
		return
	}
	c.missed.reset(account)

	ctx, cancel := context.WithTimeout(context.Background(), loginFailDBTimeout)
	defer cancel()
	if err := c.db.WithContext(ctx).Where("account = ?", account).
		Delete(&model.LoginFailCounter{}).Error; err != nil {
		c.logThrottled(&c.lastWriteErrAt, "清除", err)
	}
}

func (s *Services) LoginFailDegraded() bool {
	if s == nil || s.loginFails == nil {
		return false
	}
	c, ok := s.loginFails.(*dbLoginFailureCounter)
	if !ok {
		return false
	}
	return c.degraded.Load()
}

func (s *Services) LoginFailDegradedTotal() int64 {
	if s == nil || s.loginFails == nil {
		return 0
	}
	c, ok := s.loginFails.(*dbLoginFailureCounter)
	if !ok {
		return 0
	}
	return c.degradedTotal.Load()
}

func (c *dbLoginFailureCounter) purgeExpired(before, deadline time.Time) (int64, error) {
	var total int64
	for {
		ctx, cancel := context.WithTimeout(context.Background(), loginFailDBTimeout)
		var accounts []string
		err := c.db.WithContext(ctx).Model(&model.LoginFailCounter{}).
			Where("since <= ?", before.Unix()).
			Limit(maintenanceBatchSize).
			Pluck("account", &accounts).Error
		cancel()
		if err != nil {
			return total, err
		}
		if len(accounts) == 0 {
			return total, nil
		}

		n, err := c.deleteAccounts(accounts, before)
		total += n
		if err != nil {
			return total, err
		}
		if len(accounts) < maintenanceBatchSize {
			return total, nil
		}
		if n == 0 {
			return total, nil
		}
		if time.Now().After(deadline) {
			return total, nil
		}
	}
}

func (c *dbLoginFailureCounter) deleteAccounts(accounts []string, before time.Time) (int64, error) {
	ctx, cancel := context.WithTimeout(context.Background(), loginFailDBTimeout)
	defer cancel()
	res := c.db.WithContext(ctx).
		Where("account IN ? AND since <= ?", accounts, before.Unix()).
		Delete(&model.LoginFailCounter{})
	return res.RowsAffected, res.Error
}

func (c *dbLoginFailureCounter) logThrottled(last *atomic.Int64, action string, err error) {
	now := time.Now().UnixNano()
	prev := last.Load()
	if now-prev < int64(loginFailLogInterval) {
		return
	}
	if !last.CompareAndSwap(prev, now) {
		return
	}
	log.Printf("[loginfail] 账号级失败计数%s失败（跨实例累加已退化，本实例仍按补记/库内值判定；"+
		"窗口 %s）: %v", action, loginFailWindow, err)
}

func (c *dbLoginFailureCounter) logDegradedThrottled(cause error) {
	c.logThrottled(&c.lastReadErrAt, "读取",
		fmt.Errorf("%w: %v", errLoginFailCounterDegraded, cause))
}

func (s *Services) PurgeExpiredLoginFails(before, deadline time.Time) int64 {
	if s == nil || s.loginFails == nil {
		return 0
	}
	c, ok := s.loginFails.(*dbLoginFailureCounter)
	if !ok {
		return 0
	}
	n, err := c.purgeExpired(before, deadline)
	if err != nil {
		log.Printf("[loginfail] 清理过期失败计数出错（本轮已清理 %d 条，下一轮维护会重试）: %v", n, err)
		return n
	}
	if n > 0 {
		log.Printf("[loginfail] 已清理 %d 条过期的账号级失败计数", n)
	}
	return n
}
