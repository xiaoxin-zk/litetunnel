package service

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"strings"
	"time"

	"gorm.io/gorm"

	"github.com/xiaoxin-zk/litetunnel/server/internal/model"
)

const MailSendTimeout = 45 * time.Second

const mailRetryInterval = 30 * time.Second

const mailBatchSize = 20

const mailMaxAttempts = 5

const mailSentRetention = 24 * time.Hour

func mailRetryDelay(attempts int) time.Duration {
	if attempts < 1 {
		attempts = 1
	}
	d := time.Minute
	for i := 1; i < attempts; i++ {
		d *= 2
		if d >= 30*time.Minute {
			return 30 * time.Minute
		}
	}
	return d
}

type mailQuota struct {
	cooldown      time.Duration
	dailyLimit    int
	dailyAllKinds bool
}

var (
	errMailQuotaCooldown = errors.New("同一邮箱发送过于频繁")
	errMailQuotaDaily    = errors.New("该邮箱当日发送已达上限")
)

func (s *Services) enqueueMail(to, subject, body, kind string, payload any, q mailQuota) (*model.MailOutbox, error) {
	raw, err := json.Marshal(payload)
	if err != nil {
		return nil, err
	}
	rec := model.MailOutbox{
		To:      to,
		Subject: subject,
		Body:    body,
		Kind:    kind,
		Payload: string(raw),
		Status:  model.MailPending,
		NextAt:  time.Now(),
	}
	err = s.DB.Transaction(func(tx *gorm.DB) error {
		if err := s.lockMailRecipient(tx, to); err != nil {
			return err
		}
		if err := checkMailQuota(tx, to, kind, q); err != nil {
			return err
		}
		return tx.Create(&rec).Error
	})
	if err != nil {
		if errors.Is(err, errMailQuotaCooldown) || errors.Is(err, errMailQuotaDaily) {
			return nil, err
		}
		log.Printf("[mail] 写入发件箱失败（收件人 %s）: %v", maskEmail(to), err)
		return nil, ErrMailQueueFull
	}
	s.kickMailWorker()
	return &rec, nil
}

func (s *Services) lockMailRecipient(tx *gorm.DB, to string) error {
	key := "mail:" + strings.ToLower(strings.TrimSpace(to))
	return s.lockAdvisory(tx, key)
}

func (s *Services) lockAdvisory(tx *gorm.DB, key string) error {
	if s.Cfg == nil || !strings.EqualFold(strings.TrimSpace(s.Cfg.DBDriver), "postgres") {
		return nil
	}
	return tx.Exec("SELECT pg_advisory_xact_lock(hashtext(?))", key).Error
}

func checkMailQuota(tx *gorm.DB, to, kind string, q mailQuota) error {
	to = strings.ToLower(strings.TrimSpace(to))

	if q.cooldown > 0 {
		var prev model.MailOutbox
		err := tx.Where("lower(to_addr) = ? AND kind = ?", to, kind).
			Order("id desc").First(&prev).Error
		if err == nil && time.Since(prev.CreatedAt) < q.cooldown {
			return errMailQuotaCooldown
		}
		if err != nil && !errors.Is(err, gorm.ErrRecordNotFound) {
			return nil
		}
	}

	if q.dailyLimit > 0 {
		now := time.Now()
		dayStart := time.Date(now.Year(), now.Month(), now.Day(), 0, 0, 0, 0, now.Location())
		qry := tx.Model(&model.MailOutbox{}).
			Where("lower(to_addr) = ? AND created_at >= ?", to, dayStart)
		if !q.dailyAllKinds {
			qry = qry.Where("kind = ?", kind)
		}
		var n int64
		if err := qry.Count(&n).Error; err != nil {
			return nil
		}
		if n >= int64(q.dailyLimit) {
			return errMailQuotaDaily
		}
	}
	return nil
}

func (s *Services) kickMailWorker() {
	if s.mailWake == nil {
		return
	}
	select {
	case s.mailWake <- struct{}{}:
	default:
	}
}

func (s *Services) StartMailWorker(ctx context.Context) <-chan struct{} {
	if s.MailEnabled() {
		log.Printf("[mail] 邮件发送已启用，发件人 %s", s.SMTPConfig().From)
	} else {
		log.Printf("[mail] 邮件发送未启用，可在管理端「系统设置 → 邮件」中配置")
	}

	done := make(chan struct{})
	go func() {
		defer close(done)
		ticker := time.NewTicker(mailRetryInterval)
		defer ticker.Stop()

		s.processMailOutbox(ctx)

		for {
			select {
			case <-ctx.Done():
				return
			case <-s.mailWake:
			case <-ticker.C:
			}
			s.processMailOutbox(ctx)
		}
	}()
	return done
}

func (s *Services) processMailOutbox(ctx context.Context) {
	if !s.MailEnabled() {
		return
	}

	var pendingActions []model.MailOutbox
	if err := s.DB.Where("status IN ? AND next_at <= ?",
		[]string{model.MailDelivered, model.MailActivating}, time.Now()).
		Order("id asc").Limit(mailBatchSize).Find(&pendingActions).Error; err != nil {
		log.Printf("[mail] 读取待激活记录失败: %v", err)
	}
	for _, row := range pendingActions {
		if ctx.Err() != nil {
			return
		}
		token, ok := s.claimMail(row.ID, []string{model.MailDelivered, model.MailActivating},
			model.MailActivating, mailActivateLease)
		if !ok {
			continue
		}
		s.finishMailAction(row, token)
	}

	var toSend []model.MailOutbox
	if err := s.DB.Where("status IN ? AND next_at <= ?",
		[]string{model.MailPending, model.MailSending}, time.Now()).
		Order("id asc").Limit(mailBatchSize).Find(&toSend).Error; err != nil {
		log.Printf("[mail] 读取发件箱失败: %v", err)
		return
	}
	for _, row := range toSend {
		if ctx.Err() != nil {
			return
		}
		token, ok := s.claimMail(row.ID, []string{model.MailPending, model.MailSending},
			model.MailSending, mailSendLease)
		if !ok {
			continue
		}
		s.deliverMail(ctx, row, token)
	}
}

const (
	mailSendLease        = MailSendTimeout + 30*time.Second
	mailActivateLease    = 2 * time.Minute
	mailSendDrainTimeout = 5 * time.Second
)

func (s *Services) claimMail(id uint, from []string, to string, lease time.Duration) (string, bool) {
	token, err := randomHex(16)
	if err != nil {
		log.Printf("[mail] 生成领取令牌失败（id=%d）: %v", id, err)
		return "", false
	}
	now := time.Now()
	res := s.DB.Model(&model.MailOutbox{}).
		Where("id = ? AND status IN ? AND next_at <= ?", id, from, now).
		Updates(map[string]any{
			"status":      to,
			"claim_token": token,
			"next_at":     now.Add(lease),
		})
	if res.Error != nil {
		log.Printf("[mail] 领取邮件失败（id=%d）: %v", id, res.Error)
		return "", false
	}
	if res.RowsAffected != 1 {
		return "", false
	}
	return token, true
}

func (s *Services) deliverMail(ctx context.Context, row model.MailOutbox, token string) {
	sender := s.mailSender()
	sendCtx, cancel := context.WithTimeout(ctx, MailSendTimeout)
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- sender.Send(sendCtx, row.To, row.Subject, row.Body) }()

	var err error
	select {
	case err = <-done:
	case <-sendCtx.Done():
		if ctx.Err() != nil {
			drainSend(done)
			return
		}
		err = fmt.Errorf("发送超时（%s）", MailSendTimeout)
		drainSend(done)
	}

	if err != nil {
		if ctx.Err() != nil || errors.Is(err, context.Canceled) {
			log.Printf("[mail] 发送被停服中断，邮件保留待发（收件人 %s，类型 %s，id=%d）",
				maskEmail(row.To), row.Kind, row.ID)
			return
		}
		s.failMail(row, token, err)
		return
	}

	log.Printf("[mail] 已送达（收件人 %s，类型 %s，第 %d 次尝试）",
		maskEmail(row.To), row.Kind, row.Attempts+1)

	// 通知类邮件（告警、报告）没有凭据动作，送达即终态；
	// 走原来的「已送达 → 激活」流程只会多一次状态写入和一条误导性的日志。
	if !mailKindHasAction(row.Kind) {
		s.finishMail(row.ID, token, mailFinish{
			status:         model.MailSent,
			attempts:       row.Attempts + 1,
			actionAttempts: row.ActionAttempts,
			clearSensitive: true,
		})
		return
	}

	updates := map[string]any{
		"status":      model.MailDelivered,
		"attempts":    row.Attempts + 1,
		"last_err":    "",
		"body":        "",
		"claim_token": "",
		"next_at":     time.Now(),
	}
	res := s.DB.Model(&model.MailOutbox{}).
		Where("id = ? AND status = ? AND claim_token = ?", row.ID, model.MailSending, token).
		Updates(updates)
	if res.Error != nil {
		log.Printf("[mail] 更新发件箱状态失败（id=%d）: %v", row.ID, res.Error)
	}
	if res.RowsAffected == 0 {
		log.Printf("[mail] 邮件已作废或已被其他实例接手，跳过凭据激活（收件人 %s，类型 %s，id=%d）",
			maskEmail(row.To), row.Kind, row.ID)
		return
	}

	row.Attempts++
	row.Body = ""

	activateToken, ok := s.claimMail(row.ID, []string{model.MailDelivered},
		model.MailActivating, mailActivateLease)
	if !ok {
		return
	}
	s.finishMailAction(row, activateToken)
}

func drainSend(done <-chan error) {
	select {
	case <-done:
	case <-time.After(mailSendDrainTimeout):
	}
}

func (s *Services) finishMailAction(row model.MailOutbox, token string) {
	err := s.applyMailAction(row, token)
	if errors.Is(err, errMailActionSuperseded) {
		log.Printf("[mail] 凭据激活已跳过：用户此后又请求了更新的凭据（收件人 %s，类型 %s，id=%d）",
			maskEmail(row.To), row.Kind, row.ID)
		s.finishMail(row.ID, token, mailFinish{
			status:         model.MailSent,
			attempts:       row.Attempts,
			actionAttempts: row.ActionAttempts,
			lastErr:        "已被更新的凭据取代，未生效",
			clearSensitive: true,
		})
		return
	}
	if errors.Is(err, errMailActionObsolete) {
		log.Printf("[mail] 凭据激活已作废：目标账号不存在（收件人 %s，类型 %s，id=%d）",
			maskEmail(row.To), row.Kind, row.ID)
		s.finishMail(row.ID, token, mailFinish{
			status:         model.MailSent,
			attempts:       row.Attempts,
			actionAttempts: row.ActionAttempts,
			lastErr:        "账号已删除，凭据动作作废",
			clearSensitive: true,
		})
		return
	}
	if err == nil {
		log.Printf("[mail] 凭据已生效（收件人 %s，类型 %s）", maskEmail(row.To), row.Kind)
		s.finishMail(row.ID, token, mailFinish{
			status:         model.MailSent,
			attempts:       row.Attempts,
			actionAttempts: row.ActionAttempts,
			clearSensitive: true,
		})
		return
	}

	attempts := row.ActionAttempts + 1
	if attempts >= mailMaxAttempts {
		log.Printf("[mail] 邮件已送达但凭据激活连续 %d 次失败，放弃（收件人 %s，id=%d）: %v"+
			"；该凭据未生效，用户原有凭据仍然可用，需要人工处理",
			attempts, maskEmail(row.To), row.ID, err)
		s.finishMail(row.ID, token, mailFinish{
			status:         model.MailFailed,
			attempts:       row.Attempts,
			actionAttempts: attempts,
			lastErr:        "凭据激活失败: " + err.Error(),
			clearSensitive: true,
		})
		return
	}

	delay := mailRetryDelay(attempts)
	log.Printf("[mail] 邮件已送达但凭据激活失败（第 %d 次），%s 后重试（不重发邮件）: %v",
		attempts, delay.Round(time.Second), err)

	updates := map[string]any{
		"status":          model.MailDelivered,
		"action_attempts": attempts,
		"next_at":         time.Now().Add(delay),
		"last_err":        truncate(err.Error(), 255),
		"claim_token":     "",
	}
	if uerr := s.DB.Model(&model.MailOutbox{}).
		Where("id = ? AND claim_token = ? AND status = ?", row.ID, token, model.MailActivating).
		Updates(updates).Error; uerr != nil {
		log.Printf("[mail] 更新发件箱失败（id=%d）: %v", row.ID, uerr)
	}
}

func (s *Services) failMail(row model.MailOutbox, token string, err error) {
	attempts := row.Attempts + 1
	if attempts >= mailMaxAttempts {
		log.Printf("[mail] 发送失败且已达重试上限（收件人 %s，类型 %s，共 %d 次）: %v"+
			"；该凭据未生效，用户原有凭据仍然可用",
			maskEmail(row.To), row.Kind, attempts, err)
		s.finishMail(row.ID, token, mailFinish{
			status:         model.MailFailed,
			attempts:       attempts,
			actionAttempts: row.ActionAttempts,
			lastErr:        err.Error(),
			clearSensitive: true,
		})
		return
	}

	delay := mailRetryDelay(attempts)
	log.Printf("[mail] 发送失败（收件人 %s，第 %d 次），%s 后重试: %v",
		maskEmail(row.To), attempts, delay.Round(time.Second), err)

	updates := map[string]any{
		"attempts":    attempts,
		"next_at":     time.Now().Add(delay),
		"last_err":    truncate(err.Error(), 255),
		"status":      model.MailPending,
		"claim_token": "",
	}
	res := s.DB.Model(&model.MailOutbox{}).
		Where("id = ? AND status = ? AND claim_token = ?", row.ID, model.MailSending, token).
		Updates(updates)
	if res.Error != nil {
		log.Printf("[mail] 更新发件箱失败（id=%d）: %v", row.ID, res.Error)
	}
	if res.RowsAffected == 0 {
		log.Printf("[mail] 邮件已作废或已被其他实例接手，失败状态不再写回（收件人 %s，id=%d）",
			maskEmail(row.To), row.ID)
	}
}

type mailFinish struct {
	status         string
	attempts       int
	actionAttempts int
	lastErr        string
	clearSensitive bool
}

func (s *Services) finishMail(id uint, token string, f mailFinish) {
	updates := map[string]any{
		"status":          f.status,
		"attempts":        f.attempts,
		"action_attempts": f.actionAttempts,
		"last_err":        truncate(f.lastErr, 255),
		"claim_token":     "",
	}
	if f.clearSensitive {
		updates["body"] = ""
		updates["payload"] = ""
	}
	res := s.DB.Model(&model.MailOutbox{}).
		Where("id = ? AND claim_token = ? AND status IN ?", id, token,
			[]string{model.MailSending, model.MailActivating}).
		Updates(updates)
	if res.Error != nil {
		log.Printf("[mail] 更新发件箱状态失败（id=%d）: %v", id, res.Error)
	}
	if res.RowsAffected == 0 {
		log.Printf("[mail] 邮件已被其他实例接手或已作废，终态不再写回（id=%d）", id)
	}
}

func (s *Services) pruneMailOutbox(ctx context.Context, deadline time.Time) {
	s.pruneTable(ctx, deadline, "已送达邮件", &model.MailOutbox{},
		"status = ? AND updated_at < ?", model.MailSent, time.Now().Add(-mailSentRetention))
}

func maskEmail(s string) string {
	at := -1
	for i, r := range s {
		if r == '@' {
			at = i
			break
		}
	}
	if at <= 1 {
		return "***"
	}
	return s[:1] + "***" + s[at:]
}
