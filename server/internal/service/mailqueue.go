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

// mailSendTimeout 是单封邮件的**总**预算：拨号与会话读写共享同一个截止。
//
// 必须覆盖邮件客户端的最长执行时间（拨号 10 秒 + 会话读写 30 秒）：
// 两层各算各的预算时，外层（30 秒）会早于 SMTP 会话（最多 40 秒）放弃，
// 慢连接上「队列已排了重试、这封信稍后却真的送到」同时发生——用户会
// 收到一封凭据尚未生效的邮件，再收到一封重复的。
const MailSendTimeout = 45 * time.Second

// mailRetryInterval 是发件箱的轮询间隔：等待重试的信与启动时遗留的信都靠它。
const mailRetryInterval = 30 * time.Second

// mailBatchSize 是单轮最多处理的邮件数。
//
// 限批而不是一次全取：SMTP 串行发送，一次几百封会把这一轮拖得很长，
// 期间新来的信也一直排在后面。
const mailBatchSize = 20

// mailMaxAttempts 是同一件事的最多重试次数（发送与凭据激活各自计数）。
//
// 到上限后标为 failed 并留下明确的日志：SMTP 配置错了的话，重试一万次
// 也不会成功，而日志会被同样的失败刷满。注意此时**凭据还没有生效**，
// 用户手里的旧凭据依然可用，所以这不是「账号找不回来」，只是「这封信没发出去」。
const mailMaxAttempts = 5

// mailSentRetention 是已办结记录的保留时长（供审计：发给谁、什么时候、成功没有）。
//
// 正文与参数在办结时就已清空，所以这里留的只是「事件」本身，不含敏感内容。
const mailSentRetention = 24 * time.Hour

// mailRetryDelay 计算第 n 次失败后的重试间隔。
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

// mailQuota 描述一类邮件的发送额度：同一收件地址的冷却窗口与每日上限。
// 0 值表示该项不限制。
type mailQuota struct {
	cooldown   time.Duration
	dailyLimit int
	// dailyAllKinds 为真时，每日上限按「该地址的全部邮件」统计而不是只算同类。
	//
	// 验证码沿用这个口径（原来就是按邮箱统计的）：注册、找回、换绑三种码
	// 各算各的话，单个地址一天能收到的信就变成三倍，防滥用效果打折。
	dailyAllKinds bool
}

// 额度不足的两种原因。调用方据此决定对外怎么说：
// 找回密码这类会泄露账号状态的接口必须把它们吞掉、照常返回成功。
var (
	errMailQuotaCooldown = errors.New("同一邮箱发送过于频繁")
	errMailQuotaDaily    = errors.New("该邮箱当日发送已达上限")
)

// enqueueMail 按额度入队：加锁 → 复核额度 → 写入待发。
//
// 三步必须在**同一个事务**里，且顺序是「先复核、后写入」：
//
//   - 复核放在写入之前，超限时一条记录都不留。先写再查的话，一批并发请求
//     会各自留下草稿、各自超限作废，而这些失败记录还会继续占额度，
//     把用户当天的额度一次性耗光——失败反而变成惩罚；
//   - 加锁是为了让同一收件地址的「复核 + 写入」串行。不加锁时并发请求
//     都读到「还没满」，各自入队，一起超额（分布式来源尤其容易）。
//
// 返回错误意味着**没写进去**，调用方必须据此回滚已经做的准备（例如撤掉刚建的
// 凭据记录）：否则用户既收不到信、旧凭据又已经失效。
//
// 注意「写进发件箱」不等于「已送达」：送达由后台协程负责并带重试，
// 凭据动作（激活新凭据、作废旧凭据）在**确认送达之后**才执行。
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
		// 用「稍后重试」的口径对外：对用户来说这与队列繁忙是一回事，
		// 而真正的原因（数据库写不进去）已经在日志里。
		log.Printf("[mail] 写入发件箱失败（收件人 %s）: %v", maskEmail(to), err)
		return nil, ErrMailQueueFull
	}
	s.kickMailWorker()
	return &rec, nil
}

// lockMailRecipient 在事务内按收件地址加锁，把「复核 + 入队」串行化。
//
// PostgreSQL 用事务级 advisory lock（与注册额度同一手法）；SQLite 不需要——
// store.Open 里连接池只有一个连接，事务天然串行。
func (s *Services) lockMailRecipient(tx *gorm.DB, to string) error {
	if s.Cfg == nil || !strings.EqualFold(strings.TrimSpace(s.Cfg.DBDriver), "postgres") {
		return nil
	}
	key := "mail:" + strings.ToLower(strings.TrimSpace(to))
	return tx.Exec("SELECT pg_advisory_xact_lock(hashtext(?))", key).Error
}

// checkMailQuota 复核某个收件地址的发信额度。
//
// 统计**全部**记录，不看投递状态：额度约束的是「请求次数」，不是「成功送达
// 的次数」。只统计成功的话，SMTP 故障期间可以无限重新排队，把队列与重试
// 都打满；投递结果不确定时还会重复发信。
//
// 「失败记录吃掉额度」这个问题在别处解决：配额不足的请求根本不会被写入
// （见 enqueueMail 的「先复核、后写入」），所以额度里的每一条都对应一次
// 真实的发送请求。
//
// 统计口径是「不含自己」（调用方尚未写入），所以达到上限即拒绝。
// 统计失败一律放行：额度是防滥用手段，不该因为一次计数失败挡住正常用户。
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

// kickMailWorker 唤醒发送协程，不必等下一个轮询周期。
func (s *Services) kickMailWorker() {
	if s.mailWake == nil {
		return
	}
	select {
	case s.mailWake <- struct{}{}:
	default:
		// 已有待处理的唤醒，合并成一次即可。
	}
}

// StartMailWorker 启动发信协程，直到 ctx 结束。
//
// 单协程串行发送：SMTP 服务商通常对并发连接有严格限制，
// 串行既避免了被限流，也让失败日志保持有序可读。
//
// 协程始终启动，而不是在未配置邮件时跳过：
// 邮件配置可以在管理端随时开启，启动时禁用不代表之后一直禁用。
// 未启用时只是不发信（待发的信留在发件箱里，配置好之后自然会被发出去）。
func (s *Services) StartMailWorker(ctx context.Context) {
	if s.MailEnabled() {
		log.Printf("[mail] 邮件发送已启用，发件人 %s", s.SMTPConfig().From)
	} else {
		log.Printf("[mail] 邮件发送未启用，可在管理端「系统设置 → 邮件」中配置")
	}

	go func() {
		ticker := time.NewTicker(mailRetryInterval)
		defer ticker.Stop()

		// 启动即处理一次：把上次进程遗留的待发邮件发出去。
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
}

// processMailOutbox 处理一批到期的工作。
//
// 两件事分开做，顺序也有讲究：先补做「已送达但凭据还没生效」的动作
// （它们不需要重发邮件），再发新的信。
func (s *Services) processMailOutbox(ctx context.Context) {
	if !s.MailEnabled() {
		// 没配 SMTP 就什么都不做：这些信留在发件箱里等配置好，
		// 不算失败、也不累计重试次数。
		return
	}

	// 记录清理交给维护任务（StartMaintenanceWorker）统一做，这里只管收发：
	// 两处都清会让「谁删了什么」变得难以追溯。
	now := time.Now()

	var pendingActions []model.MailOutbox
	if err := s.DB.Where("status = ? AND next_at <= ?", model.MailDelivered, now).
		Order("id asc").Limit(mailBatchSize).Find(&pendingActions).Error; err != nil {
		log.Printf("[mail] 读取待激活记录失败: %v", err)
	}
	for _, row := range pendingActions {
		if ctx.Err() != nil {
			return
		}
		s.finishMailAction(row)
	}

	// 待发 + 租约已过期的「发送中」：后者是某个实例在发送途中崩溃留下的，
	// 租约到期后由任意实例接手（至多重复投递一次，方向安全）。
	var toSend []model.MailOutbox
	if err := s.DB.Where("status IN ? AND next_at <= ?",
		[]string{model.MailPending, model.MailSending}, now).
		Order("id asc").Limit(mailBatchSize).Find(&toSend).Error; err != nil {
		log.Printf("[mail] 读取发件箱失败: %v", err)
		return
	}
	for _, row := range toSend {
		if ctx.Err() != nil {
			return
		}
		if !s.claimMail(row.ID, now) {
			// 被别的实例抢先领走了。多实例共用一个库时这是常态，
			// 不是异常——安静跳过即可。
			continue
		}
		s.deliverMail(ctx, row)
	}
}

// mailSendLease 是「发送中」的租约时长。
//
// 领取时把 next_at 推后这么久：租约内别的实例不会再取到这一行；
// 持有者若在发送途中崩溃，到期后可以被重新领取。取值要覆盖一次发送的
// 最坏耗时（MailSendTimeout + 一点余量），否则正常发送中的信会被重复领取。
const mailSendLease = MailSendTimeout + 30*time.Second

// claimMail 原子领取一封待发邮件：pending（或租约过期的 sending）→ sending。
//
// 多实例共用 PostgreSQL 时，每个实例都有自己的发件协程。直接读 pending 就发
// 会让同一行被两个实例各发一次——收件人会收到两封、凭据被激活两次。
// 条件更新把「谁能发」收敛成一个原子动作：只有 RowsAffected=1 的那个实例发。
//
// SQLite 单连接下天然串行，这一步同样没有副作用。
func (s *Services) claimMail(id uint, now time.Time) bool {
	res := s.DB.Model(&model.MailOutbox{}).
		Where("id = ? AND status IN ? AND next_at <= ?",
			id, []string{model.MailPending, model.MailSending}, now).
		Updates(map[string]any{
			"status":  model.MailSending,
			"next_at": now.Add(mailSendLease),
		})
	if res.Error != nil {
		log.Printf("[mail] 领取邮件失败（id=%d）: %v", id, res.Error)
		return false
	}
	return res.RowsAffected == 1
}

// deliverMail 发送一封邮件；送达后再执行凭据动作。
func (s *Services) deliverMail(ctx context.Context, row model.MailOutbox) {
	sender := s.mailSender()
	// 发送预算通过 ctx 传给客户端：拨号与会话读写共用同一个截止，
	// 不会再出现「外层判超时、实际稍后送达」的重复投递。
	sendCtx, cancel := context.WithTimeout(ctx, MailSendTimeout)
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- sender.Send(sendCtx, row.To, row.Subject, row.Body) }()

	var err error
	select {
	case err = <-done:
	case <-sendCtx.Done():
		if ctx.Err() != nil {
			// 服务停止：本轮直接放弃，不发失败记录（下次启动重试）。
			return
		}
		err = fmt.Errorf("发送超时（%s）", MailSendTimeout)
	}

	if err != nil {
		// 先看父 ctx：停服取消不是发送失败。
		// 这是**统一**判断，不能只写在上面的 Done 分支里——取消时
		// Send 往往也以 context.Canceled 返回，两个分支同时就绪，
		// select 选中 done 的话会走到这里。把停服记成一次失败并
		// attempts+1，反复重启就足以耗尽尝试次数，把一封好信永久置为失败。
		// 这里不落库：邮件既没送达也没失败，保持待发，下次启动重发。
		if ctx.Err() != nil || errors.Is(err, context.Canceled) {
			log.Printf("[mail] 发送被停服中断，邮件保留待发（收件人 %s，类型 %s，id=%d）",
				maskEmail(row.To), row.Kind, row.ID)
			return
		}
		s.failMail(row, err)
		return
	}

	log.Printf("[mail] 已送达（收件人 %s，类型 %s，第 %d 次尝试）",
		maskEmail(row.To), row.Kind, row.Attempts+1)

	// 送达即清空正文：正文里是明文验证码/重置链接，而这封信不会再重发，
	// 留着只是把敏感数据在库里多放一段时间。
	// Payload 先留着——凭据动作还要用它，动作完成后一并清掉。
	updates := map[string]any{
		"status":   model.MailDelivered,
		"attempts": row.Attempts + 1,
		"last_err": "",
		"body":     "",
	}
	// 状态用**条件**更新（仅 sending，即本实例领取时写入的状态）：
	// 这封信在发送期间可能已经被作废——换邮箱会把旧地址的待发邮件标成失败。
	// 无条件写回 delivered 会把它「复活」，随后激活出一份指向旧邮箱的凭据。
	res := s.DB.Model(&model.MailOutbox{}).
		Where("id = ? AND status = ?", row.ID, model.MailSending).
		Updates(updates)
	if res.Error != nil {
		log.Printf("[mail] 更新发件箱状态失败（id=%d）: %v", row.ID, res.Error)
	}
	if res.RowsAffected == 0 {
		log.Printf("[mail] 邮件在发送期间已被作废，跳过凭据激活（收件人 %s，类型 %s，id=%d）",
			maskEmail(row.To), row.Kind, row.ID)
		return
	}

	// 本地也同步加一：下面的凭据动作会把尝试次数写回终态，
	// 沿用旧值的话每轮激活重试都会把「发送次数」再加一次
	// （激活重试并不是发送尝试），审计数据就不准了。
	row.Attempts++
	row.Body = ""
	s.finishMailAction(row)
}

// finishMailAction 执行凭据动作；失败只重试这一步，不重发邮件。
//
// 「邮件已送达」与「凭据已生效」是两件事，必须能分别重试：
// 把两者绑成一步的话，数据库瞬时故障就会把整封邮件标成 failed 而不再尝试
// ——用户手里拿着验证码，库里却没有对应记录，谁也救不回来。
func (s *Services) finishMailAction(row model.MailOutbox) {
	err := s.applyMailAction(row)
	if errors.Is(err, errMailActionSuperseded) {
		// 被更新的同类凭据取代：这是**有意跳过**，不是失败。
		// 重试没有意义（旧凭据永远不该再压过新凭据），按已办结处理。
		log.Printf("[mail] 凭据激活已跳过：用户此后又请求了更新的凭据（收件人 %s，类型 %s，id=%d）",
			maskEmail(row.To), row.Kind, row.ID)
		s.finishMail(row.ID, mailFinish{
			status:         model.MailSent,
			attempts:       row.Attempts,
			actionAttempts: row.ActionAttempts,
			lastErr:        "已被更新的凭据取代，未生效",
			clearSensitive: true,
		})
		return
	}
	if errors.Is(err, errMailActionObsolete) {
		// 目标账号已删除：凭据动作注定无效，重试只是空转。
		log.Printf("[mail] 凭据激活已作废：目标账号不存在（收件人 %s，类型 %s，id=%d）",
			maskEmail(row.To), row.Kind, row.ID)
		s.finishMail(row.ID, mailFinish{
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
		// 凭据已生效：参数（含验证码摘要）也没有保留价值了，一并清掉。
		// attempts 用 row.Attempts（发送次数，已由调用方同步过），
		// 而不是 +1——激活重试不是发送尝试。
		s.finishMail(row.ID, mailFinish{
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
		s.finishMail(row.ID, mailFinish{
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
	}
	if uerr := s.DB.Model(&model.MailOutbox{}).Where("id = ?", row.ID).
		Updates(updates).Error; uerr != nil {
		log.Printf("[mail] 更新发件箱失败（id=%d）: %v", row.ID, uerr)
	}
}

// failMail 记录一次发送失败并按需安排重试。
func (s *Services) failMail(row model.MailOutbox, err error) {
	attempts := row.Attempts + 1
	if attempts >= mailMaxAttempts {
		log.Printf("[mail] 发送失败且已达重试上限（收件人 %s，类型 %s，共 %d 次）: %v"+
			"；该凭据未生效，用户原有凭据仍然可用",
			maskEmail(row.To), row.Kind, attempts, err)
		// 不会重发了，正文（含明文验证码）也没有保留价值。
		s.finishMail(row.ID, mailFinish{
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
		"attempts": attempts,
		"next_at":  time.Now().Add(delay),
		"last_err": truncate(err.Error(), 255),
		"status":   model.MailPending,
	}
	if uerr := s.DB.Model(&model.MailOutbox{}).Where("id = ?", row.ID).Updates(updates).Error; uerr != nil {
		log.Printf("[mail] 更新发件箱失败（id=%d）: %v", row.ID, uerr)
	}
}

// mailFinish 是一封邮件的终态。
type mailFinish struct {
	status string
	// attempts 是发送尝试次数，actionAttempts 是凭据激活尝试次数。
	// 两者都要写回：最后那一次也要算进去，否则「重试了几次才放弃」
	// 在库里会少一次，排查时对不上账。
	attempts       int
	actionAttempts int
	lastErr        string
	// clearSensitive 为 true 时同时清空正文与参数：它们含明文验证码/重置链接，
	// 一旦确定不再需要就该立刻抹掉，而不是等记录过期。
	clearSensitive bool
}

// finishMail 写下一封邮件的终态。
func (s *Services) finishMail(id uint, f mailFinish) {
	updates := map[string]any{
		"status":          f.status,
		"attempts":        f.attempts,
		"action_attempts": f.actionAttempts,
		"last_err":        truncate(f.lastErr, 255),
	}
	if f.clearSensitive {
		updates["body"] = ""
		updates["payload"] = ""
	}
	if err := s.DB.Model(&model.MailOutbox{}).Where("id = ?", id).Updates(updates).Error; err != nil {
		log.Printf("[mail] 更新发件箱状态失败（id=%d）: %v", id, err)
	}
}

// pruneMailOutbox 清理已办结的记录（由清理任务调用，分批进行）。
//
// 只留「事件」本身（发给谁、什么时候、成功没有）供审计；正文与参数在办结时
// 就已经清空，不依赖这里。
func (s *Services) pruneMailOutbox() {
	s.pruneTable("已送达邮件", &model.MailOutbox{},
		"status = ? AND updated_at < ?", model.MailSent, time.Now().Add(-mailSentRetention))
}

// maskEmail 对日志中的邮箱做脱敏，避免日志成为邮箱收集来源。
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
