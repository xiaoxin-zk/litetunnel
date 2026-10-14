package service

import (
	"context"
	"log"
	"time"
)

// mailQueueSize 是待发邮件队列长度。
//
// 找回密码接口对外表现必须与「账号是否存在」无关，因此发信必须异步：
// 若同步等待 SMTP 往返，账号存在时响应会明显变慢，形成账号枚举侧信道。
// 队列同时起到限流作用——满时直接丢弃，不会无限堆积协程。
const mailQueueSize = 128

// mailSendTimeout 是单封邮件的发送超时。
const mailSendTimeout = 30 * time.Second

type outboundMail struct {
	To      string
	Subject string
	Body    string
}

// enqueueMail 投递一封邮件到异步队列。队列满时丢弃并记录告警。
func (s *Services) enqueueMail(to, subject, body string) {
	if !s.MailEnabled() {
		return
	}
	select {
	case s.mailCh <- outboundMail{To: to, Subject: subject, Body: body}:
	default:
		log.Printf("[mail] 发信队列已满，丢弃一封发往 %s 的邮件", maskEmail(to))
	}
}

// StartMailWorker 启动发信协程，直到 ctx 结束。
//
// 单协程串行发送：SMTP 服务商通常对并发连接有严格限制，
// 串行既避免了被限流，也让失败日志保持有序可读。
//
// 协程始终启动，而不是在未配置邮件时跳过：
// 邮件配置可以在管理端随时开启，启动时禁用不代表之后一直禁用。
func (s *Services) StartMailWorker(ctx context.Context) {
	if s.MailEnabled() {
		log.Printf("[mail] 邮件发送已启用，发件人 %s", s.SMTPConfig().From)
	} else {
		log.Printf("[mail] 邮件发送未启用，可在管理端「系统设置 → 邮件」中配置")
	}

	go func() {
		for {
			select {
			case <-ctx.Done():
				return
			case m := <-s.mailCh:
				sender := s.Mailer()
				done := make(chan error, 1)
				go func() { done <- sender.Send(m.To, m.Subject, m.Body) }()

				select {
				case err := <-done:
					if err != nil {
						log.Printf("[mail] 发送失败（收件人 %s）: %v", maskEmail(m.To), err)
					}
				case <-time.After(mailSendTimeout):
					log.Printf("[mail] 发送超时（收件人 %s）", maskEmail(m.To))
				case <-ctx.Done():
					return
				}
			}
		}
	}()
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
