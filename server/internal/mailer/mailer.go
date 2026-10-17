// Package mailer 提供基于 net/smtp 的极简邮件发送能力。
//
// 只依赖标准库：本项目的邮件用途单一（找回密码），引入第三方库不划算，
// 且能避免 go.sum 与镜像构建的额外耦合。
package mailer

import (
	"context"
	"crypto/tls"
	"encoding/base64"
	"errors"
	"fmt"
	"mime"
	"net"
	"net/smtp"
	"strconv"
	"strings"
	"time"

	"github.com/xiaoxin-zk/litetunnel/server/internal/config"
)

// Mailer 封装一次 SMTP 投递。
type Mailer struct {
	cfg config.SMTPConfig
}

// New 构造发信器。
func New(cfg config.SMTPConfig) *Mailer { return &Mailer{cfg: cfg} }

// Enabled 表示邮件功能是否可用。未配置时上层应明确告知用户，而不是静默失败。
func (m *Mailer) Enabled() bool { return m.cfg.Enabled() }

// From 返回配置的发件人，供上层展示。
func (m *Mailer) From() string { return m.cfg.From }

// Send 发送一封 HTML 邮件。
//
// ctx 的截止时间覆盖**拨号与会话读写全程**：队列层据此判定「这次没发出去」，
// 两层若各算各的预算，就会出现「队列已判超时并安排重试，SMTP 那边稍后
// 却真的送达了」——用户先收到一封凭据尚未生效的邮件，再收到一封重复的。
// 因此拨号用 DialContext（或把拨号截止对齐到同一个 deadline），连接建立后
// 的读写截止也直接取这个 deadline。
//
// 没有 deadline 的 ctx（例如手工调用）退化为「拨号 10 秒、会话读写 30 秒」。
func (m *Mailer) Send(ctx context.Context, to, subject, htmlBody string) error {
	if !m.Enabled() {
		return errors.New("邮件服务未配置")
	}
	to = strings.TrimSpace(to)
	if to == "" || !strings.Contains(to, "@") {
		return errors.New("收件人地址无效")
	}

	addr := net.JoinHostPort(m.cfg.Host, strconv.Itoa(m.cfg.Port))
	tlsConf := &tls.Config{ServerName: m.cfg.Host, MinVersion: tls.VersionTLS12}

	deadline, hasDeadline := ctx.Deadline()
	dialer := &net.Dialer{Timeout: 10 * time.Second}
	if hasDeadline {
		dialer.Deadline = deadline
	}

	var (
		conn net.Conn
		err  error
	)
	if m.cfg.TLS == "ssl" {
		// 465：隐式 TLS，连上就是加密的。
		// 走 tls.Dialer.DialContext 而不是 tls.DialWithDialer：
		// ctx 取消时拨号能立刻放弃，不必等到 deadline。
		td := &tls.Dialer{NetDialer: dialer, Config: tlsConf}
		conn, err = td.DialContext(ctx, "tcp", addr)
	} else {
		conn, err = dialer.DialContext(ctx, "tcp", addr)
	}
	if err != nil {
		return fmt.Errorf("连接邮件服务器失败: %w", err)
	}
	defer func() { _ = conn.Close() }()
	if hasDeadline {
		// 会话读写与拨号共用同一个截止：外层超时即整体中止，
		// 不会再出现「队列判失败、连接仍在慢慢写」的情况。
		_ = conn.SetDeadline(deadline)
	} else {
		_ = conn.SetDeadline(time.Now().Add(30 * time.Second))
	}

	// ctx 取消时**立刻关闭连接**，而不是只靠 socket deadline：
	// 服务停止时队列会放弃等待发送协程，若 SMTP 会话还跑到截止时间，
	// 期间邮件可能已经送达、状态却仍停在待发送，重启后会重复投递。
	// （关闭会让阻塞中的读写立刻返回错误，Send 随即返回。）
	stopWatch := make(chan struct{})
	defer close(stopWatch)
	go func() {
		select {
		case <-ctx.Done():
			_ = conn.Close()
		case <-stopWatch:
		}
	}()

	client, err := smtp.NewClient(conn, m.cfg.Host)
	if err != nil {
		return fmt.Errorf("建立 SMTP 会话失败: %w", err)
	}
	defer func() { _ = client.Close() }()

	if m.cfg.TLS == "starttls" {
		if ok, _ := client.Extension("STARTTLS"); !ok {
			return errors.New("邮件服务器不支持 STARTTLS，请改用 465/ssl")
		}
		if err := client.StartTLS(tlsConf); err != nil {
			return fmt.Errorf("STARTTLS 协商失败: %w", err)
		}
	}

	if ok, _ := client.Extension("AUTH"); ok {
		auth := smtp.PlainAuth("", m.cfg.User, m.cfg.Password, m.cfg.Host)
		if err := client.Auth(auth); err != nil {
			// QQ 邮箱最常见的坑：填了登录密码而不是授权码。
			return fmt.Errorf("SMTP 认证失败（QQ 邮箱需使用「授权码」而非登录密码）: %w", err)
		}
	}

	// 信封发件人必须是裸地址，显示名只出现在邮件头里。
	if err := client.Mail(envelopeAddress(m.cfg.From)); err != nil {
		return fmt.Errorf("设置发件人失败: %w", err)
	}
	if err := client.Rcpt(to); err != nil {
		return fmt.Errorf("设置收件人失败: %w", err)
	}

	w, err := client.Data()
	if err != nil {
		return fmt.Errorf("开始写入邮件内容失败: %w", err)
	}
	if _, err := w.Write(buildMessage(m.cfg.From, to, subject, htmlBody)); err != nil {
		return fmt.Errorf("写入邮件内容失败: %w", err)
	}
	if err := w.Close(); err != nil {
		return fmt.Errorf("提交邮件内容失败: %w", err)
	}
	return client.Quit()
}

// envelopeAddress 从 `显示名 <addr@host>` 中取出裸地址。
func envelopeAddress(from string) string {
	if i := strings.LastIndex(from, "<"); i >= 0 {
		if j := strings.Index(from[i:], ">"); j > 0 {
			return strings.TrimSpace(from[i+1 : i+j])
		}
	}
	return strings.TrimSpace(from)
}

// buildMessage 组装符合 MIME 规范的邮件。
//
// 标题用 RFC 2047 编码、正文用 Base64：中文直接放进头部或按原文写入正文
// 都可能被某些邮件服务器按单行 998 字节限制截断。
func buildMessage(from, to, subject, htmlBody string) []byte {
	var b strings.Builder
	b.WriteString("From: " + from + "\r\n")
	b.WriteString("To: " + to + "\r\n")
	b.WriteString("Subject: " + mime.BEncoding.Encode("UTF-8", subject) + "\r\n")
	b.WriteString("Date: " + time.Now().Format(time.RFC1123Z) + "\r\n")
	b.WriteString("MIME-Version: 1.0\r\n")
	b.WriteString("Content-Type: text/html; charset=\"UTF-8\"\r\n")
	b.WriteString("Content-Transfer-Encoding: base64\r\n")
	b.WriteString("\r\n")

	encoded := base64.StdEncoding.EncodeToString([]byte(htmlBody))
	// 每 76 字符折行，符合 RFC 2045。
	for len(encoded) > 76 {
		b.WriteString(encoded[:76] + "\r\n")
		encoded = encoded[76:]
	}
	b.WriteString(encoded + "\r\n")
	return []byte(b.String())
}
