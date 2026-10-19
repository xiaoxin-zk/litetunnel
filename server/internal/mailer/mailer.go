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

type Mailer struct {
	cfg config.SMTPConfig
}

func New(cfg config.SMTPConfig) *Mailer { return &Mailer{cfg: cfg} }

func (m *Mailer) Enabled() bool { return m.cfg.Enabled() }

func (m *Mailer) From() string { return m.cfg.From }

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
		_ = conn.SetDeadline(deadline)
	} else {
		_ = conn.SetDeadline(time.Now().Add(30 * time.Second))
	}

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
			return fmt.Errorf("SMTP 认证失败（QQ 邮箱需使用「授权码」而非登录密码）: %w", err)
		}
	}

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

func envelopeAddress(from string) string {
	if i := strings.LastIndex(from, "<"); i >= 0 {
		if j := strings.Index(from[i:], ">"); j > 0 {
			return strings.TrimSpace(from[i+1 : i+j])
		}
	}
	return strings.TrimSpace(from)
}

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
	for len(encoded) > 76 {
		b.WriteString(encoded[:76] + "\r\n")
		encoded = encoded[76:]
	}
	b.WriteString(encoded + "\r\n")
	return []byte(b.String())
}
