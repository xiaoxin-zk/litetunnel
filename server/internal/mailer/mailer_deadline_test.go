package mailer

import (
	"context"
	"net"
	"testing"
	"time"

	"github.com/xiaoxin-zk/litetunnel/server/internal/config"
)

func TestSendHonorsContextDeadline(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("起监听失败: %v", err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			t.Cleanup(func() { _ = conn.Close() })
		}
	}()

	port := ln.Addr().(*net.TCPAddr).Port
	m := New(config.SMTPConfig{
		Host: "127.0.0.1", Port: port, User: "u", Password: "p",
		From: "noreply@example.com", TLS: "none",
	})

	ctx, cancel := context.WithTimeout(context.Background(), 150*time.Millisecond)
	defer cancel()

	start := time.Now()
	err = m.Send(ctx, "user@example.com", "测试", "<p>x</p>")
	elapsed := time.Since(start)

	if err == nil {
		t.Fatal("服务器不响应时应返回错误")
	}
	if elapsed > 3*time.Second {
		t.Fatalf("发送应服从 ctx 截止，实际耗时 %s", elapsed.Round(time.Millisecond))
	}
}

func TestSendUsesDialDeadlineFromContext(t *testing.T) {
	m := New(config.SMTPConfig{
		Host: "198.51.100.1", Port: 25, User: "u", Password: "p",
		From: "noreply@example.com", TLS: "none",
	})

	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()

	start := time.Now()
	err := m.Send(ctx, "user@example.com", "测试", "<p>x</p>")
	elapsed := time.Since(start)
	if err == nil {
		t.Fatal("不可达地址应返回错误")
	}
	if elapsed > 3*time.Second {
		t.Fatalf("拨号应服从 ctx 截止，实际耗时 %s", elapsed.Round(time.Millisecond))
	}
}
