package mailer

import (
	"context"
	"net"
	"testing"
	"time"

	"github.com/xiaoxin-zk/litetunnel/server/internal/config"
)

func TestSendAbortsOnContextCancel(t *testing.T) {
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

	m := New(config.SMTPConfig{
		Host: "127.0.0.1", Port: ln.Addr().(*net.TCPAddr).Port,
		User: "u", Password: "p", From: "noreply@example.com", TLS: "none",
	})

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() {
		time.Sleep(150 * time.Millisecond)
		cancel()
	}()

	start := time.Now()
	err = m.Send(ctx, "user@example.com", "测试", "<p>x</p>")
	elapsed := time.Since(start)

	if err == nil {
		t.Fatal("取消后发送不应返回成功")
	}
	if elapsed > 3*time.Second {
		t.Fatalf("取消应立即中断会话，实际耗时 %s", elapsed.Round(time.Millisecond))
	}
}
