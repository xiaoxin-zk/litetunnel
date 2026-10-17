package mailer

import (
	"context"
	"net"
	"testing"
	"time"

	"github.com/xiaoxin-zk/litetunnel/server/internal/config"
)

// TestSendHonorsContextDeadline 覆盖「发送总预算贯穿拨号与会话」。
//
// 假 SMTP 服务器接受连接后一言不发（慢连接/挂死）。调用方的 ctx 截止
// 必须真正中断会话读写：以前会话超时是客户端内部固定的 30 秒，队列层
// 30 秒判超时后安排重试，而这封信仍可能稍后送达——用户会先收到一封
// 凭据尚未生效的邮件，再收到一封重复的。
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
			// 收下连接就不说话：模拟不响应的 SMTP 服务器。
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
	// 截止 150ms；给调度与收尾留足余量，但必须远小于固定的 30 秒会话超时。
	if elapsed > 3*time.Second {
		t.Fatalf("发送应服从 ctx 截止，实际耗时 %s", elapsed.Round(time.Millisecond))
	}
}

// TestSendUsesDialDeadlineFromContext 覆盖「拨号也吃同一个截止」。
//
// 拨号到不可达地址（黑洞地址）时，若只有 10 秒的固定拨号超时，外层
// 早已判失败、拨号仍在继续。这里把截止压到 100ms，要求整体尽快返回。
func TestSendUsesDialDeadlineFromContext(t *testing.T) {
	m := New(config.SMTPConfig{
		// 198.51.100.0/24 是 TEST-NET-2，正常网络里不可路由。
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
