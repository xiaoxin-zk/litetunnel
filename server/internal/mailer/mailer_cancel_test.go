package mailer

import (
	"context"
	"net"
	"testing"
	"time"

	"github.com/xiaoxin-zk/litetunnel/server/internal/config"
)

// TestSendAbortsOnContextCancel 覆盖「取消立即中断 SMTP 会话」。
//
// 只设固定 socket deadline 时，服务停止（ctx 取消）后 SMTP 操作仍会跑到
// 30 秒截止：期间邮件可能已经送达，而状态还停在待发送，重启后会重复投递。
// 取消必须直接关闭连接，让阻塞中的读写立刻返回。
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
			// 收下连接就不说话：模拟卡住的 SMTP 会话。
			t.Cleanup(func() { _ = conn.Close() })
		}
	}()

	m := New(config.SMTPConfig{
		Host: "127.0.0.1", Port: ln.Addr().(*net.TCPAddr).Port,
		User: "u", Password: "p", From: "noreply@example.com", TLS: "none",
	})

	// 只取消、不给 deadline：此时唯一的退出机制就是「取消即关连接」。
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
	// 没有 deadline 时默认 socket 超时是 30 秒；取消必须远早于此。
	if elapsed > 3*time.Second {
		t.Fatalf("取消应立即中断会话，实际耗时 %s", elapsed.Round(time.Millisecond))
	}
}
