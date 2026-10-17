package service

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/xiaoxin-zk/litetunnel/server/internal/model"
	"gorm.io/gorm"
)

func TestRecoveryMissingPublicURLCountsFailure(t *testing.T) {
	svc, _ := newMailTestServices(t)
	svc.processRecovery(recoveryRequest{account: "any-account"})
	if svc.RecoveryStats()["failed"] != 1 {
		t.Fatal("缺少对外地址必须计为全局配置失败")
	}
}

func TestRecoveryPublicRequestsDoNotQueryAccounts(t *testing.T) {
	svc, _ := newMailTestServices(t)
	u := model.User{Username: "recoverasync", Password: "unused", Email: "recoverasync@example.com", EmailVerified: true, Status: model.UserStatusActive}
	if err := svc.DB.Create(&u).Error; err != nil {
		t.Fatal(err)
	}
	queries := 0
	if err := svc.DB.Callback().Query().Before("gorm:query").Register("recovery:no_sync_queries", func(tx *gorm.DB) {
		queries++
		tx.AddError(errors.New("database unavailable"))
	}); err != nil {
		t.Fatal(err)
	}
	for _, account := range []string{u.Username, "missing"} {
		if err := svc.RequestPasswordReset(account, "127.0.0.1", "https://panel.example.com"); err != nil {
			t.Fatal(err)
		}
	}
	for _, email := range []string{u.Email, "missing@example.com"} {
		if err := svc.SendEmailCode(email, EmailSceneReset, "127.0.0.1"); err != nil {
			t.Fatal(err)
		}
	}
	if queries != 0 || len(svc.recoveryCh) != 4 {
		t.Fatalf("公开路径不得查询账号，queries=%d queued=%d", queries, len(svc.recoveryCh))
	}
	for len(svc.recoveryCh) > 0 {
		svc.processRecovery(<-svc.recoveryCh)
	}
	if queries == 0 {
		t.Fatal("数据库故障必须在后台路径触发")
	}
	if svc.RecoveryStats()["failed"] != 4 {
		t.Fatal("所有后台数据库故障都必须计数")
	}
}

func TestRecoveryQueueFullIsAccountIndependent(t *testing.T) {
	svc, _ := newMailTestServices(t)
	svc.recoveryCh = make(chan recoveryRequest, 1)
	svc.recoveryCh <- recoveryRequest{}
	for _, account := range []string{"known", "unknown"} {
		if err := svc.RequestPasswordReset(account, "127.0.0.1", "https://panel.example.com"); !errors.Is(err, ErrMailQueueFull) {
			t.Fatalf("队满应统一报繁忙: %v", err)
		}
	}
	if err := svc.SendEmailCode("any@example.com", EmailSceneReset, "127.0.0.1"); !errors.Is(err, ErrMailQueueFull) {
		t.Fatal(err)
	}
	if svc.RecoveryStats()["rejected"] != 3 {
		t.Fatal("队列满必须计数")
	}
}

func TestRecoveryWorkerCreatesOutboxOnlyForEligibleAccounts(t *testing.T) {
	for _, code := range []bool{false, true} {
		svc, _ := newMailTestServices(t)
		u := model.User{Username: "workerreset", Password: "unused", Email: "workerreset@example.com", EmailVerified: true, Status: model.UserStatusActive}
		if err := svc.DB.Create(&u).Error; err != nil {
			t.Fatal(err)
		}
		for _, email := range []string{u.Email, "missing@example.com"} {
			var err error
			if code {
				err = svc.SendEmailCode(email, EmailSceneReset, "127.0.0.1")
			} else {
				err = svc.RequestPasswordReset(email, "127.0.0.1", "https://panel.example.com")
			}
			if err != nil {
				t.Fatal(err)
			}
		}
		for len(svc.recoveryCh) > 0 {
			svc.processRecovery(<-svc.recoveryCh)
		}
		var count int64
		if err := svc.DB.Model(&model.MailOutbox{}).Count(&count).Error; err != nil || count != 1 {
			t.Fatalf("只为有效账号写发件箱: count=%d err=%v", count, err)
		}
	}
}

func TestRecoveryWorkerHonorsCancelledContext(t *testing.T) {
	svc, _ := newMailTestServices(t)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	svc.recoveryCh <- recoveryRequest{account: "unused"}
	svc.StartRecoveryWorker(ctx)
	time.Sleep(20 * time.Millisecond)
	if len(svc.recoveryCh) != 1 {
		t.Fatal("已取消的 worker 不应消费请求")
	}
}
