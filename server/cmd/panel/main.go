package main

import (
	"context"
	"errors"
	"log"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/gin-gonic/gin"

	"github.com/xiaoxin-zk/litetunnel/server/internal/auth"
	"github.com/xiaoxin-zk/litetunnel/server/internal/config"
	"github.com/xiaoxin-zk/litetunnel/server/internal/handler/adminapi"
	"github.com/xiaoxin-zk/litetunnel/server/internal/handler/authapi"
	"github.com/xiaoxin-zk/litetunnel/server/internal/handler/frpsplugin"
	"github.com/xiaoxin-zk/litetunnel/server/internal/handler/userapi"
	"github.com/xiaoxin-zk/litetunnel/server/internal/router"
	"github.com/xiaoxin-zk/litetunnel/server/internal/service"
	"github.com/xiaoxin-zk/litetunnel/server/internal/store"
)

func main() {
	log.SetFlags(log.LstdFlags | log.Lmsgprefix)
	log.SetPrefix("[litetunnel] ")

	cfg, err := config.Load()
	if err != nil {
		log.Fatalf("配置加载失败: %v", err)
	}
	if cfg.IsProd() {
		gin.SetMode(gin.ReleaseMode)
	}

	db, err := store.Open(cfg)
	if err != nil {
		log.Fatalf("数据库初始化失败: %v", err)
	}
	createdAdmin, err := store.Seed(db, cfg, auth.HashPassword)
	if err != nil {
		log.Fatalf("初始数据播种失败: %v", err)
	}
	printStartupWarnings(cfg, createdAdmin)

	svc := service.New(db, cfg)

	svc.LoadAccessGuard()

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	logCtx, stopLog := context.WithCancel(context.Background())
	defer stopLog()

	workers := []workerRun{
		{"traffic-collector", svc.StartTrafficCollector(ctx)},
		{"login-log-writer", svc.StartLoginLogWriter(logCtx)},
		{"mail-worker", svc.StartMailWorker(ctx)},
		{"recovery-worker", svc.StartRecoveryWorker(ctx)},
		{"maintenance-worker", svc.StartMaintenanceWorker(ctx)},
		{"firewall-reconciler", svc.StartFirewallReconciler(ctx)},
		{"proxy-drain-worker", svc.StartProxyDrainWorker(ctx)},
		{"alert-worker", svc.StartAlertWorker(ctx)},
		{"report-worker", svc.StartReportWorker(ctx)},
	}
	monDone := make(chan struct{})
	go func() {
		defer close(monDone)
		svc.Monitor.Start(ctx)
	}()
	workers = append(workers, workerRun{"monitor", monDone})

	engine := router.New(cfg, svc,
		authapi.New(svc, cfg.AdminPath),
		userapi.New(svc),
		adminapi.New(svc),
		frpsplugin.New(svc, cfg.FrpsPluginAllowCIDRs))

	srv := newServer(cfg.UserAddr, engine)
	// 稳定运行 30 秒后清除「更新待确认」标记，供启动脚本判断是否需要回滚。
	svc.ConfirmStartup()

	go func() {
		log.Printf("LiteTunnel %s 启动中（环境 %s）", config.Version, cfg.Env)
		log.Printf("控制面监听于 %s", cfg.UserAddr)
		log.Printf("  用户控制台  http://%s/", cfg.UserAddr)
		log.Printf("  管理后台    http://%s%s/", cfg.UserAddr, cfg.AdminPath)
		if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			log.Fatalf("服务异常退出: %v", err)
		}
	}()

	<-ctx.Done()
	log.Println("收到退出信号，正在优雅关闭…")

	shutdownCtx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	_ = srv.Shutdown(shutdownCtx)

	stopLog()

	waitWorkers(workers)

	svc.Close()
	log.Println("已退出")
}

const workerShutdownWait = 5 * time.Second

type workerRun struct {
	name string
	done <-chan struct{}
}

func waitWorkers(workers []workerRun) {
	if len(workers) == 0 {
		return
	}
	var wg sync.WaitGroup
	wg.Add(len(workers))
	for _, w := range workers {
		go func(w workerRun) {
			defer wg.Done()
			<-w.done
		}(w)
	}
	allDone := make(chan struct{})
	go func() {
		wg.Wait()
		close(allDone)
	}()
	select {
	case <-allDone:
		return
	case <-time.After(workerShutdownWait):
		remaining := make([]string, 0, len(workers))
		for _, w := range workers {
			select {
			case <-w.done:
			default:
				remaining = append(remaining, w.name)
			}
		}
		log.Printf("后台 worker 未在 %s 内全部退出，仍在运行：%s",
			workerShutdownWait, strings.Join(remaining, ", "))
	}
}

func printStartupWarnings(cfg *config.Config, createdAdmin bool) {
	if len(cfg.GeneratedSecrets) > 0 {
		log.Printf("【注意】以下密钥未通过环境变量提供，已随机生成（重启后失效）：%s",
			strings.Join(cfg.GeneratedSecrets, ", "))
	}
	if cfg.EphemeralAdminPassword && createdAdmin {
		log.Printf("【注意】初始管理员账号 %s，密码 %s（本次随机生成，重启后不再打印）",
			cfg.BootstrapAdminUser, cfg.BootstrapAdminPassword)
		log.Printf("【注意】请登录后立即修改密码，并启用双因素认证")
	}
	for _, w := range cfg.Warnings {
		log.Printf("【警告】%s", w)
	}
	if !cfg.IsProd() {
		log.Printf("【警告】当前为 %s 环境，安全校验已放宽，请勿用于公网部署", cfg.Env)
	}
}

func newServer(addr string, handler http.Handler) *http.Server {
	return &http.Server{
		Addr:              addr,
		Handler:           handler,
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      4 * time.Minute,
		IdleTimeout:       90 * time.Second,
		MaxHeaderBytes:    1 << 20,
	}
}
