// Command panel 是 LiteTunnel 的控制面服务端。
//
// 单一公网入口：用户控制台与管理后台共用同一监听地址，通过路径区分
// （用户控制台在 /，管理后台在 /admin）。安全由四层机制共同保证：
// 令牌域隔离、IP 限流、账号级锁定、管理员双因素认证；
// 可选地通过 LT_ADMIN_ALLOW_CIDR 进一步限制管理后台来源。
package main

import (
	"context"
	"errors"
	"log"
	"net/http"
	"os"
	"os/signal"
	"strings"
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

	// 准入状态必须在开始监听**之前**同步加载完。
	//
	// 超额与禁用标记只在内存里，由后台采集维护；而插件热路径查不到它时，
	// 「没有这一条」与「该账号没问题」是同一个样子。异步启动采集意味着
	// 从监听开始到第一次采集成功之间有一段窗口：那时所有客户端都在重连，
	// 超额用户与已禁用账号会被照常放行。所以这里同步取一次（失败也不阻断
	// 启动，但状态保持「未知」，插件会拒绝，由采集协程重试）。
	svc.LoadAccessGuard()

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	svc.StartTrafficCollector(ctx)
	svc.StartLoginLogWriter(ctx)
	svc.StartMailWorker(ctx)
	svc.StartRecoveryWorker(ctx)
	// 短期数据（过期验证码、用完的令牌、终态邮件记录）的周期清理。
	// 没有它，公网服务跑久了这几张表会一直膨胀。
	svc.StartMaintenanceWorker(ctx)
	fwDone := svc.StartFirewallReconciler(ctx)
	// 系统指标采集：每 5 秒一次，只写内存环形缓冲。
	go svc.Monitor.Start(ctx)

	engine := router.New(cfg, svc,
		authapi.New(svc, cfg.AdminPath),
		userapi.New(svc),
		adminapi.New(svc),
		frpsplugin.New(svc, cfg.FrpsPluginAllowCIDRs))

	srv := newServer(cfg.UserAddr, engine)

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

	// 等协调器退出再返回：它可能正在访问数据库或调用 helper，
	// 进程先走会让那次写操作停在半路。
	select {
	case <-fwDone:
	case <-time.After(5 * time.Second):
		log.Println("防火墙协调器未在 5 秒内退出，继续关闭")
	}
	log.Println("已退出")
}

// printStartupWarnings 输出启动期的安全提示。
//
// 非生产环境会自动生成随机密钥与初始密码，必须明确告知使用者：
// 这些值重启即变，且该环境的安全校验是放宽的，绝不能用于公网。
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

// newServer 构造带安全超时的 HTTP 服务，避免慢连接耗尽资源。
func newServer(addr string, handler http.Handler) *http.Server {
	return &http.Server{
		Addr:              addr,
		Handler:           handler,
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      60 * time.Second,
		IdleTimeout:       90 * time.Second,
		MaxHeaderBytes:    1 << 20,
	}
}
