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

	// 登录日志落库协程用**独立的** ctx，不能与其它 worker 共用信号 ctx。
	//
	// 那个协程在结束时会先把队列里剩下的日志刷完再返回。若共用信号 ctx，
	// 结束信号与 HTTP 关闭同时到达，而在途请求此时还在写登录日志：它们
	// 入队的记录落在 drain 之后，退出时被静默丢掉——丢的恰好是「退出前
	// 最后几条」，而审计记录的价值往往就在出事那一段。
	// 所以它的取消时机推迟到 srv.Shutdown 之后（见下方 stopLog）。
	logCtx, stopLog := context.WithCancel(context.Background())
	defer stopLog()

	// 统一收集后台 worker 的退出信号，关闭阶段逐个等待（见 waitWorkers）。
	// 之前只有防火墙协调器被等待，其余 worker 在进程退出时可能还握着
	// 数据库连接或 SMTP 会话，尾部数据会丢。
	workers := []<-chan struct{}{
		svc.StartTrafficCollector(ctx),
		svc.StartLoginLogWriter(logCtx),
		svc.StartMailWorker(ctx),
		svc.StartRecoveryWorker(ctx),
		// 短期数据（过期验证码、用完的令牌、终态邮件记录）的周期清理。
		// 没有它，公网服务跑久了这几张表会一直膨胀。
		svc.StartMaintenanceWorker(ctx),
		svc.StartFirewallReconciler(ctx),
		// 断流待办的补偿重试：禁用/删号时若 frps 管理接口不可用，那批代理
		// 关不掉，只把意图落库（lt_proxy_drain_pending）。没有这个 worker，
		// 落库的待办就没有任何执行者——账号已禁用、流量却一直跑着，重启
		// 也不会好转，而这从业务界面上完全看不出来。
		svc.StartProxyDrainWorker(ctx),
	}
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

	// HTTP 已停止接收新请求、在途请求处理完毕，这时才让日志协程收尾：
	// 它会把队列里剩下的记录刷进库再返回（见 logCtx 处的说明）。
	stopLog()

	// 统一等待所有后台 worker 退出再返回：它们可能正在访问数据库或调用
	// helper/SMTP，进程先走会让那次写操作停在半路、尾部数据丢失。
	waitWorkers(workers)

	// 最后关掉 Services 自己起的 gc 协程（验证码存储、登录锁定器）。
	// 放在 worker 之后：它们可能仍在读这两份内存状态。
	svc.Close()
	log.Println("已退出")
}

// workerShutdownWait 是关闭阶段等待全部后台 worker 退出的总上限。
//
// 各 worker 都在 select 里监听 ctx.Done()，正常情况下收到退出信号后几毫秒内
// 就会返回；留这个上限是防止某个 worker 卡在写盘、网络调用上，让窗口/进程
// 无限期关不掉。
const workerShutdownWait = 5 * time.Second

// waitWorkers 等待所有后台 worker 退出，超过总上限则记录并继续关闭。
func waitWorkers(workers []<-chan struct{}) {
	if len(workers) == 0 {
		return
	}
	allDone := make(chan struct{})
	go func() {
		for _, done := range workers {
			<-done
		}
		close(allDone)
	}()
	select {
	case <-allDone:
		return
	case <-time.After(workerShutdownWait):
		log.Println("后台 worker 未在 5 秒内全部退出，继续关闭")
	}
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
		ReadTimeout: 30 * time.Second,
		// 写超时必须大于配置下发链路的**最坏**耗时：域名/证书下发会调用
		// lt-config 完成渲染、容器校验、重建与稳定检查，客户端那侧的
		// renderTimeout 是 3 分钟。以前这里是 60 秒，长于一分钟的合法下发
		// 会在面板侧被写超时切断，管理员看到的是「请求失败」，而 helper
		// 其实已经改完配置并重建了容器——这是最难排查的一类不一致。
		WriteTimeout: 4 * time.Minute,
		IdleTimeout:  90 * time.Second,
		MaxHeaderBytes:    1 << 20,
	}
}
