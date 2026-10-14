// Command panel 是 LiteTunnel 的控制面服务端。
//
// 它同时监听两个地址：
//   - 用户侧（默认 0.0.0.0:8080）：用户控制台与其 API，可对公网暴露；
//   - 管理侧（默认 127.0.0.1:8443）：管理员后台与其 API、frps 插件回调，
//     默认不监听公网，需通过本机反代或 VPN 访问。
package main

import (
	"context"
	"errors"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/gin-gonic/gin"

	"github.com/xiaoxin-zk/litetunnel/server/internal/auth"
	"github.com/xiaoxin-zk/litetunnel/server/internal/config"
	"github.com/xiaoxin-zk/litetunnel/server/internal/handler/adminapi"
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
	if err := store.Seed(db, cfg, auth.HashPassword); err != nil {
		log.Fatalf("初始数据播种失败: %v", err)
	}

	svc := service.New(db, cfg)

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	svc.StartTrafficCollector(ctx)

	userRouter := router.NewUser(cfg, svc, userapi.New(svc))
	adminRouter := router.NewAdmin(cfg, svc, adminapi.New(svc), frpsplugin.New(svc, cfg.FrpsPluginAllowCIDRs))

	userSrv := newServer(cfg.UserAddr, userRouter)
	adminSrv := newServer(cfg.AdminAddr, adminRouter)

	errCh := make(chan error, 2)
	go func() {
		log.Printf("用户控制台监听于 %s", cfg.UserAddr)
		if err := userSrv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			errCh <- err
		}
	}()
	go func() {
		log.Printf("管理后台监听于 %s（请勿直接对公网暴露）", cfg.AdminAddr)
		if err := adminSrv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			errCh <- err
		}
	}()

	select {
	case err := <-errCh:
		log.Fatalf("服务异常退出: %v", err)
	case <-ctx.Done():
		log.Println("收到退出信号，正在优雅关闭…")
	}

	shutdownCtx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	_ = userSrv.Shutdown(shutdownCtx)
	_ = adminSrv.Shutdown(shutdownCtx)
	log.Println("已退出")
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
