package main

import (
	"context"
	"fmt"
	"log"
	"net/http"
	"os/exec"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/xiaoxin-zk/litetunnel/client/internal/frpc"
)

type TunnelVO struct {
	ID                uint   `json:"id"`
	Name              string `json:"name"`
	Type              string `json:"type"`
	LocalIP           string `json:"local_ip"`
	LocalPort         int    `json:"local_port"`
	PublicAddr        string `json:"public_addr"`
	Status            string `json:"status"`
	Online            bool   `json:"online"`
	TrafficUsed       int64  `json:"traffic_used"`
	BandwidthLimitStr string `json:"bandwidth_limit_str"`

	Running bool `json:"running"`

	Registered bool `json:"registered"`

	PendingSeconds int `json:"pending_seconds,omitempty"`

	LastError   string     `json:"last_error"`
	LastErrorAt *time.Time `json:"last_error_at"`

	ConfigRev string `json:"config_rev,omitempty"`
}

type State struct {
	ServerURL      string `json:"server_url"`
	ServerFixed    bool   `json:"server_fixed"`
	NeedsServerURL bool   `json:"needs_server_url"`

	LoggedIn   bool   `json:"logged_in"`
	Username   string `json:"username"`
	APIKeyMask string `json:"api_key_mask"`

	GatewayHost  string     `json:"gateway_host"`
	GatewayPort  int        `json:"gateway_port"`
	FrontendURL  string     `json:"frontend_url"`
	TunnelDomain string     `json:"tunnel_domain"`
	Tunnels      []TunnelVO `json:"tunnels"`
	TrafficUsed  int64      `json:"traffic_used"`
	TrafficQuota int64      `json:"traffic_quota"`
	Exceeded     bool       `json:"exceeded"`

	Running    bool   `json:"running"`
	FrpcFound  bool   `json:"frpc_found"`
	FrpcPath   string `json:"frpc_path"`
	ConfigPath string `json:"config_path"`

	Group          *groupLimit `json:"group,omitempty"`
	PaymentEnabled bool        `json:"payment_enabled"`
	BalanceCents   int64       `json:"balance_cents"`

	LastSyncAt *time.Time `json:"last_sync_at"`
	SyncErr    string     `json:"sync_err"`

	ConfigError string `json:"config_error"`
	Version     string `json:"version"`

	LogEpoch uint64 `json:"log_epoch"`

	StateSeq uint64 `json:"state_seq"`

	AuthGen uint64 `json:"auth_gen"`
}

type App struct {
	ctx context.Context

	startedAt time.Time

	mu   sync.RWMutex
	cfg  *Config
	mgr  *frpc.Manager
	http *http.Client

	tunnels      []TunnelVO
	username     string
	apiKeyMask   string
	gatewayHost  string
	gatewayPort  int
	frontendURL  string
	tunnelDomain string
	trafficUsed  int64
	trafficQuota int64
	exceeded     bool
	lastError    string

	group          *groupLimit
	paymentEnabled bool
	balanceCents   int64

	applied    map[uint]string
	lastSyncAt time.Time
	syncErr    string

	cleanupErr string

	cfgRev map[uint]string

	syncGate chan struct{}
	gateOnce sync.Once

	authMu sync.Mutex

	authGeneration uint64

	syncStart int

	syncRoot   context.Context
	syncCancel context.CancelFunc

	closeDone sync.Once

	syncSeq        atomic.Uint64
	appliedSyncSeq uint64

	domReadyOnce sync.Once

	tunnelErrs map[uint]tunnelErr

	cleanupWarned map[uint]bool

	registered map[uint]bool

	registeredAt map[uint]time.Time

	connectAt map[uint]time.Time

	errEmitAt map[uint]time.Time

	logMu       sync.Mutex
	logBuf      []pendingLog
	logBufBytes int
	logDropped  int

	logEpoch      uint64
	logDroppedSeq uint64
	logKick       chan struct{}
	stateKick     chan struct{}
	logStop       chan struct{}
	logStopOnce   sync.Once
	logWg         sync.WaitGroup

	retries map[uint]*retryState

	stopIntents map[uint]uint64

	startGen map[uint]uint64

	cfgErr string

	stateSeq uint64
}

func NewApp() *App {
	cfg, cfgErr := loadConfig()
	if cfgErr != nil {
		log.Printf("[client] %v", cfgErr)
	}

	exePath, err := ensureFrpc()
	if err != nil {
		log.Printf("[client] %v，将回退到同目录查找 frpc.exe", err)
		exePath = ""
	}
	frpc.SetStrictLookup(len(embeddedFrpc) > 0)

	syncCtx, syncCancel := context.WithCancel(context.Background())

	app := &App{
		cfg:          cfg,
		mgr:          frpc.New(exePath),
		syncRoot:     syncCtx,
		syncCancel:   syncCancel,
		applied:      map[uint]string{},
		cfgRev:       map[uint]string{},
		tunnelErrs:   map[uint]tunnelErr{},
		retries:      map[uint]*retryState{},
		registered:   map[uint]bool{},
		registeredAt: map[uint]time.Time{},
		connectAt:    map[uint]time.Time{},
		errEmitAt:    map[uint]time.Time{},
		startGen:     map[uint]uint64{},
		logKick:      make(chan struct{}, 1),
		stateKick:    make(chan struct{}, 1),
		logStop:      make(chan struct{}),
		startedAt:    time.Now(),
		http: &http.Client{
			Timeout: 15 * time.Second,
		},
	}
	if cfgErr != nil {
		app.cfgErr = cfgErr.Error()
	}
	return app
}

func (a *App) startup(ctx context.Context) {
	a.ctx = ctx
	a.startLogFlusher()
	a.logWg.Add(1)
	go func() {
		defer a.logWg.Done()
		a.stateLoop()
	}()
	a.mgr.SetAccountCallbacks(func(acct uint64, id uint, name string, gen uint64, seq uint64, line string) {
		if gen == 0 {
			epoch := accountEpoch(acct)
			if !epoch.known() {
				epoch = a.captureEpoch()
			}
			a.appendLogLineAcct(epoch, seq, line)
			return
		}

		epoch, ok := a.tunnelEpoch(id)
		if !ok {
			return
		}
		if !a.mgr.Current(id, gen) {
			return
		}
		if !a.appendLogLineAcct(epoch, seq, line) {
			return
		}
		if !a.epochCurrent(epoch) {
			return
		}
		body := frpc.StripLogPrefix(line)
		switch {
		case strings.Contains(body, "start proxy success"):
			a.clearTunnelErrAcct(id, epoch, gen)
			a.clearRetryAcct(id, epoch, gen)
			a.setTunnelRegisteredAcct(id, epoch, gen, true)
			a.emitTunnelReadyEpoch(epoch, id, name)
			if a.epochCurrent(epoch) {
				a.requestState()
			}
		case frpc.IsErrorLine(line):
			if a.recordTunnelErrMsgAcct(id, epoch, gen, frpc.StripLogPrefix(line)) && a.epochCurrent(epoch) {
				a.requestState()
			}
		}
	}, func(id uint, name string, gen uint64, err error, requested bool) {
		if !a.mgr.Current(id, gen) {
			return
		}
		a.onTunnelExitGen(id, name, gen, err, requested)
	})
}

func (a *App) onTunnelExit(id uint, name string, err error, requested bool) {
	a.onTunnelExitGen(id, name, 0, err, requested)
}

func (a *App) onTunnelExitGen(id uint, name string, gen uint64, err error, requested bool) {
	startEpoch, current := a.startGeneration(id)
	if !current {
		return
	}
	epoch := accountEpoch(startEpoch)
	if !a.epochCurrent(epoch) {
		return
	}
	a.setTunnelRegisteredAcct(id, epoch, gen, false)
	if !a.epochCurrent(epoch) {
		return
	}
	if a.consumeStopIntent(id, gen) {
		requested = true
	}
	if !a.epochCurrent(epoch) {
		return
	}
	switch {
	case requested:
		a.clearRetryAcct(id, epoch, gen)
	default:
		reason := "frpc 已退出"
		if err != nil {
			reason = "frpc 异常退出：" + err.Error()
		}
		a.noteStartFailureAcct(id, epoch, gen, name, reason)
	}
	if a.epochCurrent(epoch) {
		a.emitState()
	}
}

func (a *App) domReady(ctx context.Context) {
	a.domReadyOnce.Do(func() { a.startOnce(ctx) })
}

func (a *App) startOnce(ctx context.Context) {
	a.startAutoSync(ctx)

	go func() {
		timer := time.NewTimer(300 * time.Millisecond)
		defer timer.Stop()
		select {
		case <-a.rootContext().Done():
			return
		case <-timer.C:
		}

		a.mu.RLock()
		hasKey := a.cfg.APIKey != ""
		a.mu.RUnlock()
		if !hasKey {
			return
		}

		gen := a.currentAuthGen()
		start := time.Now()
		if _, err := a.syncLocked(); err != nil {
			if a.authGenCurrent(gen) {
				a.emitLog("启动同步失败：" + err.Error())
			}
		} else {
			if a.authGenCurrent(gen) {
				a.emitLog(fmt.Sprintf("启动同步完成：%d 条隧道运行中（%d 条已停用，用时 %s，自客户端启动 %s）",
					len(a.mgr.RunningIDs()), a.countDisabledTunnels(),
					time.Since(start).Round(time.Millisecond),
					time.Since(a.startedAt).Round(100*time.Millisecond)))
			}
		}
		if a.authGenCurrent(gen) {
			a.emitState()
		}
	}()
}

const shutdownSyncWait = 3 * time.Second

func (a *App) shutdown(ctx context.Context) {
	a.closeDone.Do(func() {
		if a.syncCancel != nil {
			a.syncCancel()
		}

		done := make(chan struct{})
		go func() {
			a.lockSyncBlocking()
			a.unlockSync()
			close(done)
		}()
		select {
		case <-done:
		case <-time.After(shutdownSyncWait):
			log.Printf("[client] 退出时等待同步结束超时（%s），继续停止 frpc", shutdownSyncWait)
		}

		if err := a.mgr.Close(); err != nil {
			log.Printf("[client] 退出时停止 frpc 失败: %v", err)
		}
	})

	if a.logStop != nil {
		a.logStopOnce.Do(func() { close(a.logStop) })
		done := make(chan struct{})
		go func() {
			a.logWg.Wait()
			close(done)
		}()
		select {
		case <-done:
		case <-time.After(shutdownDrainTimeout):
			log.Printf("[client] 退出时仍有日志/状态推送未完成（UI 可能已销毁），不再等待")
		}
	}
	a.flushLogs()
}

const shutdownDrainTimeout = 2 * time.Second

func (a *App) OpenDataDir() (string, error) {
	dir, err := dataDir()
	if err != nil {
		return "", err
	}
	var cmd *exec.Cmd
	switch runtime.GOOS {
	case "windows":
		cmd = exec.Command("explorer", dir)
	case "darwin":
		cmd = exec.Command("open", dir)
	default:
		cmd = exec.Command("xdg-open", dir)
	}
	if err := cmd.Start(); err != nil {
		return dir, fmt.Errorf("打开数据目录失败: %w", err)
	}
	return dir, nil
}
