package main

import (
	"context"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"
)

func main() {
	var (
		addr = flag.String("addr", envOr("LT_CFG_ADDR", "127.0.0.1:7850"),
			"监听地址，必须是回环地址")
		token = flag.String("token", os.Getenv("LT_CFG_TOKEN"),
			"访问令牌（必填，至少 16 字符）")
		deployDir = flag.String("deploy-dir", envOr("LT_CFG_DEPLOY_DIR", "./deploy"),
			"部署目录（docker-compose.yml 与模板所在处）")
		envFile = flag.String("env-file", os.Getenv("LT_CFG_ENV_FILE"),
			".env 路径，默认取部署目录的上一级")
		composeFile = flag.String("compose-file", os.Getenv("LT_CFG_COMPOSE_FILE"),
			"docker-compose.yml 路径，默认取部署目录下的同名文件")
		caddyTpl = flag.String("caddy-template", os.Getenv("LT_CFG_CADDY_TPL"),
			"Caddyfile 模板路径")
		caddyOut = flag.String("caddy-out", os.Getenv("LT_CFG_CADDY_OUT"),
			"Caddyfile 输出路径")
		frpsTpl = flag.String("frps-template", os.Getenv("LT_CFG_FRPS_TPL"),
			"frps.toml 模板路径")
		frpsOut = flag.String("frps-out", os.Getenv("LT_CFG_FRPS_OUT"),
			"frps.toml 输出路径")
		caddyData = flag.String("caddy-data", os.Getenv("LT_CFG_CADDY_DATA"),
			"Caddy 数据目录，用于读取证书状态")
		caddyImage = flag.String("caddy-image", os.Getenv("LT_CFG_CADDY_IMAGE"),
			"校验用的 Caddy 镜像，默认取 .env 的 LT_CADDY_IMAGE")
		frpsImage = flag.String("frps-image", envOr("LT_CFG_FRPS_IMAGE", "fatedier/frps:v0.71.0"),
			"校验用的 frps 镜像")
		validateFrps = flag.Bool("validate-frps", envBool("LT_CFG_VALIDATE_FRPS", true),
			"是否用 frps verify 校验渲染出的 frps.toml")
		allowApply = flag.Bool("apply", envBool("LT_CFG_APPLY", true),
			"是否允许重建容器（false 时只渲染与校验，用于演练）")
	)
	flag.Parse()

	if raw := strings.TrimSpace(os.Getenv("LT_CFG_VALIDATE_FRPS")); raw != "" {
		if _, err := strconv.ParseBool(raw); err != nil {
			log.Fatalf("LT_CFG_VALIDATE_FRPS 配置无效（%q），请使用 true 或 false: %v", raw, err)
		}
	}
	if raw := strings.TrimSpace(os.Getenv("LT_CFG_APPLY")); raw != "" {
		if _, err := strconv.ParseBool(raw); err != nil {
			log.Fatalf("LT_CFG_APPLY 配置无效（%q），请使用 true 或 false: %v", raw, err)
		}
	}

	p := newPaths(*deployDir, *envFile, *composeFile, *caddyTpl, *caddyOut, *frpsTpl, *frpsOut, *caddyData)

	if *validateFrps {
		resolved, ok := composeServiceImageViaDocker(p.composeFile, p.envFile, "frps")
		if !ok {
			img, err := composeServiceImage(p.composeFile, "frps")
			if err != nil {
				log.Fatalf("[lt-config] 无法从 Compose 读取 frps 镜像，无法确认校验镜像与实际运行镜像一致: %v", err)
			}
			if resolved, ok = resolveComposeImage(img, composeEnvLookup(p.envFile)); !ok {
				log.Fatalf("[lt-config] Compose 的 frps 镜像 %q 含无法解析的变量，无法确认校验镜像与实际运行镜像一致", img)
			}
		}
		if *frpsImage != resolved {
			log.Fatalf("[lt-config] 校验用的 frps 镜像（%s）与 Compose 实际使用的镜像（%s）不一致："+
				"请让 LT_CFG_FRPS_IMAGE 与 Compose 中的 image 相同，或取消前者", *frpsImage, resolved)
		}
	}
	if err := validateManagedPaths(p); err != nil {
		log.Fatalf("[lt-config] %v", err)
	}

	blockedDirs := cleanupLeftovers(p)
	for _, dir := range blockedDirs {
		log.Printf("[lt-config] 警告：%s 存在未能自动收敛的配置现场（批次记录/备份与目标内容无法对齐）。"+
			"本次进程将拒绝所有写盘请求，请先人工确认该目录下的 %s 与 %s 备份，再手工清理",
			dir, batchManifestName, backupSuffix)
	}
	if err := validateConfig(*addr, *token, p); err != nil {
		log.Fatalf("[lt-config] %v", err)
	}

	srv := &service{
		token:        *token,
		paths:        p,
		caddyImage:   *caddyImage,
		frpsImage:    *frpsImage,
		validateFrps: *validateFrps,
		allowApply:   *allowApply,
		blockedDirs:  blockedDirs,
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/health", srv.handleHealth)
	mux.HandleFunc("/render", srv.handleRender)
	mux.HandleFunc("/apply", srv.handleApply)
	mux.HandleFunc("/dns/check", srv.handleDNSCheck)
	mux.HandleFunc("/certs", srv.handleCerts)

	rootCtx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	httpSrv := &http.Server{
		Addr:              *addr,
		Handler:           srv.auth(mux),
		BaseContext:       func(net.Listener) context.Context { return rootCtx },
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      writeTimeout,
	}

	shutdownDone := make(chan struct{})
	go func() {
		defer close(shutdownDone)
		<-rootCtx.Done()
		shutdownCtx, cancel := context.WithTimeout(context.Background(), shutdownTimeout)
		defer cancel()
		if err := httpSrv.Shutdown(shutdownCtx); err != nil {
			log.Printf("[lt-config] 关闭时出错: %v", err)
		}
	}()

	log.Printf("[lt-config] 部署目录 %s", p.deployDir)
	log.Printf("[lt-config] 监听 %s（重建容器：%v，frps 校验：%v）", *addr, *allowApply, *validateFrps)
	err := httpSrv.ListenAndServe()
	if err != nil && !errors.Is(err, http.ErrServerClosed) {
		log.Fatalf("[lt-config] 服务退出: %v", err)
	}
	if errors.Is(err, http.ErrServerClosed) {
		<-shutdownDone
	}
}

func composeEnvLookup(envPath string) func(string) string {
	vars := map[string]string{}
	if _, parsed, err := readEnvFile(envPath); err != nil {
		log.Printf("[lt-config] 读取 %s 失败，Compose 镜像里的变量只能来自进程环境: %v", envPath, err)
	} else {
		vars = parsed
	}
	return func(name string) string {
		if v, ok := os.LookupEnv(name); ok && strings.TrimSpace(v) != "" {
			return v
		}
		return vars[name]
	}
}

const (
	writeTimeout = 10 * time.Minute

	shutdownTimeout = 4 * time.Minute
)

func (s *service) addWarn(msg string) {
	s.warnMu.Lock()
	defer s.warnMu.Unlock()
	s.pendingWarns = append(s.pendingWarns, msg)
}

func (s *service) takeWarns() []string {
	s.warnMu.Lock()
	defer s.warnMu.Unlock()
	if len(s.pendingWarns) == 0 {
		return nil
	}
	out := s.pendingWarns
	s.pendingWarns = nil
	return out
}

type paths struct {
	deployDir   string
	envFile     string
	composeFile string
	caddyTpl    string
	caddyOut    string
	frpsTpl     string
	frpsOut     string
	caddyData   string
}

func newPaths(deployDir, envFile, composeFile, caddyTpl, caddyOut, frpsTpl, frpsOut, caddyData string) paths {
	abs := func(p string) string {
		if p == "" {
			return ""
		}
		v, err := filepath.Abs(p)
		if err != nil {
			return p
		}
		return v
	}
	p := paths{
		deployDir:   abs(deployDir),
		envFile:     abs(envFile),
		composeFile: abs(composeFile),
		caddyTpl:    abs(caddyTpl),
		caddyOut:    abs(caddyOut),
		frpsTpl:     abs(frpsTpl),
		frpsOut:     abs(frpsOut),
		caddyData:   abs(caddyData),
	}
	if p.envFile == "" {
		p.envFile = filepath.Join(filepath.Dir(p.deployDir), ".env")
	}
	if p.composeFile == "" {
		p.composeFile = filepath.Join(p.deployDir, "docker-compose.yml")
	}
	if p.caddyTpl == "" {
		p.caddyTpl = filepath.Join(p.deployDir, "caddy", "Caddyfile.template")
	}
	if p.caddyOut == "" {
		p.caddyOut = filepath.Join(p.deployDir, "caddy", "Caddyfile")
	}
	if p.frpsTpl == "" {
		p.frpsTpl = filepath.Join(p.deployDir, "frps", "frps.toml.template")
	}
	if p.frpsOut == "" {
		p.frpsOut = filepath.Join(p.deployDir, "frps", "frps.toml")
	}
	if p.caddyData == "" {
		p.caddyData = filepath.Join(p.deployDir, "data", "caddy")
	}
	return p
}

func validateConfig(addr, token string, p paths) error {
	if strings.TrimSpace(token) == "" {
		return errors.New("必须设置 LT_CFG_TOKEN：没有令牌的话，本机任何进程都能让它改 Caddy 配置并重启容器")
	}
	if len(token) < 16 {
		return errors.New("LT_CFG_TOKEN 太短，请使用至少 16 字符的随机值")
	}

	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		return fmt.Errorf("监听地址非法: %w", err)
	}
	if ip := net.ParseIP(host); ip == nil || !ip.IsLoopback() {
		return fmt.Errorf("拒绝监听 %s：只允许回环地址", addr)
	}

	if err := validateManagedPaths(p); err != nil {
		return err
	}

	for _, f := range []string{p.caddyTpl, p.frpsTpl, p.composeFile} {
		state, err := statRegularFileState(f)
		switch state {
		case fileMissing:
			return fmt.Errorf("缺少必需文件 %s：请确认 LT_CFG_DEPLOY_DIR 指向部署目录", f)
		case fileUnknown:
			return fmt.Errorf("无法读取必需文件 %s（%v）：请检查部署目录的权限与挂载", f, err)
		case fileNotRegular:
			return fmt.Errorf("必需文件 %s 不是普通文件（可能是目录）：请检查部署目录", f)
		}
	}
	switch state, err := statRegularFileState(p.envFile); state {
	case fileMissing:
		return fmt.Errorf("缺少 .env（%s）：请确认 LT_CFG_ENV_FILE", p.envFile)
	case fileUnknown:
		return fmt.Errorf("无法读取 .env（%s，%v）：请检查权限与挂载", p.envFile, err)
	case fileNotRegular:
		return fmt.Errorf(".env（%s）不是普通文件（可能是目录）：请检查权限与挂载", p.envFile)
	}
	for _, f := range []string{p.caddyOut, p.frpsOut, p.envFile} {
		if err := writable(filepath.Dir(f)); err != nil {
			return fmt.Errorf("目录不可写 %s: %w", filepath.Dir(f), err)
		}
	}
	return nil
}

func writable(dir string) error {
	f, err := os.CreateTemp(dir, ".lt-config-writecheck-*")
	if err != nil {
		return err
	}
	name := f.Name()
	_ = f.Close()
	return os.Remove(name)
}

type service struct {
	token string
	paths paths

	applyMu sync.Mutex

	warnMu       sync.Mutex
	pendingWarns []string

	caddyImage   string
	frpsImage    string
	validateFrps bool
	allowApply   bool

	validateFn func(caddyText, caddyImage, frpsText string, vars map[string]string) (string, error)

	blockedDirs []string
	blockedMu   sync.RWMutex

	dockerProbe    dockerProbeCache
	dockerProbeFn  func() dockerProbeResult
	composeProbeFn func() composeProbeResult
}

func (s *service) blockedDirsSnapshot() []string {
	s.blockedMu.RLock()
	defer s.blockedMu.RUnlock()
	return append([]string(nil), s.blockedDirs...)
}

func (s *service) auth(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
		if subtle.ConstantTimeCompare([]byte(got), []byte(s.token)) != 1 {
			writeJSON(w, http.StatusUnauthorized, map[string]any{"error": "令牌无效"})
			return
		}
		next.ServeHTTP(w, r)
	})
}

func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(v)
}

func failJSON(w http.ResponseWriter, code int, err error) {
	writeJSON(w, code, map[string]any{"error": err.Error()})
}

func envOr(key, def string) string {
	if v := strings.TrimSpace(os.Getenv(key)); v != "" {
		return v
	}
	return def
}

func envBool(key string, def bool) bool {
	v := strings.TrimSpace(os.Getenv(key))
	if v == "" {
		return def
	}
	b, err := strconv.ParseBool(v)
	if err != nil {
		return def
	}
	return b
}

func atoiOr(s string, def int) int {
	if n, err := strconv.Atoi(strings.TrimSpace(s)); err == nil {
		return n
	}
	return def
}
