// Command lt-config 是运行在**宿主机**上的域名与证书配置服务。
//
// # 它做什么
//
// 面板上的「域名与证书」页保存配置后，由本服务：
//
//	1. 把配置合并进部署目录的 .env（只有白名单里的键能被覆盖）；
//	2. 用 deploy 目录下的模板渲染 Caddyfile 与 frps.toml；
//	3. 用**将要上线的那个镜像**校验渲染结果，不通过就不写盘；
//	4. 写入文件并重建 caddy / frps 容器。
//
// # 为什么校验和应用必须放在宿主机
//
// 面板容器是 read_only 的，只挂载了 /data：它既写不了部署目录，
// 也没有 docker socket。把「改 Caddy 配置 + 重建容器」交给它，等于
// 把一个能操纵宿主机的入口放到公网路径上。这与防火墙写操作交给
// lt-fw 的取舍完全一致（见 cmd/lt-fw 的包注释）。
//
// # 权限边界
//
// 即使面板被完全控制，攻击者能做的也只有：
//
//   - 修改白名单内的域名 / DNS 服务商 / DNS 凭据；
//   - 触发重新渲染与重建 caddy、frps 两个容器；
//
// frps token、端口池范围、面板监听地址、数据库路径都不在白名单内，
// 校验器也会拒绝产出一份 Caddy 加载不了的配置。
//
// # 为什么 Caddy 的管理 API 仍然保持关闭
//
// Caddy 自身的 admin API 能直接改运行时配置，把它开放（哪怕只对回环）
// 就等于多了一条「不改文件也能改路由」的路径，而面板与 Caddy 并不在同一
// 个网络命名空间里，放开就意味着要把它暴露到某个可被面板触达的地址上。
// 所以这里走「校验 → 写文件 → 重建容器」：慢几秒，但每一条生效的路由
// 都能在磁盘上找到对应的那一行。
//
// # 部署
//
// 见 deploy/systemd/lt-config.service 与 README 的「域名与证书」一节。
package main

import (
	"crypto/subtle"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
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

	p := newPaths(*deployDir, *envFile, *composeFile, *caddyTpl, *caddyOut, *frpsTpl, *frpsOut, *caddyData)
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
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/health", srv.handleHealth)
	mux.HandleFunc("/render", srv.handleRender)
	mux.HandleFunc("/apply", srv.handleApply)
	mux.HandleFunc("/dns/check", srv.handleDNSCheck)
	mux.HandleFunc("/certs", srv.handleCerts)

	httpSrv := &http.Server{
		Addr:    *addr,
		Handler: srv.auth(mux),
		// 渲染要等 docker 校验，读超时给足；写超时同理。
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      4 * time.Minute,
	}

	log.Printf("[lt-config] 部署目录 %s", p.deployDir)
	log.Printf("[lt-config] 监听 %s（重建容器：%v，frps 校验：%v）", *addr, *allowApply, *validateFrps)
	if err := httpSrv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
		log.Fatalf("[lt-config] 服务退出: %v", err)
	}
}

// paths 是全部会被本服务读写的路径，启动时统一解析与校验。
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

// validateConfig 在启动阶段把配置问题全部挡掉。
//
// 这类问题拖到运行期的表现是「面板说保存成功，但配置没变、容器也没重启」，
// 排查成本极高。宁可启动失败。
func validateConfig(addr, token string, p paths) error {
	if strings.TrimSpace(token) == "" {
		return errors.New("必须设置 LT_CFG_TOKEN：没有令牌的话，本机任何进程都能让它改 Caddy 配置并重启容器")
	}
	if len(token) < 16 {
		return errors.New("LT_CFG_TOKEN 太短，请使用至少 16 字符的随机值")
	}

	// 只允许回环：绑到 0.0.0.0 等于把「重写 TLS 配置」的接口送给整个网段。
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		return fmt.Errorf("监听地址非法: %w", err)
	}
	if ip := net.ParseIP(host); ip == nil || !ip.IsLoopback() {
		return fmt.Errorf("拒绝监听 %s：只允许回环地址", addr)
	}

	for _, f := range []string{p.caddyTpl, p.frpsTpl, p.composeFile} {
		if _, err := os.Stat(f); err != nil {
			return fmt.Errorf("缺少必需文件 %s：请确认 LT_CFG_DEPLOY_DIR 指向部署目录", f)
		}
	}
	if _, err := os.Stat(p.envFile); err != nil {
		return fmt.Errorf("缺少 .env（%s）：请确认 LT_CFG_ENV_FILE", p.envFile)
	}
	// 产物目录必须可写，否则会在「校验都过了、写盘才失败」这一步才暴露。
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

	caddyImage   string
	frpsImage    string
	validateFrps bool
	allowApply   bool
}

// auth 校验 Bearer token，用常量时间比较避免逐字节试探。
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

// atoiOr 把 .env 里的端口字符串转成整数，非法值返回默认值。
//
// 不报错是有意的：健康检查只是把端口显示出来，
// 一个写错的端口不该让整页状态变成「不可用」。
func atoiOr(s string, def int) int {
	if n, err := strconv.Atoi(strings.TrimSpace(s)); err == nil {
		return n
	}
	return def
}
