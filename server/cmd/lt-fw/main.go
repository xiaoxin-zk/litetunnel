// Command lt-fw 是运行在**宿主机**上的防火墙操作 helper。
//
// # 为什么需要它
//
// 面板容器不应该持有 NET_ADMIN。一旦控制面出现远程代码执行漏洞，
// 攻击者拿到的就不只是面板，而是整台主机的防火墙控制权——
// 那比面板本身被攻破严重得多。
//
// 把写操作拆出来之后，权限被切成两层：
//
//	面板（无任何特权）  ——  只读扫描监听端口（/proc/net/*），
//	                       写操作一律转发给 helper
//	lt-fw（宿主机 root）——  只接受回环地址 + Bearer token 的请求，
//	                       且仍然受保护端口与端口池范围的双重约束
//
// 即使面板被完全控制，攻击者能做的也只是「放行/关闭端口池内的端口」，
// 保护端口（SSH、控制面自身端口等）依然动不了。
//
// # 为什么用 systemd 而不是容器
//
// 它需要操作宿主机的 nftables/iptables。跑在容器里要么重新引入特权，
// 要么把宿主机的 netns 与 xtables 锁挂进去——绕了一圈又回到原点。
// 用 systemd 直接在宿主机上跑，权限边界最清晰。
//
// # 部署
//
// 见 deploy/systemd/lt-fw.service 与 README 的「防火墙 helper」一节。
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
	"strconv"
	"strings"
	"time"

	"github.com/xiaoxin-zk/litetunnel/server/internal/firewall"
)

func main() {
	var (
		addr = flag.String("addr", envOr("LT_FW_ADDR", "127.0.0.1:7849"),
			"监听地址，必须是回环地址")
		token = flag.String("token", os.Getenv("LT_FW_TOKEN"),
			"访问令牌（必填，至少 16 字符）")
		protected = flag.String("protected-ports", envOr("LT_FW_PROTECTED_PORTS", "22"),
			"保护端口，逗号分隔；这些端口永远不允许被关闭")
		poolStart = flag.Int("pool-start", envInt("LT_FW_POOL_START", 0),
			"隧道端口池起始（0 表示不限制）")
		poolEnd = flag.Int("pool-end", envInt("LT_FW_POOL_END", 0),
			"隧道端口池结束")
		backendName = flag.String("backend", envOr("LT_FW_BACKEND", "auto"),
			"防火墙后端：auto / iptables / nftables / ufw / firewalld")
	)
	flag.Parse()

	if err := validateConfig(*addr, *token, *poolStart, *poolEnd); err != nil {
		log.Fatalf("[lt-fw] %v", err)
	}

	guard := firewall.NewGuard(*protected, *poolStart, *poolEnd)
	backend := firewall.Detect(*backendName)

	log.Printf("[lt-fw] 启动：后端 %s，保护端口 %v，端口池 %d-%d",
		backend.Name(), guard.Protected(), *poolStart, *poolEnd)
	if n, ok := backend.(*firewall.None); ok {
		log.Printf("[lt-fw] 注意：%s", n.Reason())
	}

	srv := &server{
		token:   *token,
		guard:   guard,
		backend: backend,
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/health", srv.handleHealth)
	mux.HandleFunc("/rules", srv.handleRules)
	mux.HandleFunc("/ports/open", srv.handleOpen)
	mux.HandleFunc("/ports/close", srv.handleClose)

	httpSrv := &http.Server{
		Addr:    *addr,
		Handler: srv.auth(mux),
		// 只服务本机面板，不需要长连接与大量并发。
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       15 * time.Second,
		WriteTimeout:      30 * time.Second,
	}

	log.Printf("[lt-fw] 监听 %s", *addr)
	if err := httpSrv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
		log.Fatalf("[lt-fw] 服务退出: %v", err)
	}
}

// validateConfig 在启动阶段就把配置问题挡掉。
//
// 这类问题拖到运行期才发现的话，表现是「面板说放行了端口但实际没生效」，
// 排查成本极高。宁可启动失败。
func validateConfig(addr, token string, poolStart, poolEnd int) error {
	if strings.TrimSpace(token) == "" {
		return errors.New("必须设置 LT_FW_TOKEN：没有令牌的话，本机任何进程都能调用它改防火墙")
	}
	if len(token) < 16 {
		return errors.New("LT_FW_TOKEN 太短，请使用至少 16 字符的随机值")
	}

	// 只允许监听回环。绑到 0.0.0.0 会让同网段的人直接调用防火墙接口。
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		return fmt.Errorf("监听地址非法: %w", err)
	}
	ip := net.ParseIP(host)
	if ip == nil || !ip.IsLoopback() {
		return fmt.Errorf("拒绝监听 %s：只允许回环地址，否则同网段可直连防火墙接口", addr)
	}

	if poolStart != 0 || poolEnd != 0 {
		if poolStart < 1024 || poolEnd <= poolStart || poolEnd > 65535 {
			return fmt.Errorf("端口池范围非法：需要 1024 < start < end <= 65535，当前 %d-%d", poolStart, poolEnd)
		}
	}
	return nil
}

type server struct {
	token   string
	guard   *firewall.Guard
	backend firewall.Backend
}

// auth 校验 Bearer token。
//
// 用常量时间比较：令牌比较若走短路求值，攻击者可以靠响应时间逐字节试探。
func (s *server) auth(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
		if subtle.ConstantTimeCompare([]byte(got), []byte(s.token)) != 1 {
			writeJSON(w, http.StatusUnauthorized, map[string]any{"error": "令牌无效"})
			return
		}
		next.ServeHTTP(w, r)
	})
}

func (s *server) handleHealth(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeJSON(w, http.StatusMethodNotAllowed, map[string]any{"error": "仅支持 GET"})
		return
	}
	enabled, statusErr := s.backend.Status()
	available := s.backend.Available()
	if _, isNone := s.backend.(*firewall.None); isNone {
		// None 是占位实现，它的 Available() 恒为 true；但对面板来说
		// 「没有可用的防火墙后端」就是不可用——否则面板会拿它当正常后端，
		// 每次操作都以 ErrNoBackend 失败，而不是走「后端不可用」的提示。
		available = false
	}
	resp := map[string]any{
		"backend":   s.backend.Name(),
		"available": available,
		"enabled":   enabled,
		"protected": s.guard.Protected(),
	}
	if statusErr != nil {
		// 查询失败不是「未启用」：带上可区分的原因，面板据此把状态标成
		// 「未知」。丢掉这个错误的话，helper 在线但底层查询失败时，
		// 面板拿到的仍是 active=false、err=nil，看起来一切正常。
		resp["enabled"] = false
		resp["error"] = "读取防火墙状态失败：" + statusErr.Error()
	}
	if n, ok := s.backend.(*firewall.None); ok {
		resp["reason"] = n.Reason()
	}
	writeJSON(w, http.StatusOK, resp)
}

// handleRules 返回**递归展开后**的放行端口。
//
// 这是只读操作：只调用 iptables-save / -S 这类查询命令。
func (s *server) handleRules(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeJSON(w, http.StatusMethodNotAllowed, map[string]any{"error": "仅支持 GET"})
		return
	}
	rules, err := firewall.ListResolvedRules()
	if err != nil {
		writeJSON(w, http.StatusBadGateway, map[string]any{"error": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"rules": rules})
}

type portReq struct {
	Port  int    `json:"port"`
	Proto string `json:"proto"`
}

// handleOpen 放行端口。仍然要过 Guard：即便面板被攻破，
// 攻击者也不能借此放行端口池之外或特权端口。
func (s *server) handleOpen(w http.ResponseWriter, r *http.Request) {
	req, err := decodePortReq(r)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": err.Error()})
		return
	}
	if err := s.guard.CheckAdd(req.Port); err != nil {
		writeJSON(w, http.StatusForbidden, map[string]any{"error": err.Error()})
		return
	}
	if err := s.backend.AddPort(req.Port, req.Proto); err != nil {
		writeJSON(w, http.StatusBadGateway, map[string]any{"error": err.Error()})
		return
	}
	log.Printf("[lt-fw] 放行 %d/%s", req.Port, req.Proto)
	writeJSON(w, http.StatusOK, map[string]any{"message": "端口已放行"})
}

// handleClose 关闭端口。保护端口在这里被硬拦。
func (s *server) handleClose(w http.ResponseWriter, r *http.Request) {
	req, err := decodePortReq(r)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": err.Error()})
		return
	}
	if err := s.guard.CheckRemove(req.Port); err != nil {
		writeJSON(w, http.StatusForbidden, map[string]any{"error": err.Error()})
		return
	}
	if err := s.backend.RemovePort(req.Port, req.Proto); err != nil {
		writeJSON(w, http.StatusBadGateway, map[string]any{"error": err.Error()})
		return
	}
	log.Printf("[lt-fw] 关闭 %d/%s", req.Port, req.Proto)
	writeJSON(w, http.StatusOK, map[string]any{"message": "端口已关闭"})
}

func decodePortReq(r *http.Request) (portReq, error) {
	var req portReq
	if err := json.NewDecoder(http.MaxBytesReader(nil, r.Body, 4<<10)).Decode(&req); err != nil {
		return req, errors.New("请求体格式不正确")
	}
	if req.Port <= 0 || req.Port > 65535 {
		return req, fmt.Errorf("端口 %d 非法", req.Port)
	}
	switch strings.ToLower(strings.TrimSpace(req.Proto)) {
	case "":
		req.Proto = "tcp"
	case "tcp", "udp":
		req.Proto = strings.ToLower(strings.TrimSpace(req.Proto))
	default:
		return req, fmt.Errorf("不支持的协议 %q", req.Proto)
	}
	return req, nil
}

func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(v)
}

func envOr(key, def string) string {
	if v := strings.TrimSpace(os.Getenv(key)); v != "" {
		return v
	}
	return def
}

func envInt(key string, def int) int {
	if v, err := strconv.Atoi(strings.TrimSpace(os.Getenv(key))); err == nil {
		return v
	}
	return def
}
