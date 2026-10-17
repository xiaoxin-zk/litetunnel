package userapi

import (
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/gin-gonic/gin"

	"github.com/xiaoxin-zk/litetunnel/server/internal/handler/shared"
	"github.com/xiaoxin-zk/litetunnel/server/internal/httpx"
	"github.com/xiaoxin-zk/litetunnel/server/internal/middleware"
	"github.com/xiaoxin-zk/litetunnel/server/internal/model"
	"github.com/xiaoxin-zk/litetunnel/server/internal/service"
)

type clientAuthReq struct {
	Username string `json:"username" binding:"required"`
	Password string `json:"password" binding:"required"`
	// 账号失败次数较多时要求人机验证（与网页端统一登录同一套策略）。
	CaptchaTicket string `json:"captcha_ticket"`
	CaptchaAnswer string `json:"captcha_answer"`
}

// clientCaptchaMessage 是「要求验证码」时给桌面客户端的提示。
//
// 不能照搬网页端那句「请输入验证码后重试」：客户端的登录框没有验证码输入框
// （它现在已经不调这个接口了，老版本才会），照着这句话做，用户只会反复看到
// 同一个他无法满足的要求。真正可执行的路径有两条，直接写出来。
const clientCaptchaMessage = "该账号近期登录失败次数较多，为防止爆破已要求人机验证。" +
	"请改用 API Key 接入，或先在网页端登录成功后再试"

// ClientAuth 供桌面客户端首次登录使用，直接返回可用的接入信息与完整配置。
//
// 这是与网页登录等价的密码校验入口：同一份账号、同一个密码，因此必须套用
// **同一套**策略，否则它就是绕过网页端限制的旁路。曾经这里只有一份独立的
// IP 限流与锁定 scope，没有账号级验证码要求——分布式来源改打这个接口就能
// 继续猜密码，而网页端早已要求验证码。
//
// 现在与统一登录共用同一份失败计数（Services.LoginGuard）与同一个 scope，
// 并同样检查账号级验证码要求。
func (h *Handler) ClientAuth(c *gin.Context) {
	var req clientAuthReq
	if err := c.ShouldBindJSON(&req); err != nil {
		httpx.BadRequest(c, "请填写用户名与密码")
		return
	}

	// 与统一登录使用同一个规范化后的账号作为计数键：验证码要求是按登录日志
	// 里的失败次数统计的，写入与查询的写法必须一致，否则交替大小写就能把
	// 失败次数摊薄（见 authapi.Login 里的说明）。
	account := strings.ToLower(strings.TrimSpace(req.Username))
	attempt := service.LoginAttempt{
		Kind:     model.LoginKindUser,
		Username: account,
		Source:   model.LoginSourceClient,
	}

	ip := httpx.ClientIP(c)
	if !shared.CheckLoginLock(c, h.svc.LoginGuard, shared.LoginLockScopeUnified, account, ip) {
		attempt.Result = model.LoginResultLocked
		attempt.Detail = "账号在当前网络下处于登录锁定期"
		h.recordLogin(c, attempt)
		return
	}

	switch shared.CheckLoginCaptcha(c, h.svc, account, req.CaptchaTicket, req.CaptchaAnswer, clientCaptchaMessage) {
	case shared.CaptchaGatePass:
	case shared.CaptchaGateWrong:
		shared.LoginFailed(h.svc.LoginGuard, shared.LoginLockScopeUnified, account, ip)
		attempt.Result = model.LoginResultBadCred
		attempt.Detail = "验证码不正确"
		h.recordLogin(c, attempt)
		return
	default:
		// 客户端拿到的是「需要验证码」而不是密码错误，因此不计入失败次数：
		// 它还没真正尝试过密码。
		attempt.Result = model.LoginResultLocked
		attempt.Detail = "账号累计失败次数较多，要求人机验证"
		h.recordLogin(c, attempt)
		return
	}

	u, err := h.svc.Authenticate(req.Username, req.Password, ip)
	if err != nil {
		shared.LoginFailed(h.svc.LoginGuard, shared.LoginLockScopeUnified, account, ip)
		attempt.Result = shared.LoginResultOf(err)
		attempt.Detail = err.Error()
		h.recordLogin(c, attempt)
		shared.Fail(c, err)
		return
	}
	shared.LoginSucceeded(h.svc.LoginGuard, shared.LoginLockScopeUnified, account, ip)
	attempt.AccountID = u.ID
	attempt.Username = u.Username
	attempt.Result = model.LoginResultSuccess
	h.recordLogin(c, attempt)
	tunnels, err := h.svc.ListTunnels(u.ID)
	if err != nil {
		shared.Fail(c, err)
		return
	}
	info, err := h.svc.BuildClientInfo(u)
	if err != nil {
		shared.Fail(c, err)
		return
	}
	cfgText, err := h.svc.BuildFrpcConfig(u, tunnels)
	if err != nil {
		shared.Fail(c, err)
		return
	}
	httpx.OK(c, gin.H{"client": info, "config": cfgText})
}

// clientInfoResp 是客户端接入信息与隧道清单的组合。
//
// 字段直接内嵌 ClientInfo，保证既有前端读取 server_addr 等字段不受影响。
type clientInfoResp struct {
	*service.ClientInfo
	// 客户端只持有 API Key，因此账号信息必须由服务端下发，
	// 不能像以前那样依赖用户在登录框里填的用户名。
	Username     string  `json:"username"`
	Nickname     string  `json:"nickname"`
	Tunnels      []gin.H `json:"tunnels"`
	TrafficUsed  int64   `json:"traffic_used"`
	TrafficQuota int64   `json:"traffic_quota"`
	Exceeded     bool    `json:"exceeded"`

	// TunnelTotal 是该账号的隧道总数（不受分页影响）。
	// 客户端据此判断是否还有下一页：只看「本页是否取满」在最后一页
	// 恰好整页时会多打一次空请求；老客户端不认识这个字段，忽略即可。
	TunnelTotal int64 `json:"tunnel_total"`

	// ListVersion 是清单版本（总数 + 该用户清单的修订号）。
	//
	// 只比条数会漏过「数量相抵」的并发变更：分页期间删掉一条已取到的、
	// 同时新增一条 id 更大的，总数不变，但新隧道落在游标之前永远取不到。
	// 修订号由数据库在「对账相关字段」变化时与数据变更同事务递增，
	// 状态切换、改端口/域名这类不增删记录的变更同样会让版本变化。
	// 客户端逐页比对版本，不一致就整轮重取。老客户端忽略此字段。
	ListVersion string `json:"list_version,omitempty"`

	// Group 是分组限制。客户端要能自己建隧道，就必须知道
	// 「允许哪些协议」「最多几条隧道」——否则表单会放行注定被拒的提交，
	// 用户填完才收到「协议不允许」的报错。
	Group *gin.H `json:"group,omitempty"`
	// Balance 仅在站点启用支付时下发，避免客户端显示一个无法使用的余额。
	BalanceCents   int64 `json:"balance_cents"`
	PaymentEnabled bool  `json:"payment_enabled"`
}

// ClientInfo 返回接入信息与当前隧道清单（需已认证）。
func (h *Handler) ClientInfo(c *gin.Context) {
	u, err := h.svc.LoadUser(middleware.CurrentUserID(c))
	if err != nil {
		shared.Fail(c, err)
		return
	}
	info, err := h.svc.BuildClientInfo(u)
	if err != nil {
		shared.Fail(c, err)
		return
	}
	// 分页：?before_id=<上一页最后一条的 id>&limit=200。
	// 不带 limit 时返回全部——老客户端不知道分页参数，必须保持原行为。
	// 用游标而不是 offset：分页期间的增删不会让结果错位（见
	// ListTunnelsPage 的说明）。
	beforeID, _ := strconv.Atoi(c.Query("before_id"))
	if beforeID < 0 {
		beforeID = 0
	}
	limit, _ := strconv.Atoi(c.Query("limit"))
	if limit < 0 {
		limit = 0
	}
	// 单页上限：防止客户端传一个巨大的 limit 把分页变成全量。
	const maxClientPageSize = 500
	if limit > maxClientPageSize {
		limit = maxClientPageSize
	}
	tunnels, total, version, err := h.svc.ListTunnelsPage(u.ID, uint(beforeID), limit)
	if err != nil {
		shared.Fail(c, err)
		return
	}
	// 限速以分组当前值为准（不在循环里逐条查库）。
	bl := h.svc.EffectiveBandwidth(u)
	// 配置头部只渲染一次：每条隧道的 config_rev 是「头部 + 该隧道段」的摘要，
	// 与 /api/user/client/config?tunnel_id= 实际返回的字节一一对应。
	header := h.svc.FrpcConfigHeader(info)
	out := make([]gin.H, 0, len(tunnels))
	for i := range tunnels {
		vo := h.tunnelVO(&tunnels[i], bl)
		// config_rev 让客户端跳过没变化的配置请求：它的值由渲染结果算出，
		// 隧道字段、分组限速、站点设置、客户端密钥只要有一处变化，摘要就会变，
		// 客户端因此不会漏掉变更，也不会为没变的隧道反复发请求。
		// 限速传入上面算好的值：逐条重算会让「分组过期/未绑定」的账号
		// 每条隧道多查一次默认分组（N+1），而这里是每 20 秒一次的同步路径。
		vo["config_rev"] = service.FrpcConfigRev(header + h.svc.FrpcConfigProxy(u, tunnels[i], bl))
		out = append(out, vo)
	}
	// 分组信息：客户端据此限制建隧道表单的可选项
	var groupVO *gin.H
	if g := h.svc.EffectiveGroup(u); g != nil {
		groupVO = &gin.H{
			"id":                  g.ID,
			"name":                g.Name,
			"max_tunnels":         g.MaxTunnels,
			"max_ports":           g.MaxPorts,
			"bandwidth_limit_str": service.FormatBandwidthHuman(g.BandwidthLimit),
			"allow_protocols":     g.AllowProtocols,
			"allow_custom_domain": g.AllowCustomDomain,
			// 同上：客户端据此决定要不要把 https 选项放进建隧道表单。
			"https_tunnel_enabled": h.svc.HTTPSProxyEntryEnabled(),
			"https_entry":          h.svc.HTTPSProxyEntry(),
		}
	}

	httpx.OK(c, clientInfoResp{
		ClientInfo:     info,
		Username:       u.Username,
		Nickname:       u.Nickname,
		Tunnels:        out,
		TunnelTotal:    total,
		ListVersion:    version,
		TrafficUsed:    u.TrafficUsed,
		TrafficQuota:   h.svc.EffectiveQuota(u),
		Exceeded:       h.svc.QuotaExceeded(u),
		Group:          groupVO,
		BalanceCents:   u.Balance,
		PaymentEnabled: h.svc.Settings.Bool(service.KeyPaymentEnabled),
	})
}

// ClientConfig 下载当前账号的 frpc.toml。
//
// 默认返回包含全部启用隧道的完整配置（供用户在网页端下载/排查）。
// 带 tunnel_id 时只返回该条隧道的配置——客户端为每条隧道单独托管一个
// frpc 进程，每条进程只能拿到属于自己的那一份，否则一条隧道的启停
// 会连带影响其他隧道（单进程承载全部隧道时就是这个表现）。
func (h *Handler) ClientConfig(c *gin.Context) {
	u, err := h.svc.LoadUser(middleware.CurrentUserID(c))
	if err != nil {
		shared.Fail(c, err)
		return
	}
	// 带 tunnel_id 时按 ID 直查，不带时才取全量。
	//
	// 以前是无条件 ListTunnels 再线性扫一遍找那条隧道。客户端给每条隧道单独
	// 起一个 frpc 进程，同步一轮就是「隧道数」次这样的请求：每次都把用户
	// 全部隧道读出来、建一遍对象，只为拿其中一条。隧道一多，这部分开销
	// 完全是无谓的——按主键查一条是 O(1)，全量查是 O(n) 加一次大分配。
	var tunnels []model.Tunnel
	if raw := strings.TrimSpace(c.Query("tunnel_id")); raw != "" {
		id, err := strconv.ParseUint(raw, 10, 64)
		if err != nil || id == 0 {
			shared.Fail(c, service.ErrInvalidParam)
			return
		}
		// 归属校验交给 GetTunnel 的 where 条件：他人的隧道 ID 一律按
		// 「不存在」处理，不给出「存在但不属于你」这种能用来探测 ID 的差别。
		// 超出 uint 表示范围的 ID 同样按不存在处理，避免截断后指向另一条隧道。
		if uint64(uint(id)) != id {
			shared.Fail(c, service.ErrNotFound)
			return
		}
		one, err := h.svc.GetTunnel(u.ID, uint(id))
		if err != nil {
			shared.Fail(c, err)
			return
		}
		tunnels = []model.Tunnel{*one}
	} else {
		tunnels, err = h.svc.ListTunnels(u.ID)
		if err != nil {
			shared.Fail(c, err)
			return
		}
	}
	text, err := h.svc.BuildFrpcConfig(u, tunnels)
	if err != nil {
		shared.Fail(c, err)
		return
	}
	// 摘要随**正文**一起返回,而不是只放在清单里。
	//
	// 清单里的 config_rev 是另一次请求(另一次渲染)算出来的:两次请求之间
	// 管理端若改了隧道或分组,客户端就可能把「新正文 + 旧摘要」配成一对缓存
	// 下来。虽然下一轮通常能纠正,但只要服务端在下一轮之前又回到旧摘要,
	// 客户端就会误判缓存有效,一直跑着过时的配置。
	// 这里用**本次正文**的哈希,客户端核对的就是它自己那份字节。
	c.Header("X-Config-Rev", service.FrpcConfigRev(text))
	if c.Query("download") == "1" {
		c.Header("Content-Disposition", `attachment; filename="frpc.toml"`)
	}
	c.Data(http.StatusOK, "text/plain; charset=utf-8", []byte(text))
}

// ClientDownload 客户端安装包信息。
type ClientDownload struct {
	Name    string `json:"name"`
	Size    int64  `json:"size"`
	Updated string `json:"updated_at"`
}

// ClientDownloads 列出可下载的客户端安装包。
//
// 只读取固定目录下的一级文件，且拒绝任何路径穿越，
// 目录不存在时返回空列表而不是报错。
func (h *Handler) ClientDownloads(c *gin.Context) {
	// 配置了外部下载地址（通常是 GitHub Releases）时只返回该地址，
	// 不列本地目录：两套来源同时出现会让用户不知道该点哪个，
	// 而且外部地址往往版本更新，本地那份可能是旧的。
	if url := strings.TrimSpace(h.svc.Settings.Get(service.KeySiteClientDownloadURL)); url != "" {
		httpx.OK(c, gin.H{"download_url": url, "files": []ClientDownload{}})
		return
	}

	dir := h.svc.Cfg.ClientDistDir
	entries, err := os.ReadDir(dir)
	if err != nil {
		httpx.OK(c, gin.H{"download_url": "", "files": []ClientDownload{}})
		return
	}
	list := make([]ClientDownload, 0, len(entries))
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		name := e.Name()
		if name != filepath.Base(name) {
			continue
		}
		info, err := e.Info()
		if err != nil {
			continue
		}
		list = append(list, ClientDownload{
			Name:    name,
			Size:    info.Size(),
			Updated: info.ModTime().Format(time.RFC3339),
		})
	}
	sort.Slice(list, func(i, j int) bool { return list[i].Name < list[j].Name })
	httpx.OK(c, gin.H{"download_url": "", "files": list})
}

// ClientDownloadFile 下载指定的客户端安装包。
func (h *Handler) ClientDownloadFile(c *gin.Context) {
	name := c.Param("name")
	// 双重防线：文件名必须等于其 base，且不允许出现路径分隔符。
	if name == "" || name != filepath.Base(name) || name == "." || name == ".." {
		httpx.BadRequest(c, "文件名非法")
		return
	}
	full := filepath.Join(h.svc.Cfg.ClientDistDir, name)
	c.FileAttachment(full, name)
}
