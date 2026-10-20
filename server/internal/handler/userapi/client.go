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
	Username      string `json:"username" binding:"required"`
	Password      string `json:"password" binding:"required"`
	CaptchaTicket string `json:"captcha_ticket"`
	CaptchaAnswer string `json:"captcha_answer"`
}

const clientCaptchaMessage = "该账号近期登录失败次数较多，为防止爆破已要求人机验证。" +
	"请改用 API Key 接入，或先在网页端登录成功后再试"

func (h *Handler) ClientAuth(c *gin.Context) {
	var req clientAuthReq
	if err := c.ShouldBindJSON(&req); err != nil {
		httpx.BadRequest(c, "请填写用户名与密码")
		return
	}

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

type clientInfoResp struct {
	*service.ClientInfo
	Username     string  `json:"username"`
	Nickname     string  `json:"nickname"`
	Tunnels      []gin.H `json:"tunnels"`
	TrafficUsed  int64   `json:"traffic_used"`
	TrafficQuota int64   `json:"traffic_quota"`
	Exceeded     bool    `json:"exceeded"`

	TunnelTotal int64 `json:"tunnel_total"`

	ListVersion string `json:"list_version,omitempty"`

	Group          *gin.H `json:"group,omitempty"`
	BalanceCents   int64  `json:"balance_cents"`
	PaymentEnabled bool   `json:"payment_enabled"`
}

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
	beforeID, _ := strconv.Atoi(c.Query("before_id"))
	if beforeID < 0 {
		beforeID = 0
	}
	limit, _ := strconv.Atoi(c.Query("limit"))
	if limit < 0 {
		limit = 0
	}
	const maxClientPageSize = 500
	if limit > maxClientPageSize {
		limit = maxClientPageSize
	}
	tunnels, total, version, err := h.svc.ListTunnelsPage(u.ID, uint(beforeID), limit)
	if err != nil {
		shared.Fail(c, err)
		return
	}
	bl := h.svc.EffectiveBandwidth(u)
	header := h.svc.FrpcConfigHeader(info)
	out := make([]gin.H, 0, len(tunnels))
	for i := range tunnels {
		vo := h.tunnelVO(&tunnels[i], bl)
		vo["config_rev"] = service.FrpcConfigRev(header + h.svc.FrpcConfigProxy(u, tunnels[i], bl))
		out = append(out, vo)
	}
	var groupVO *gin.H
	if g := h.svc.EffectiveGroup(u); g != nil {
		groupVO = &gin.H{
			"id":                   g.ID,
			"name":                 g.Name,
			"max_tunnels":          g.MaxTunnels,
			"max_ports":            g.MaxPorts,
			"bandwidth_limit_str":  service.FormatBandwidthHuman(g.BandwidthLimit),
			"allow_protocols":      g.AllowProtocols,
			"allow_custom_domain":  g.AllowCustomDomain,
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

func (h *Handler) ClientConfig(c *gin.Context) {
	u, err := h.svc.LoadUser(middleware.CurrentUserID(c))
	if err != nil {
		shared.Fail(c, err)
		return
	}
	var tunnels []model.Tunnel
	if raw := strings.TrimSpace(c.Query("tunnel_id")); raw != "" {
		id, err := strconv.ParseUint(raw, 10, 64)
		if err != nil || id == 0 {
			shared.Fail(c, service.ErrInvalidParam)
			return
		}
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
	c.Header("X-Config-Rev", service.FrpcConfigRev(text))
	if c.Query("download") == "1" {
		c.Header("Content-Disposition", `attachment; filename="frpc.toml"`)
	}
	c.Data(http.StatusOK, "text/plain; charset=utf-8", []byte(text))
}

type ClientDownload struct {
	Name    string `json:"name"`
	Size    int64  `json:"size"`
	Updated string `json:"updated_at"`
}

func (h *Handler) ClientDownloads(c *gin.Context) {
	// 外部下载地址与本站文件是互补关系而不是二选一：外部地址挂了、或者填的是
	// 发布页而不是直链时，用户至少还能从这里拿到文件。两个都返回，前端并排展示。
	url := strings.TrimSpace(h.svc.Settings.Get(service.KeySiteClientDownloadURL))

	dir := h.svc.Cfg.ClientDistDir
	entries, err := os.ReadDir(dir)
	if err != nil {
		httpx.OK(c, gin.H{"download_url": url, "files": []ClientDownload{}})
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
		// 上传中的临时文件（.upload-*）与其它隐藏文件不对外暴露：
		// 列出来用户点了只会下到半截文件，比「没有文件」更难排查。
		if strings.HasPrefix(name, ".") {
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
	httpx.OK(c, gin.H{"download_url": url, "files": list})
}

func (h *Handler) ClientDownloadFile(c *gin.Context) {
	name := c.Param("name")
	if name == "" || name != filepath.Base(name) || name == "." || name == ".." {
		httpx.BadRequest(c, "文件名非法")
		return
	}
	full := filepath.Join(h.svc.Cfg.ClientDistDir, name)
	// 先确认是普通文件：直接交给 FileAttachment 的话，文件被删/被换成目录时
	// 返回的是 404 或 500 的 HTML，前端只能显示「下载失败」，无从判断原因。
	st, err := os.Stat(full)
	if err != nil || !st.Mode().IsRegular() {
		httpx.NotFound(c, "安装包不存在或已被删除，请联系管理员重新上传")
		return
	}
	c.FileAttachment(full, name)
}
