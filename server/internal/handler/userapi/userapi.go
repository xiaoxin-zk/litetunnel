// Package userapi 实现用户控制台 API。
//
// 该包只注册在「用户侧监听地址」上，与管理后台在物理端口上隔离：
// 即使管理路由被误注册，也无法从公网端口访问。
package userapi

import (
	"errors"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/gin-gonic/gin"

	"github.com/xiaoxin-zk/litetunnel/server/internal/auth"
	"github.com/xiaoxin-zk/litetunnel/server/internal/handler/shared"
	"github.com/xiaoxin-zk/litetunnel/server/internal/httpx"
	"github.com/xiaoxin-zk/litetunnel/server/internal/middleware"
	"github.com/xiaoxin-zk/litetunnel/server/internal/model"
	"github.com/xiaoxin-zk/litetunnel/server/internal/service"
)

// Handler 用户控制台处理器。
type Handler struct {
	svc *service.Services
	// guard 按账号维度锁定连续登录失败，抵御代理池对单一账号的慢速爆破。
	guard *middleware.LoginGuard
}

// New 构造处理器。
func New(svc *service.Services) *Handler {
	return &Handler{
		svc: svc,
		// 连续失败 5 次开始锁定，首次 15 分钟，之后逐次翻倍，上限 24 小时。
		guard: middleware.NewLoginGuard(5, 15*time.Minute, 24*time.Hour),
	}
}

// ---- 认证 ----

type registerReq struct {
	Username string `json:"username" binding:"required"`
	Password string `json:"password" binding:"required"`
	Email    string `json:"email"`
}

// Register 用户注册。
func (h *Handler) Register(c *gin.Context) {
	var req registerReq
	if err := c.ShouldBindJSON(&req); err != nil {
		httpx.BadRequest(c, "请填写用户名与密码")
		return
	}
	u, err := h.svc.Register(service.RegisterInput{
		Username: req.Username,
		Password: req.Password,
		Email:    req.Email,
		IP:       httpx.ClientIP(c),
	})
	if err != nil {
		shared.Fail(c, err)
		return
	}
	httpx.OK(c, gin.H{"id": u.ID, "username": u.Username})
}

type loginReq struct {
	Username string `json:"username" binding:"required"`
	Password string `json:"password" binding:"required"`
}

// Login 用户登录，签发用户域令牌。
func (h *Handler) Login(c *gin.Context) {
	var req loginReq
	if err := c.ShouldBindJSON(&req); err != nil {
		httpx.BadRequest(c, "请填写用户名与密码")
		return
	}

	account := strings.ToLower(strings.TrimSpace(req.Username))
	if !shared.CheckLoginLock(c, h.guard, shared.LoginLockScopeUser, account) {
		return
	}

	u, err := h.svc.Authenticate(req.Username, req.Password, httpx.ClientIP(c))
	if err != nil {
		shared.LoginFailed(h.guard, shared.LoginLockScopeUser, account)
		shared.Fail(c, err)
		return
	}
	shared.LoginSucceeded(h.guard, shared.LoginLockScopeUser, account)

	token, expireAt, err := auth.Issue(
		h.svc.Cfg.UserJWTSecret, auth.DomainUser,
		u.ID, u.Username, "", h.svc.Cfg.UserJWTExpire,
	)
	if err != nil {
		shared.Fail(c, err)
		return
	}
	httpx.OK(c, gin.H{
		"token":      token,
		"expires_at": expireAt,
		"user":       h.profileVO(u),
	})
}

// Logout 用户登出。JWT 无状态，服务端仅作审计记录，客户端需自行清除令牌。
func (h *Handler) Logout(c *gin.Context) {
	httpx.OK(c, gin.H{"message": "已退出登录"})
}

// Profile 当前用户信息。
func (h *Handler) Profile(c *gin.Context) {
	u, err := h.svc.LoadUser(middleware.CurrentUserID(c))
	if err != nil {
		shared.Fail(c, err)
		return
	}
	httpx.OK(c, h.profileVO(u))
}

type changePasswordReq struct {
	OldPassword string `json:"old_password" binding:"required"`
	NewPassword string `json:"new_password" binding:"required"`
}

// ChangePassword 修改密码。
func (h *Handler) ChangePassword(c *gin.Context) {
	var req changePasswordReq
	if err := c.ShouldBindJSON(&req); err != nil {
		httpx.BadRequest(c, "请填写原密码与新密码")
		return
	}
	if err := h.svc.UpdatePassword(middleware.CurrentUserID(c), req.OldPassword, req.NewPassword); err != nil {
		shared.Fail(c, err)
		return
	}
	httpx.OK(c, gin.H{"message": "密码已更新，请重新登录"})
}

// profileVO 用户信息视图对象。不包含口令与任何密钥字段。
func (h *Handler) profileVO(u *model.User) gin.H {
	g := h.svc.EffectiveGroup(u)
	quota := h.svc.EffectiveQuota(u)
	vo := gin.H{
		"id":                u.ID,
		"username":          u.Username,
		"nickname":          u.Nickname,
		"email":             u.Email,
		"status":            u.Status,
		"traffic_used":      u.TrafficUsed,
		"traffic_quota":     quota,
		"traffic_reset_at":  u.TrafficResetAt,
		"traffic_exceeded":  h.svc.QuotaExceeded(u),
		"balance":           u.Balance,
		"group_expire_at":   u.GroupExpireAt,
		"api_key_prefix":    u.APIKeyPrefix,
		"api_key_created_at": u.APIKeyCreatedAt,
		"created_at":        u.CreatedAt,
		"last_login_at":     u.LastLoginAt,
	}
	if g != nil {
		vo["group"] = gin.H{
			"id":                  g.ID,
			"name":                g.Name,
			"max_tunnels":         g.MaxTunnels,
			"max_ports":           g.MaxPorts,
			"traffic_quota":       g.TrafficQuota,
			"bandwidth_limit":     g.BandwidthLimit,
			"bandwidth_limit_str": service.FormatBandwidth(g.BandwidthLimit),
			"allow_protocols":     g.AllowProtocols,
			"allow_custom_domain": g.AllowCustomDomain,
		}
	}
	return vo
}

// ---- 桌面客户端接入 ----

type clientAuthReq struct {
	Username string `json:"username" binding:"required"`
	Password string `json:"password" binding:"required"`
}

// ClientAuth 供桌面客户端首次登录使用，直接返回可用的接入信息与完整配置。
//
// 这是与网页登录等价的密码校验入口，必须套用同样的账号锁定策略，
// 否则攻击者可以绕过网页端的锁定直接从客户端接口爆破。
func (h *Handler) ClientAuth(c *gin.Context) {
	var req clientAuthReq
	if err := c.ShouldBindJSON(&req); err != nil {
		httpx.BadRequest(c, "请填写用户名与密码")
		return
	}

	account := strings.ToLower(strings.TrimSpace(req.Username))
	if !shared.CheckLoginLock(c, h.guard, shared.LoginLockScopeUser, account) {
		return
	}

	u, err := h.svc.Authenticate(req.Username, req.Password, httpx.ClientIP(c))
	if err != nil {
		shared.LoginFailed(h.guard, shared.LoginLockScopeUser, account)
		shared.Fail(c, err)
		return
	}
	shared.LoginSucceeded(h.guard, shared.LoginLockScopeUser, account)
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
	Tunnels      []gin.H `json:"tunnels"`
	TrafficUsed  int64   `json:"traffic_used"`
	TrafficQuota int64   `json:"traffic_quota"`
	Exceeded     bool    `json:"exceeded"`
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
	tunnels, err := h.svc.ListTunnels(u.ID)
	if err != nil {
		shared.Fail(c, err)
		return
	}
	out := make([]gin.H, 0, len(tunnels))
	for i := range tunnels {
		out = append(out, h.tunnelVO(&tunnels[i]))
	}
	httpx.OK(c, clientInfoResp{
		ClientInfo:   info,
		Tunnels:      out,
		TrafficUsed:  u.TrafficUsed,
		TrafficQuota: h.svc.EffectiveQuota(u),
		Exceeded:     h.svc.QuotaExceeded(u),
	})
}

// ClientConfig 下载当前账号的 frpc.toml。
func (h *Handler) ClientConfig(c *gin.Context) {
	u, err := h.svc.LoadUser(middleware.CurrentUserID(c))
	if err != nil {
		shared.Fail(c, err)
		return
	}
	tunnels, err := h.svc.ListTunnels(u.ID)
	if err != nil {
		shared.Fail(c, err)
		return
	}
	text, err := h.svc.BuildFrpcConfig(u, tunnels)
	if err != nil {
		shared.Fail(c, err)
		return
	}
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
	dir := h.svc.Cfg.ClientDistDir
	entries, err := os.ReadDir(dir)
	if err != nil {
		httpx.OK(c, []ClientDownload{})
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
	httpx.OK(c, list)
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

// ---- 隧道管理 ----

// ListTunnels 列出当前用户隧道，并附加运行态。
func (h *Handler) ListTunnels(c *gin.Context) {
	uid := middleware.CurrentUserID(c)
	list, err := h.svc.ListTunnels(uid)
	if err != nil {
		shared.Fail(c, err)
		return
	}
	out := make([]gin.H, 0, len(list))
	for i := range list {
		out = append(out, h.tunnelVO(&list[i]))
	}
	httpx.OK(c, out)
}

func (h *Handler) tunnelVO(t *model.Tunnel) gin.H {
	return gin.H{
		"id":                   t.ID,
		"name":                 t.Name,
		"type":                 t.Type,
		"local_ip":             t.LocalIP,
		"local_port":           t.LocalPort,
		"remote_port":          t.RemotePort,
		"domain":               t.Domain,
		"subdomain":            t.Subdomain,
		"remark":               t.Remark,
		"status":               t.Status,
		"online":               h.svc.Runtime.IsTunnelOnline(t.ID),
		"traffic_used":         t.TrafficUsed,
		"bandwidth_limit":      t.BandwidthLimit,
		"bandwidth_limit_str":  service.FormatBandwidth(t.BandwidthLimit),
		"use_encryption":       t.UseEncryption,
		"use_compression":      t.UseCompression,
		"last_online_at":       t.LastOnlineAt,
		"created_at":           t.CreatedAt,
		"public_addr":          h.publicAddr(t),
	}
}

// publicAddr 给出该隧道对外的访问地址，方便用户直接复制。
func (h *Handler) publicAddr(t *model.Tunnel) string {
	host := h.svc.Cfg.GatewayHost
	switch t.Type {
	case model.ProxyTypeTCP, model.ProxyTypeUDP:
		if t.RemotePort == 0 {
			return ""
		}
		return host + ":" + strconv.Itoa(t.RemotePort)
	case model.ProxyTypeHTTP, model.ProxyTypeHTTPS:
		if t.Domain != "" {
			return t.Domain
		}
		if t.Subdomain != "" && h.svc.Cfg.TunnelDomain != "" {
			return t.Subdomain + "." + h.svc.Cfg.TunnelDomain
		}
	}
	return ""
}

// CreateTunnel 新建隧道。
func (h *Handler) CreateTunnel(c *gin.Context) {
	var in service.TunnelInput
	if err := c.ShouldBindJSON(&in); err != nil {
		httpx.BadRequest(c, "参数格式不正确")
		return
	}
	u, err := h.svc.LoadUser(middleware.CurrentUserID(c))
	if err != nil {
		shared.Fail(c, err)
		return
	}
	t, err := h.svc.CreateTunnel(u, in)
	if err != nil {
		shared.Fail(c, err)
		return
	}
	httpx.OK(c, h.tunnelVO(t))
}

// UpdateTunnel 修改隧道。
func (h *Handler) UpdateTunnel(c *gin.Context) {
	id, err := parseID(c)
	if err != nil {
		httpx.BadRequest(c, "隧道 ID 非法")
		return
	}
	var in service.TunnelInput
	if err := c.ShouldBindJSON(&in); err != nil {
		httpx.BadRequest(c, "参数格式不正确")
		return
	}
	u, err := h.svc.LoadUser(middleware.CurrentUserID(c))
	if err != nil {
		shared.Fail(c, err)
		return
	}
	t, err := h.svc.UpdateTunnel(u, id, in)
	if err != nil {
		shared.Fail(c, err)
		return
	}
	httpx.OK(c, h.tunnelVO(t))
}

// DeleteTunnel 删除隧道。
func (h *Handler) DeleteTunnel(c *gin.Context) {
	id, err := parseID(c)
	if err != nil {
		httpx.BadRequest(c, "隧道 ID 非法")
		return
	}
	if err := h.svc.DeleteTunnel(middleware.CurrentUserID(c), id); err != nil {
		shared.Fail(c, err)
		return
	}
	httpx.OK(c, gin.H{"message": "隧道已删除"})
}

type tunnelStatusReq struct {
	Status string `json:"status" binding:"required"`
}

// SetTunnelStatus 启用或停用隧道。
func (h *Handler) SetTunnelStatus(c *gin.Context) {
	id, err := parseID(c)
	if err != nil {
		httpx.BadRequest(c, "隧道 ID 非法")
		return
	}
	var req tunnelStatusReq
	if err := c.ShouldBindJSON(&req); err != nil {
		httpx.BadRequest(c, "参数格式不正确")
		return
	}
	if err := h.svc.SetTunnelStatus(middleware.CurrentUserID(c), id, req.Status); err != nil {
		shared.Fail(c, err)
		return
	}
	httpx.OK(c, gin.H{"message": "状态已更新"})
}

// ---- API Key ----

// GetAPIKey 返回 API Key 的元信息（不含明文）。
func (h *Handler) GetAPIKey(c *gin.Context) {
	u, err := h.svc.LoadUser(middleware.CurrentUserID(c))
	if err != nil {
		shared.Fail(c, err)
		return
	}
	httpx.OK(c, gin.H{
		"prefix":     u.APIKeyPrefix,
		"created_at": u.APIKeyCreatedAt,
		"exists":     u.APIKeyHash != "",
	})
}

// RevealAPIKey 解密回显 API Key 明文，供用户复制到客户端。
func (h *Handler) RevealAPIKey(c *gin.Context) {
	u, err := h.svc.LoadUser(middleware.CurrentUserID(c))
	if err != nil {
		shared.Fail(c, err)
		return
	}
	plain, err := h.svc.RevealAPIKey(u)
	if err != nil {
		httpx.BadRequest(c, "尚未生成 API Key，请先重置生成")
		return
	}
	httpx.OK(c, gin.H{"api_key": plain})
}

// RotateAPIKey 重置 API Key，旧 Key 立即失效。
func (h *Handler) RotateAPIKey(c *gin.Context) {
	uid := middleware.CurrentUserID(c)
	plain, prefix, err := h.svc.RotateAPIKey(uid)
	if err != nil {
		shared.Fail(c, err)
		return
	}
	httpx.OK(c, gin.H{
		"api_key": plain,
		"prefix":  prefix,
		"message": "API Key 已重置，请妥善保存，旧 Key 已失效",
	})
}

// ---- 兑换 ----

type redeemReq struct {
	Code string `json:"code" binding:"required"`
}

// Redeem 兑换码核销。
func (h *Handler) Redeem(c *gin.Context) {
	var req redeemReq
	if err := c.ShouldBindJSON(&req); err != nil {
		httpx.BadRequest(c, "请输入兑换码")
		return
	}
	res, err := h.svc.Redeem(middleware.CurrentUserID(c), req.Code, httpx.ClientIP(c))
	if err != nil {
		shared.Fail(c, err)
		return
	}
	httpx.OK(c, res)
}

// RedeemRecords 我的兑换记录。
func (h *Handler) RedeemRecords(c *gin.Context) {
	page, pageSize, offset := httpx.Pagination(c)
	list, total, err := h.svc.ListRedeemRecords(middleware.CurrentUserID(c), offset, pageSize)
	if err != nil {
		shared.Fail(c, err)
		return
	}
	httpx.PageOK(c, list, total, page, pageSize)
}

// ---- 概览与统计 ----

// StatsOverview 控制台首页概览。
func (h *Handler) StatsOverview(c *gin.Context) {
	uid := middleware.CurrentUserID(c)
	u, err := h.svc.LoadUser(uid)
	if err != nil {
		shared.Fail(c, err)
		return
	}
	tunnels, err := h.svc.ListTunnels(uid)
	if err != nil {
		shared.Fail(c, err)
		return
	}
	online := 0
	for i := range tunnels {
		if h.svc.Runtime.IsTunnelOnline(tunnels[i].ID) {
			online++
		}
	}
	httpx.OK(c, gin.H{
		"traffic_used":     u.TrafficUsed,
		"traffic_quota":    h.svc.EffectiveQuota(u),
		"traffic_exceeded": h.svc.QuotaExceeded(u),
		"balance":          u.Balance,
		"tunnel_total":     len(tunnels),
		"tunnel_online":    online,
		"group_name":       groupName(h.svc.EffectiveGroup(u)),
	})
}

func groupName(g *model.Group) string {
	if g == nil {
		return "未分组"
	}
	return g.Name
}

// TrafficStats 近 N 天流量曲线。
func (h *Handler) TrafficStats(c *gin.Context) {
	uid := middleware.CurrentUserID(c)
	days := 7
	if v, err := strconv.Atoi(c.DefaultQuery("days", "7")); err == nil && v > 0 && v <= 90 {
		days = v
	}
	type row struct {
		Date     string `json:"date"`
		InBytes  int64  `json:"in_bytes"`
		OutBytes int64  `json:"out_bytes"`
	}
	var rows []row
	err := h.svc.DB.Model(&model.TrafficDaily{}).
		Select("date, SUM(in_bytes) AS in_bytes, SUM(out_bytes) AS out_bytes").
		Where("user_id = ? AND date >= ?", uid, time.Now().AddDate(0, 0, -days+1).Format("2006-01-02")).
		Group("date").Order("date asc").Scan(&rows).Error
	if err != nil {
		shared.Fail(c, err)
		return
	}
	httpx.OK(c, rows)
}

func parseID(c *gin.Context) (uint, error) {
	v, err := strconv.ParseUint(c.Param("id"), 10, 64)
	if err != nil || v == 0 {
		return 0, errors.New("非法 ID")
	}
	return uint(v), nil
}
