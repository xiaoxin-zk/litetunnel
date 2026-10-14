package service

import (
	"errors"
	"fmt"
	"net"
	"strings"

	"gorm.io/gorm"

	"github.com/xiaoxin-zk/litetunnel/server/internal/model"
)

// TunnelInput 隧道创建/更新入参。
type TunnelInput struct {
	Name           string `json:"name"`
	Type           string `json:"type"`
	LocalIP        string `json:"local_ip"`
	LocalPort      int    `json:"local_port"`
	RemotePort     int    `json:"remote_port"`
	Domain         string `json:"domain"`
	Subdomain      string `json:"subdomain"`
	Remark         string `json:"remark"`
	UseEncryption  bool   `json:"use_encryption"`
	UseCompression bool   `json:"use_compression"`
}

// ListTunnels 返回用户全部隧道。
func (s *Services) ListTunnels(userID uint) ([]model.Tunnel, error) {
	var list []model.Tunnel
	err := s.DB.Where("user_id = ?", userID).Order("id desc").Find(&list).Error
	return list, err
}

// GetTunnel 按 ID 与归属校验后取隧道。
func (s *Services) GetTunnel(userID, id uint) (*model.Tunnel, error) {
	var t model.Tunnel
	err := s.DB.Where("id = ? AND user_id = ?", id, userID).First(&t).Error
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	return &t, nil
}

// FindTunnelByName 按用户与隧道名定位，供 frps 插件回调校验使用。
func (s *Services) FindTunnelByName(userID uint, name string) (*model.Tunnel, error) {
	var t model.Tunnel
	err := s.DB.Where("user_id = ? AND name = ?", userID, name).First(&t).Error
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	return &t, nil
}

// CreateTunnel 校验分组权限并创建隧道。
func (s *Services) CreateTunnel(u *model.User, in TunnelInput) (*model.Tunnel, error) {
	g := s.EffectiveGroup(u)
	if g == nil {
		return nil, errors.New("当前账号未绑定任何分组，请联系管理员")
	}

	normalized, err := s.normalizeInput(u, g, in)
	if err != nil {
		return nil, err
	}

	var created model.Tunnel
	err = s.DB.Transaction(func(tx *gorm.DB) error {
		// 数量上限校验放在事务内，避免并发绕过限制。
		var count int64
		if err := tx.Model(&model.Tunnel{}).Where("user_id = ?", u.ID).Count(&count).Error; err != nil {
			return err
		}
		if g.MaxTunnels > 0 && count >= int64(g.MaxTunnels) {
			return ErrTunnelLimit
		}

		if normalized.Type == model.ProxyTypeTCP || normalized.Type == model.ProxyTypeUDP {
			if g.MaxPorts > 0 {
				var portCount int64
				if err := tx.Model(&model.Tunnel{}).
					Where("user_id = ? AND remote_port > 0", u.ID).Count(&portCount).Error; err != nil {
					return err
				}
				if portCount >= int64(g.MaxPorts) {
					return ErrPortLimit
				}
			}
			port := normalized.RemotePort
			if port == 0 {
				p, err := s.allocatePort(tx, u.ID)
				if err != nil {
					return err
				}
				port = p
			} else if err := s.assertPortFree(tx, port); err != nil {
				return err
			}
			normalized.RemotePort = port
		} else {
			normalized.RemotePort = 0
		}

		normalized.UserID = u.ID
		normalized.BandwidthLimit = g.BandwidthLimit
		return tx.Create(&normalized).Error
	})
	if err != nil {
		return nil, err
	}
	return &created, nil
}

// UpdateTunnel 更新隧道。端口与协议不可变更，避免影响已下发的客户端配置。
func (s *Services) UpdateTunnel(u *model.User, id uint, in TunnelInput) (*model.Tunnel, error) {
	t, err := s.GetTunnel(u.ID, id)
	if err != nil {
		return nil, err
	}
	g := s.EffectiveGroup(u)
	if g == nil {
		return nil, errors.New("当前账号未绑定任何分组，请联系管理员")
	}

	if in.LocalPort < 1 || in.LocalPort > 65535 {
		return nil, fmt.Errorf("%w: 本地端口需在 1-65535 之间", ErrInvalidParam)
	}
	localIP := strings.TrimSpace(in.LocalIP)
	if localIP == "" {
		localIP = "127.0.0.1"
	}
	if net.ParseIP(localIP) == nil && !isValidHostname(localIP) {
		return nil, fmt.Errorf("%w: 本地地址格式不正确", ErrInvalidParam)
	}

	t.LocalIP = localIP
	t.LocalPort = in.LocalPort
	t.Remark = truncate(in.Remark, 200)
	t.UseEncryption = in.UseEncryption
	t.UseCompression = in.UseCompression

	if t.Type == model.ProxyTypeHTTP || t.Type == model.ProxyTypeHTTPS {
		domain, sub, err := s.normalizeDomain(g, in)
		if err != nil {
			return nil, err
		}
		t.Domain = domain
		t.Subdomain = sub
	}

	if err := s.DB.Save(t).Error; err != nil {
		return nil, err
	}
	return t, nil
}

// DeleteTunnel 删除隧道并释放端口。
func (s *Services) DeleteTunnel(userID, id uint) error {
	res := s.DB.Where("id = ? AND user_id = ?", id, userID).Delete(&model.Tunnel{})
	if res.Error != nil {
		return res.Error
	}
	if res.RowsAffected == 0 {
		return ErrNotFound
	}
	return nil
}

// SetTunnelStatus 启用/停用隧道。
func (s *Services) SetTunnelStatus(userID, id uint, status string) error {
	if status != model.TunnelStatusActive && status != model.TunnelStatusDisabled {
		return ErrInvalidParam
	}
	res := s.DB.Model(&model.Tunnel{}).
		Where("id = ? AND user_id = ?", id, userID).
		Update("status", status)
	if res.Error != nil {
		return res.Error
	}
	if res.RowsAffected == 0 {
		return ErrNotFound
	}
	return nil
}

// normalizeInput 统一校验并清洗入参。
func (s *Services) normalizeInput(u *model.User, g *model.Group, in TunnelInput) (model.Tunnel, error) {
	var out model.Tunnel

	name := strings.TrimSpace(in.Name)
	if len(name) < 1 || len(name) > 32 || !IsSafeName(name) {
		return out, fmt.Errorf("%w: 隧道名称需为 1-32 位字母、数字或下划线", ErrInvalidParam)
	}
	// 名称会拼进 frp 的 proxy 名（形如 {user}.{name}），前缀保留给系统使用。
	if strings.HasPrefix(strings.ToLower(name), "lt") {
		return out, fmt.Errorf("%w: 隧道名称不能以 lt 开头", ErrInvalidParam)
	}

	ptype := strings.ToLower(strings.TrimSpace(in.Type))
	allowed := AllowedProtocols(g)
	if !allowed[ptype] {
		return out, ErrProtocolDenied
	}
	switch ptype {
	case model.ProxyTypeTCP, model.ProxyTypeUDP, model.ProxyTypeHTTP, model.ProxyTypeHTTPS:
	default:
		return out, ErrProtocolDenied
	}

	if in.LocalPort < 1 || in.LocalPort > 65535 {
		return out, fmt.Errorf("%w: 本地端口需在 1-65535 之间", ErrInvalidParam)
	}
	localIP := strings.TrimSpace(in.LocalIP)
	if localIP == "" {
		localIP = "127.0.0.1"
	}
	if net.ParseIP(localIP) == nil && !isValidHostname(localIP) {
		return out, fmt.Errorf("%w: 本地地址格式不正确", ErrInvalidParam)
	}

	out = model.Tunnel{
		Name:           name,
		Type:           ptype,
		LocalIP:        localIP,
		LocalPort:      in.LocalPort,
		Remark:         truncate(in.Remark, 200),
		UseEncryption:  in.UseEncryption,
		UseCompression: in.UseCompression,
		Status:         model.TunnelStatusActive,
	}

	if ptype == model.ProxyTypeHTTP || ptype == model.ProxyTypeHTTPS {
		domain, sub, err := s.normalizeDomain(g, in)
		if err != nil {
			return out, err
		}
		out.Domain = domain
		out.Subdomain = sub
	} else {
		out.RemotePort = in.RemotePort
	}
	return out, nil
}

// normalizeDomain 处理 HTTP/HTTPS 的域名或二级域名。
func (s *Services) normalizeDomain(g *model.Group, in TunnelInput) (domain, sub string, err error) {
	domain = strings.ToLower(strings.TrimSpace(in.Domain))
	sub = strings.ToLower(strings.TrimSpace(in.Subdomain))

	if domain == "" && sub == "" {
		return "", "", fmt.Errorf("%w: HTTP/HTTPS 隧道需指定域名或二级域名", ErrInvalidParam)
	}
	if domain != "" {
		if !g.AllowCustomDomain {
			return "", "", ErrDomainDenied
		}
		if !isValidHostname(domain) {
			return "", "", fmt.Errorf("%w: 域名格式不正确", ErrInvalidParam)
		}
		// 自定义域名必须落在平台泛域名之下，防止用户劫持他人域名。
		if s.Cfg.TunnelDomain != "" && !strings.HasSuffix(domain, "."+s.Cfg.TunnelDomain) && domain != s.Cfg.TunnelDomain {
			return "", "", fmt.Errorf("%w: 仅允许使用 *.%s 下的域名", ErrDomainDenied, s.Cfg.TunnelDomain)
		}
		return domain, "", nil
	}

	if s.Cfg.TunnelDomain == "" {
		return "", "", fmt.Errorf("%w: 平台未配置泛域名，暂不支持二级域名", ErrInvalidParam)
	}
	if !IsSafeName(sub) {
		return "", "", fmt.Errorf("%w: 二级域名仅允许字母、数字或下划线", ErrInvalidParam)
	}
	return "", sub, nil
}

// allocatePort 从端口池中分配一个未占用端口。
//
// 依赖 lt_tunnels(remote_port) 上的部分唯一索引做最终兜底：
// 即使并发分配撞车，也会由数据库拒绝，不会出现端口冲突。
func (s *Services) allocatePort(tx *gorm.DB, userID uint) (int, error) {
	// 必须统计全部用户（含自己）已占用的端口，否则会给同一用户重复分配。
	var used []int
	if err := tx.Model(&model.Tunnel{}).
		Where("remote_port > 0").
		Pluck("remote_port", &used).Error; err != nil {
		return 0, err
	}
	set := make(map[int]struct{}, len(used))
	for _, p := range used {
		set[p] = struct{}{}
	}

	start, end := s.Cfg.PortRangeStart, s.Cfg.PortRangeEnd
	span := end - start + 1
	if span <= 0 {
		return 0, ErrNoPortAvailable
	}
	// 从用户 ID 派生起点，把不同用户的端口天然分散开，降低并发碰撞概率。
	offset := int(userID) % span
	for i := 0; i < span; i++ {
		p := start + (offset+i)%span
		if _, ok := set[p]; !ok {
			return p, nil
		}
	}
	return 0, ErrNoPortAvailable
}

// assertPortFree 校验指定端口是否可用。
func (s *Services) assertPortFree(tx *gorm.DB, port int) error {
	if port < s.Cfg.PortRangeStart || port > s.Cfg.PortRangeEnd {
		return fmt.Errorf("%w: 端口需在 %d-%d 范围内", ErrInvalidParam, s.Cfg.PortRangeStart, s.Cfg.PortRangeEnd)
	}
	var n int64
	if err := tx.Model(&model.Tunnel{}).Where("remote_port = ?", port).Count(&n).Error; err != nil {
		return err
	}
	if n > 0 {
		return ErrPortInUse
	}
	return nil
}

func isValidHostname(s string) bool {
	if s == "" || len(s) > 253 {
		return false
	}
	for _, label := range strings.Split(s, ".") {
		if label == "" || len(label) > 63 {
			return false
		}
		for i, r := range label {
			switch {
			case r >= 'a' && r <= 'z', r >= '0' && r <= '9':
			case r == '-':
				if i == 0 || i == len(label)-1 {
					return false
				}
			default:
				return false
			}
		}
	}
	return true
}

func truncate(s string, n int) string {
	s = strings.TrimSpace(s)
	if len(s) <= n {
		return s
	}
	return s[:n]
}
