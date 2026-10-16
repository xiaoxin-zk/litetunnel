package service

import (
	"errors"
	"fmt"
	"log"
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
//
// 全程持有该用户的锁：与「删除该用户」互斥（见 userLock）。
func (s *Services) CreateTunnel(u *model.User, in TunnelInput) (*model.Tunnel, error) {
	lock := s.userLock(u.ID)
	lock.Lock()
	defer lock.Unlock()

	// 自动分配端口时，唯一索引仍可能在并发下拒绝其中一个：两个请求恰好
	// 随机到同一个端口（概率很低，但会发生）。这是可重试的——换一个随机
	// 端口，把整条建隧道流程重来一次即可。
	//
	// 重试放在**这里**而不是事务内部，是为了让每次尝试都是一次完整的
	// createTunnelLocked：它拿到的端口锁会随这次调用返回而释放，重试时
	// 重新取新端口的锁。放在事务内部的话，上一把锁只能靠 defer 释放最后
	// 那一把，旧端口上的防火墙操作会从此卡死。
	//
	// 用户自己指定端口时不重试：那是他明确要的端口，冲突应当如实报错，
	// 而不是悄悄换一个给他。
	attempts := 1
	if in.RemotePort == 0 {
		attempts = portAllocAttempts
	}

	var (
		created *model.Tunnel
		err     error
	)
	for attempt := 1; attempt <= attempts; attempt++ {
		created, err = s.createTunnelLocked(u, in)
		if err == nil {
			return created, nil
		}
		if !isPortConflict(err) {
			return nil, describeTunnelWriteError(err)
		}
		log.Printf("[tunnel] 端口分配撞车（第 %d/%d 次尝试），重新随机分配后重试", attempt, attempts)
	}
	// 重试次数用尽仍是端口冲突：如实返回（下面这行对它没有影响）。
	return nil, describeTunnelWriteError(err)
}

// createTunnelLocked 在**已持有该用户锁**的前提下创建隧道。
func (s *Services) createTunnelLocked(u *model.User, in TunnelInput) (*model.Tunnel, error) {
	g := s.EffectiveGroup(u)
	if g == nil {
		return nil, errors.New("当前账号未绑定任何分组，请联系管理员")
	}

	normalized, err := s.normalizeInput(u, g, in)
	if err != nil {
		return nil, err
	}

	var created model.Tunnel

	// portUnlock 在事务内取到端口锁之后赋值，事务结束（无论成败）后释放。
	// 之所以要在**提交之前**取锁，见下面取锁处的说明。
	var portUnlock func()
	defer func() {
		if portUnlock != nil {
			portUnlock()
		}
	}()

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

		// 拿到该端口的锁，并持有到下面的放行完成。
		//
		// 必须在**提交之前**取：一条「收回 20001」的待办重试时，会先查数据库
		// 确认这个端口确实不该开着。如果本事务还没提交，它查不到这条新隧道，
		// 于是认为可以关——然后我们提交、放行，它紧接着把端口关掉。
		// 新隧道的规则就这样被一条过时任务关掉了，用户看到「刚建好就连不上」。
		//
		// 取锁顺序是「用户锁 → 端口锁」，与删除路径一致，不会死锁。
		if normalized.RemotePort > 0 {
			pl := s.portLock(normalized.RemotePort)
			pl.Lock()
			portUnlock = pl.Unlock
		}

		normalized.UserID = u.ID
		normalized.BandwidthLimit = g.BandwidthLimit
		if err := tx.Create(&normalized).Error; err != nil {
			return err
		}
		// 把写入后的结果带出去（含自增 ID 与分配到的公网端口）。
		//
		// 少了这一步，CreateTunnel 会返回一个**零值隧道**：上面的
		// tx.Create 填的是 normalized，而不是外面声明的 created。
		// 这个错误长期没被发现，是因为调用方大多紧接着重新拉一次列表，
		// 拿到的是真实数据；但直接读接口返回值的人（包括新加的批量创建）
		// 会拿到一个 id=0、name 为空的对象。
		created = normalized
		return nil
	})
	if err != nil {
		return nil, err
	}

	// 隧道建好后按需在主机防火墙上放行端口。
	// 失败不影响隧道本身——管理员仍可去云安全组手工放行，
	// 而把建隧道整体失败掉会让用户完全无从下手。
	//
	// 用 Locked 版本：该端口的锁已经在事务里拿到了（见上面取锁处），
	// 这里再调一次会重复加锁、直接死锁。
	if created.RemotePort > 0 {
		s.applyPortIntentLocked(created.RemotePort, ProtoOfTunnel(created.Type), true)
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
	// 先取出端口信息：记录删掉之后就查不到了，
	// 而防火墙需要它才能收回对应的放行规则。
	var t model.Tunnel
	if err := s.DB.Where("id = ? AND user_id = ?", id, userID).First(&t).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return ErrNotFound
		}
		return err
	}

	res := s.DB.Where("id = ? AND user_id = ?", id, userID).Delete(&model.Tunnel{})
	if res.Error != nil {
		return res.Error
	}
	if res.RowsAffected == 0 {
		return ErrNotFound
	}

	// 隧道已删除，收回防火墙上的放行规则。
	//
	// 走 applyPortIntent 而不是直接调 FirewallClosePort：后者失败时只写一行
	// 日志，而记录已经删了、端口号再也查不回来——helper 恰好不可用的话，
	// 这条规则就永久留在宿主机上，且没有任何地方会再尝试收回。
	// 若该端口在保护列表中，护栏会拒绝并记日志，属预期行为。
	if t.RemotePort > 0 {
		s.applyPortIntent(t.RemotePort, ProtoOfTunnel(t.Type), false)
	}
	return nil
}

// SetTunnelStatus 启用/停用隧道。
//
// 状态切换同时联动防火墙：停用即收回端口，启用即重新放行。
// 否则「停用的隧道端口仍然对外开放」会成为一个隐蔽的安全缺口。
func (s *Services) SetTunnelStatus(userID, id uint, status string) error {
	if status != model.TunnelStatusActive && status != model.TunnelStatusDisabled {
		return ErrInvalidParam
	}

	var t model.Tunnel
	if err := s.DB.Where("id = ? AND user_id = ?", id, userID).First(&t).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return ErrNotFound
		}
		return err
	}

	// 重新启用一条 HTTPS 隧道时同样要确认入口还在：管理员可能已经把平台
	// 切回了边缘模式。否则「停用 → 切换模式 → 启用」会绕开创建时的检查，
	// 得到一条状态为运行中、实际永远连不上的隧道。
	if status == model.TunnelStatusActive && t.Type == model.ProxyTypeHTTPS && !s.HTTPSProxyEntryEnabled() {
		return ErrNoHTTPSProxyEntry
	}

	if err := s.DB.Model(&model.Tunnel{}).
		Where("id = ? AND user_id = ?", id, userID).
		Update("status", status).Error; err != nil {
		return err
	}

	if t.RemotePort > 0 {
		if status == model.TunnelStatusActive {
			s.applyPortIntent(t.RemotePort, ProtoOfTunnel(t.Type), true)
		} else {
			// 收回失败要进重试队列：数据库状态已经改了、接口也返回成功，
			// 只写一行日志的话规则会一直开着，而且没有任何地方会再尝试。
			s.applyPortIntent(t.RemotePort, ProtoOfTunnel(t.Type), false)
		}
	}
	return nil
}

func truncate(s string, n int) string {
	s = strings.TrimSpace(s)
	if len(s) <= n {
		return s
	}
	return s[:n]
}
