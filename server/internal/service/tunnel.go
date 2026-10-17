package service

import (
	"errors"
	"fmt"
	"log"
	"net"
	"strings"
	"unicode/utf8"

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
//
// # 为什么不能整行 Save
//
// Save(t) 会把**整条记录**写回去，而采集器（见 runtime.go）正并发更新同一条
// 记录的流量与在线时间：编辑读到旧快照、采集器写入新值、Save 再用旧快照
// 覆盖回去——流量凭空缩水。同理，并发停用写回的「停用」状态也会被编辑
// 快照里的「启用」改回去。
//
// 更糟的是删除竞态：删除先完成后，GORM 的 Save 在更新影响行数为零时会
// 回退为插入——已删除的隧道被这次「编辑」复活，且防火墙意图不会跟着
// 这次复活重新应用。
//
// 因此只更新本次允许修改的字段（状态、端口、流量等一概不碰），
// 用 id + user_id 圈定目标并检查影响行数：删掉了就返回 NotFound，
// 绝不重新插入。编辑与删除、状态变更共用用户锁（userLock），
// 同一用户的这三类操作只能先后发生。
func (s *Services) UpdateTunnel(u *model.User, id uint, in TunnelInput) (*model.Tunnel, error) {
	// 与「删除该用户」「删除隧道」「启停隧道」互斥（见 userLock）：
	// 这些操作都以「读状态 → 改数据」的模式工作，交错时各自的读
	// 都可能过时。
	lock := s.userLock(u.ID)
	lock.Lock()
	defer lock.Unlock()

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

	updates := map[string]any{
		"local_ip":        localIP,
		"local_port":      in.LocalPort,
		"remark":          truncate(in.Remark, 200),
		"use_encryption":  in.UseEncryption,
		"use_compression": in.UseCompression,
	}
	if t.Type == model.ProxyTypeHTTP || t.Type == model.ProxyTypeHTTPS {
		domain, sub, err := s.normalizeDomain(g, in)
		if err != nil {
			return nil, err
		}
		updates["domain"] = domain
		updates["subdomain"] = sub
	}

	res := s.DB.Model(&model.Tunnel{}).
		Where("id = ? AND user_id = ?", id, u.ID).
		Updates(updates)
	if res.Error != nil {
		return nil, res.Error
	}
	if res.RowsAffected == 0 {
		// 记录在编辑期间被删除（或从未属于该用户）：如实报不存在。
		// 这里绝不能像 Save 的零行回退那样把它重新插回去。
		return nil, ErrNotFound
	}
	return s.GetTunnel(u.ID, id)
}

// DeleteTunnel 删除隧道并释放端口。
//
// 全程持有该用户的锁：与「编辑隧道」「启停隧道」共用（见 UpdateTunnel）。
// 删除是「读状态 → 删记录 → 收端口」三步，中间插进一次编辑或状态切换，
// 那次操作的副作用（比如按启用状态放行的端口）会建立在已被删除的记录上。
func (s *Services) DeleteTunnel(userID, id uint) error {
	lock := s.userLock(userID)
	lock.Lock()
	defer lock.Unlock()

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
// 这里只负责「按用户圈定目标」；状态切换本身走 setTunnelStatus——管理员那条
// 路径也要用同一套检查，两处各写一份迟早会分叉（见 assertTunnelCanEnable）。
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
	return s.setTunnelStatus(&t, status)
}

// assertTunnelCanEnable 是「把隧道切到启用」的唯一前置检查。
//
// 只检查启用方向的 HTTPS：平台切回边缘模式后，那条隧道在 Caddy 与 frps 上
// 都没有对应入口了。此时「停用 → 切模式 → 启用」会绕开创建时的检查，得到一条
// 状态为运行中、实际永远连不上的隧道——用户只会看到连不上，界面却一切正常。
//
// 用户侧与管理员侧都必须走它。分开写的话，先漏掉的一定是后来新增的那条路径。
func (s *Services) assertTunnelCanEnable(t *model.Tunnel, status string) error {
	if status != model.TunnelStatusActive || t.Type != model.ProxyTypeHTTPS {
		return nil
	}
	if !s.HTTPSProxyEntryEnabled() {
		return ErrNoHTTPSProxyEntry
	}
	return nil
}

// setTunnelStatus 是「启用/停用隧道」的唯一实现。
//
// 状态切换的副作用不止改一行数据库：还要校验 HTTPS 入口、联动防火墙。
// 这些必须与状态变更保持同一份代码，否则新增一条入口（管理员批量操作、
// 命令行工具）就会漏掉其中一项。
func (s *Services) setTunnelStatus(t *model.Tunnel, status string) error {
	// 与编辑、删除互斥（见 UpdateTunnel 的说明）：这些都是「读状态 → 改数据」
	// 的操作，交错时各自的读都可能过时。锁按隧道**归属者**取，
	// 用户侧与管理员侧两条路径共用，谁也不会漏。
	lock := s.userLock(t.UserID)
	lock.Lock()
	defer lock.Unlock()

	// 锁内重读：调用方的读发生在取锁之前，删除可能已经先拿到锁并完成。
	// 不重读的话，随后的零行更新会被当成成功——接口返回 200，
	// 状态根本没改，用户看到「已停用」的隧道实际还在跑。
	var cur model.Tunnel
	if err := s.DB.First(&cur, t.ID).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return ErrNotFound
		}
		return err
	}
	t = &cur

	if err := s.assertTunnelCanEnable(t, status); err != nil {
		return err
	}

	// 零行更新同样不能当成功：重读到更新之间没有数据库级互斥
	// （用户锁只拦本进程），这条兜底把残余竞态也如实暴露出来。
	res := s.DB.Model(&model.Tunnel{}).
		Where("id = ?", t.ID).
		Update("status", status)
	if res.Error != nil {
		return res.Error
	}
	if res.RowsAffected == 0 {
		return ErrNotFound
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

// truncate 按字节上限截断，但绝不切断多字节字符。
//
// 输入是用户填的备注、错误信息这类文本，中文一个字占三个字节：直接按
// 字节切片的话，切点落在字符中间，存进库的是一段以替换字符收尾的乱码
// ——界面上看起来像数据损坏。这里从上限处向前回退到最近的 UTF-8
// 字符起始字节，最多回退 3 个字节（UTF-8 单字符最长 4 字节，回退
// 已覆盖所有合法前缀）。入参本身仍是字节上限，调用方的约束不变。
func truncate(s string, n int) string {
	s = strings.TrimSpace(s)
	if len(s) <= n {
		return s
	}
	cut := s[:n]
	for len(cut) > 0 {
		r, size := utf8.DecodeLastRuneInString(cut)
		if r != utf8.RuneError || size != 1 {
			break
		}
		cut = cut[:len(cut)-1]
	}
	return cut
}
