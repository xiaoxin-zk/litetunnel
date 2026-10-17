package service

import (
	"errors"
	"fmt"
	"hash/fnv"
	"log"
	"net"
	"strings"
	"time"
	"unicode/utf8"

	"gorm.io/gorm"
	"gorm.io/gorm/clause"

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
	list, _, _, err := s.ListTunnelsPage(userID, 0, 0)
	return list, err
}

// ListTunnelsPage 按游标分页取某用户的隧道：返回 id < beforeID 的记录，
// beforeID 为 0 表示从最新一条开始；limit<=0 表示不分页（全部）。
//
// 为什么要分页：客户端接入信息接口原先一次返回该账号的全部隧道，
// 隧道一多响应就能顶到客户端 4 MiB 的读取上限，截断后 JSON 解析失败，
// 表现为「同步一直失败、界面上什么都没变」。分页后单页大小可控。
//
// 为什么用游标而不是 offset：分页期间发生增删时，offset 会错位——
// 删掉一条之后下一页的 offset 越过了本来该出现的那条，或新增一条
// 导致下一页重复返回。客户端拿到漏项的清单，会把漏掉的隧道当成
// 「服务端已删除」而停掉本机进程、删掉本地配置。游标只依赖 id 的
// 单调性，增删都不会让分页错位。
//
// 同时返回总数与**清单版本**：只比条数会漏过「数量相抵」的并发变更
// （分页期间删掉一条已取到的、同时新增一条 id 更大的：总数不变，但
// 新隧道落在游标之前，永远取不到）。版本是对账相关字段的摘要，见
// tunnelListVersionTx。
//
// 版本与页面数据在**同一个只读事务**里读：SQLite 只有一条连接，事务内
// 看到的是同一个快照；即便别的数据库上是逐语句快照，跨页比对版本也能
// 发现期间的变化，最坏只是多重取一轮。
func (s *Services) ListTunnelsPage(userID, beforeID uint, limit int) (list []model.Tunnel, total int64, version string, err error) {
	err = s.DB.Transaction(func(tx *gorm.DB) error {
		v, n, verr := s.tunnelListVersionTx(tx, userID)
		if verr != nil {
			return verr
		}
		version, total = v, n

		q := tx.Where("user_id = ?", userID).Order("id desc")
		if beforeID > 0 {
			q = q.Where("id < ?", beforeID)
		}
		if limit > 0 {
			q = q.Limit(limit)
		}
		return q.Find(&list).Error
	})
	if err != nil {
		return nil, 0, "", err
	}
	return list, total, version, nil
}

// tunnelListVersionTx 计算用户隧道清单的版本，覆盖**客户端对账用到的
// 全部字段**，而不只是条数与 id。
//
// 只算「总数 + 最大 id」发现不了「启用切停用」「改了端口/域名」这类不增删
// 记录的变更：多页同步期间状态翻转时，各页版本仍然一致，客户端会按旧
// 状态启停进程，直到下一轮同步才纠正。
//
// 摘要里**不含** updated_at 与流量/在线字段：采集器每轮都会写这些列，
// 让它们参与版本会让版本无谓地抖动，多页同步被反复打断。
func (s *Services) tunnelListVersionTx(tx *gorm.DB, userID uint) (string, int64, error) {
	var rows []model.Tunnel
	if err := tx.Model(&model.Tunnel{}).
		Select("id, status, name, type, local_ip, local_port, remote_port, domain, subdomain, bandwidth_limit, use_encryption, use_compression").
		Where("user_id = ?", userID).Order("id asc").Find(&rows).Error; err != nil {
		return "", 0, err
	}
	h := fnv.New64a()
	for _, t := range rows {
		fmt.Fprintf(h, "%d|%s|%s|%s|%s|%d|%d|%s|%s|%d|%t|%t;",
			t.ID, t.Status, t.Name, t.Type, t.LocalIP, t.LocalPort, t.RemotePort,
			t.Domain, t.Subdomain, t.BandwidthLimit, t.UseEncryption, t.UseCompression)
	}
	return fmt.Sprintf("%d:%016x", len(rows), h.Sum64()), int64(len(rows)), nil
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
		created, err = s.createTunnelLocked(u, in, true)
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

// reloadUserWithGroupTx 在事务内重读用户行与生效分组，两者都加行锁。
//
// handler 传入的 u 是请求开始时加载的快照：管理员改组（AdminSetUserGroup
// 锁用户行）、调套餐与我们交错时，快照里的协议、隧道数、域名权限都可能
// 已经过时——按旧套餐建出的隧道会一直带着越权参数跑下去。
//
// FOR UPDATE 必须在**事务内**才真正持锁到提交：放在事务外只是一次
// 立即释放的读，挡不住紧接着提交的改组。锁序「用户行 → 分组行」，
// 与 Redeem / AdminSetUserGroup / DeleteGroup 一致。
func (s *Services) reloadUserWithGroupTx(tx *gorm.DB, userID uint) (*model.User, *model.Group, error) {
	var u model.User
	if err := tx.Clauses(clause.Locking{Strength: "UPDATE"}).
		First(&u, userID).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, nil, ErrNotFound
		}
		return nil, nil, err
	}
	g, err := s.effectiveGroupTx(tx, &u)
	if err != nil {
		return nil, nil, err
	}
	return &u, g, nil
}

// effectiveGroupTx 按 EffectiveGroup 的语义取生效分组，但对分组行加锁，
// 且只使用传入的 tx——SQLite 只开一个连接，事务内再用 s.DB 查询会自己
// 等死自己。
func (s *Services) effectiveGroupTx(tx *gorm.DB, u *model.User) (*model.Group, error) {
	// 分组已过期或未绑定：回落默认分组（与 EffectiveGroup 一致）。
	if u.GroupExpireAt != nil && u.GroupExpireAt.Before(time.Now()) {
		return s.defaultGroupTx(tx), nil
	}
	if u.GroupID == 0 {
		return s.defaultGroupTx(tx), nil
	}
	var g model.Group
	if err := tx.Clauses(clause.Locking{Strength: "UPDATE"}).
		First(&g, u.GroupID).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			// 分组刚被并发删除：按未绑定处理，回落默认分组。
			return s.defaultGroupTx(tx), nil
		}
		return nil, err
	}
	return &g, nil
}

// defaultGroupTx 是 defaultGroup 的事务内版本，原因同上。
//
// 默认分组同样加行锁：它虽不可删除，但套餐（协议、隧道数、域名权限）
// 仍可被 UpdateGroup 调整。不加锁的话，回落到默认分组的用户在并发调组
// 时会按调整前的权限建出隧道——与普通分组路径的锁语义必须一致。
func (s *Services) defaultGroupTx(tx *gorm.DB) *model.Group {
	var g model.Group
	if err := tx.Clauses(clause.Locking{Strength: "UPDATE"}).
		Where("is_default = ?", true).First(&g).Error; err != nil {
		return nil
	}
	return &g
}

// createTunnelLocked 在**已持有该用户锁**的前提下创建隧道。
//
// firewallNow 决定是否在事务提交后立即尝试放行防火墙端口：
// 单条创建传 true（规则即时生效）；批量创建传 false 并把放行挪到
// 用户锁之外异步执行——helper 不可达时单次网络调用可达 10 秒，
// 串行二十条会把同一用户的其他操作全部卡在锁上（见 CreateTunnelsBatch）。
// 无论哪种，放行失败都会进重试队列兜底。
func (s *Services) createTunnelLocked(u *model.User, in TunnelInput, firewallNow bool) (*model.Tunnel, error) {
	var created model.Tunnel

	// portUnlock 在事务内取到端口锁之后赋值，事务结束（无论成败）后释放。
	// 之所以要在**提交之前**取锁，见下面取锁处的说明。
	var portUnlock func()
	defer func() {
		if portUnlock != nil {
			portUnlock()
		}
	}()

	err := s.DB.Transaction(func(tx *gorm.DB) error {
		// 用户与生效分组在事务内重读并加行锁（见 reloadUserWithGroupTx）：
		// 数量上限、协议、域名权限都以**此刻**的套餐为准，而不是请求
		// 开始时的快照。
		u, g, err := s.reloadUserWithGroupTx(tx, u.ID)
		if err != nil {
			return err
		}
		if g == nil {
			return errors.New("当前账号未绑定任何分组，请联系管理员")
		}

		normalized, err := s.normalizeInput(u, g, in)
		if err != nil {
			return err
		}

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
	if firewallNow && created.RemotePort > 0 {
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

	// 用户与生效分组在事务内重读并加行锁：编辑 HTTP/HTTPS 隧道时的域名
	// 权限按**此刻**的套餐判定，而不是请求开始时的快照（见
	// reloadUserWithGroupTx）。
	if err := s.DB.Transaction(func(tx *gorm.DB) error {
		u, g, err := s.reloadUserWithGroupTx(tx, u.ID)
		if err != nil {
			return err
		}
		if g == nil {
			return errors.New("当前账号未绑定任何分组，请联系管理员")
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
				return err
			}
			updates["domain"] = domain
			updates["subdomain"] = sub
		}

		res := tx.Model(&model.Tunnel{}).
			Where("id = ? AND user_id = ?", id, u.ID).
			Updates(updates)
		if res.Error != nil {
			return res.Error
		}
		if res.RowsAffected == 0 {
			// 记录在编辑期间被删除（或从未属于该用户）：如实报不存在。
			// 这里绝不能像 Save 的零行回退那样把它重新插回去。
			return ErrNotFound
		}
		return nil
	}); err != nil {
		return nil, err
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
