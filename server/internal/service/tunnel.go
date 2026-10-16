package service

import (
	"crypto/rand"
	"errors"
	"fmt"
	"log"
	"math/big"
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

// portAllocAttempts 是自动分配端口撞车后的最大尝试次数。
//
// 取 5 是权衡：随机撞车的概率本身很低（池子越大越低），5 次几乎不可能全部
// 撞上；而真撞上 5 次说明池子已经接近占满，继续重试也没意义。
const portAllocAttempts = 5

// isPortConflict 判断错误是否来自「端口唯一索引冲突」。
//
// 两个驱动的报错文本不同，但都会带上端口这个标识：
//
//	SQLite     ：UNIQUE constraint failed: lt_tunnels.remote_port
//	PostgreSQL ：duplicate key value violates unique constraint "idx_lt_tunnels_remote_port"
//
// 判定必须**同时**要求「是唯一约束」和「提到端口」，只认前者会把名称冲突
// 也算进来（见 isNameConflict）：那种冲突重试再多次也还是同一个错误，
// 却会在日志里留下 5 行「端口分配撞车」——把排查方向直接带到错的地方。
func isPortConflict(err error) bool {
	if err == nil {
		return false
	}
	msg := strings.ToLower(err.Error())
	if !strings.Contains(msg, "unique") && !strings.Contains(msg, "duplicate key") {
		return false
	}
	return strings.Contains(msg, "remote_port")
}

// isNameConflict 判断错误是否来自「同一用户下隧道名重复」（user_id + name）。
//
// 排除法是刻意的：PG 的报错里往往只有索引名，而索引名是建表时定的
//（idx_user_tunnel），靠它反而更脆；带上 remote_port 的一定是端口冲突，
// 剩下的唯一约束冲突就只可能是名字。
func isNameConflict(err error) bool {
	if err == nil {
		return false
	}
	msg := strings.ToLower(err.Error())
	if !strings.Contains(msg, "unique") && !strings.Contains(msg, "duplicate key") {
		return false
	}
	return !strings.Contains(msg, "remote_port")
}

// describeTunnelWriteError 把唯一索引冲突翻译成用户看得懂的错误。
//
// 数据库原文（UNIQUE constraint failed: lt_tunnels.user_id, lt_tunnels.name）
// 对用户没有任何意义，原样往上抛只会变成一句「服务内部错误，请稍后重试」，
// 而用户真正需要知道的是「换个隧道名」。
func describeTunnelWriteError(err error) error {
	if err == nil {
		return nil
	}
	if !isPortConflict(err) && isNameConflict(err) {
		return fmt.Errorf("%w: 隧道名已存在，请换一个名字", ErrInvalidParam)
	}
	return err
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

// MaxBatchTunnels 是单次批量创建的上限。
//
// 取 20：足以覆盖「开一串连续端口的游戏服」这个主要场景，
// 又不至于让一次误操作把端口池占满。真正的上限仍由分组配置决定——
// 这里只是防止一次请求带来无上限的循环。
const MaxBatchTunnels = 20

// CreateTunnelBatchInput 是批量创建隧道的入参。
type CreateTunnelBatchInput struct {
	// NamePrefix 是名称前缀，每条隧道会被命名为「前缀_本机端口」。
	//
	// 用前缀而不是让用户逐个起名：批量创建的场景下（比如开一串
	// 连续端口的游戏服），逐条命名是纯粹的负担，而「前缀_端口」
	// 既保证唯一，又能一眼看出隧道与端口的对应关系。
	NamePrefix string `json:"name_prefix"`
	Type       string `json:"type"`
	LocalIP    string `json:"local_ip"`
	// Ports 是待映射的本机端口。公网端口一律由服务端自动分配。
	Ports []int `json:"ports"`
}

// BatchFailure 记录一条创建失败。
type BatchFailure struct {
	LocalPort int    `json:"local_port"`
	Name      string `json:"name"`
	Reason    string `json:"reason"`
}

// BatchCreateResult 是批量创建的结果。
type BatchCreateResult struct {
	Created  []model.Tunnel `json:"created"`
	Failures []BatchFailure `json:"failures"`
}

// CreateTunnelsBatch 批量创建隧道。
//
// 逐条创建、**不整体回滚**：用户要的是一批端口尽可能都建好，
// 而不是「一条失败就全都没了」。每条失败的原因单独返回，
// 用户才知道该去改哪一个。
//
// 遇到数量/端口上限时提前结束：后续每一条都会以完全相同的原因失败，
// 继续尝试只是把同一个错误重复播报十几遍。
func (s *Services) CreateTunnelsBatch(u *model.User, in CreateTunnelBatchInput) (*BatchCreateResult, error) {
	prefix := strings.TrimSpace(in.NamePrefix)
	// 前缀会拼成「前缀_端口」，所以要预留端口部分的位置。
	// 隧道名上限是 32 位，端口最多 5 位加分隔符共 6 位。
	if len(prefix) < 1 || len(prefix) > 24 || !IsSafeName(prefix) {
		return nil, fmt.Errorf("%w: 名称前缀需为 1-24 位字母、数字或下划线", ErrInvalidParam)
	}
	if strings.HasPrefix(strings.ToLower(prefix), "lt") {
		return nil, fmt.Errorf("%w: 名称前缀不能以 lt 开头", ErrInvalidParam)
	}

	ports := dedupeBatchPorts(in.Ports)
	if len(ports) == 0 {
		return nil, fmt.Errorf("%w: 请至少填写一个有效的本机端口", ErrInvalidParam)
	}
	if len(ports) > MaxBatchTunnels {
		return nil, fmt.Errorf("%w: 一次最多创建 %d 条隧道", ErrInvalidParam, MaxBatchTunnels)
	}

	res := &BatchCreateResult{
		Created:  make([]model.Tunnel, 0, len(ports)),
		Failures: make([]BatchFailure, 0),
	}

	// 整批持有该用户的锁，而不是每条各自去抢：
	// 后者会让「删除该用户」插在两条之间，剩下的隧道就建给一个已经
	// 不存在的账号了（记录与防火墙规则都留着，而账号没了）。
	lock := s.userLock(u.ID)
	lock.Lock()
	defer lock.Unlock()

	for _, port := range ports {
		// 分隔符用下划线而不是连字符：隧道名沿用 IsSafeName 的字符集
		// （字母数字下划线），连字符会被拒绝。
		name := fmt.Sprintf("%s_%d", prefix, port)

		t, err := s.createTunnelLocked(u, TunnelInput{
			Name:      name,
			Type:      in.Type,
			LocalIP:   in.LocalIP,
			LocalPort: port,
		})
		if err != nil {
			// 逐条回报失败原因，同样要把数据库原文翻译一遍：
			// 批量失败列表里出现 "UNIQUE constraint failed" 这种内容，
			// 用户既看不懂，也不知道该怎么改。
			res.Failures = append(res.Failures, BatchFailure{
				LocalPort: port,
				Name:      name,
				Reason:    describeTunnelWriteError(err).Error(),
			})
			// 上限类错误后续每一条都会重复出现，直接结束，
			// 避免把同一个原因播报二十遍。
			if errors.Is(err, ErrTunnelLimit) || errors.Is(err, ErrPortLimit) {
				break
			}
			continue
		}
		res.Created = append(res.Created, *t)
	}
	return res, nil
}

// dedupeBatchPorts 去掉重复与越界的端口，保持用户填写的顺序。
//
// 保持顺序而不是排序：用户按 25565、25566、25567 的顺序填，
// 建出来的隧道列表也应当是这个顺序，否则他会怀疑自己填错了。
func dedupeBatchPorts(in []int) []int {
	seen := make(map[int]bool, len(in))
	out := make([]int, 0, len(in))
	for _, p := range in {
		if p < 1 || p > 65535 || seen[p] {
			continue
		}
		seen[p] = true
		out = append(out, p)
	}
	return out
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

	// HTTPS 隧道与 HTTP 隧道的入口不是同一条：HTTP 走 Caddy 的 443，
	// 由 Caddy 用泛域名证书终止 TLS 后转发给 frps；HTTPS 则由 frps 在独立
	// 端口上按 SNI 透传原始 TLS 连接，证书留在本地网站——而那条入口只在
	// 端到端模式下存在。
	//
	// 不拦的话，用户会创建一个永远打不开的隧道，然后去查本地网站的配置、
	// 防火墙、证书，一路查到最后才发现是平台根本不提供这条入口。
	if ptype == model.ProxyTypeHTTPS && !s.HTTPSProxyEntryEnabled() {
		return out, ErrNoHTTPSProxyEntry
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
		//
		// 用 TunnelDomain() 而不是 Cfg.TunnelDomain：管理员在「域名与证书」
		// 里改完域名后，面板容器不会重启，照 Cfg 判权会让「新域名的子域
		// 被拒绝、旧域名的子域被放行」——而渲染出的 Caddyfile 里只有新域名。
		td := s.TunnelDomain()
		if td != "" && !strings.HasSuffix(domain, "."+td) && domain != td {
			return "", "", fmt.Errorf("%w: 仅允许使用 *.%s 下的域名", ErrDomainDenied, td)
		}
		return domain, "", nil
	}

	if s.TunnelDomain() == "" {
		return "", "", fmt.Errorf("%w: 平台未配置泛域名，暂不支持二级域名", ErrInvalidParam)
	}
	if !IsSafeName(sub) {
		return "", "", fmt.Errorf("%w: 二级域名仅允许字母、数字或下划线", ErrInvalidParam)
	}
	return "", sub, nil
}

// allocatePort 从端口池中**随机**分配一个未占用端口。
//
// 起点用随机数，而不是「按用户 ID 派生起点 + 顺序扫描」：
//
//   - 顺序分配时端口是**可预测**的。同一用户每次拿到的都是池里靠前的第一个
//     空位，连续创建几条隧道就能把用到的整段端口推出来；换端口也一样。
//     端口可预测会明显降低外部扫描/撞库的成本，而端口对外就是服务入口。
//   - 随机起点同样能避免并发碰撞：两个请求几乎不可能从同一个位置开始扫，
//     真正撞上时由下面的唯一索引兜底。
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
	offset, err := randomOffset(span)
	if err != nil {
		// 取不到随机数（几乎不可能）：退回按用户分散，至少不会让所有用户
		// 都从同一个位置开始扫。
		offset = int(userID) % span
	}
	for i := 0; i < span; i++ {
		p := start + (offset+i)%span
		if _, ok := set[p]; !ok {
			return p, nil
		}
	}
	return 0, ErrNoPortAvailable
}

// randomOffset 返回 [0, span) 内的一个随机数。
//
// 用 crypto/rand 而不是 math/rand：这里要的是「外部猜不到」，而不只是
// 「分布均匀」——math/rand 的全局序列是可预测的，知道种子就能算出下一条
// 隧道会拿到哪个端口。
func randomOffset(span int) (int, error) {
	n, err := rand.Int(rand.Reader, big.NewInt(int64(span)))
	if err != nil {
		return 0, err
	}
	return int(n.Int64()), nil
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
