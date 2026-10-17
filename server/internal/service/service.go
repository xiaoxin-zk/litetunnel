// Package service 承载控制面的全部业务逻辑。
//
// 设计要点：
//   - 权限与配额只在服务端计算，客户端提交的任何额度声明都不被信任；
//   - 所有对外返回的用户对象都不包含口令与密钥哈希（模型已用 json:"-" 保证）。
package service

import (
	"context"
	"errors"
	"fmt"
	"log"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"gorm.io/gorm"

	"github.com/xiaoxin-zk/litetunnel/server/internal/config"
	"github.com/xiaoxin-zk/litetunnel/server/internal/mailer"
	"github.com/xiaoxin-zk/litetunnel/server/internal/middleware"
	"github.com/xiaoxin-zk/litetunnel/server/internal/model"
	"github.com/xiaoxin-zk/litetunnel/server/internal/monitor"
)

// 登录取证用的一组常量：合并入口采用最严的一档（无法预判提交的是用户还是
// 管理员账号），并对所有校验密码的入口共用同一份计数。
const (
	loginLockThreshold = 3
	loginLockBase      = 30 * time.Minute
	loginLockMax       = 24 * time.Hour
)

// 业务错误。处理器统一映射为 HTTP 状态码。
var (
	ErrNotFound        = errors.New("资源不存在")
	ErrBadCredentials  = errors.New("用户名或密码错误")
	ErrUsernameTaken   = errors.New("该用户名已被占用")
	ErrAccountDisabled = errors.New("账号已被禁用，请联系管理员")
	ErrQuotaExceeded   = errors.New("流量额度已用尽，请兑换或联系管理员")
	ErrTunnelLimit     = errors.New("已达到当前分组的隧道数量上限")
	ErrPortLimit       = errors.New("已达到当前分组的端口数量上限")
	ErrNoPortAvailable = errors.New("端口池已耗尽，请稍后重试")
	ErrPortInUse       = errors.New("该远程端口已被占用")
	ErrProtocolDenied  = errors.New("当前分组不允许使用该协议")
	ErrDomainDenied    = errors.New("当前分组不允许使用自定义域名")
	ErrCodeInvalid     = errors.New("兑换码无效")
	ErrCodeUsed        = errors.New("兑换码已被使用")
	ErrCodeExpired     = errors.New("兑换码已过期")
	ErrCodeDisabled    = errors.New("兑换码已被禁用")
	ErrInvalidParam    = errors.New("参数不合法")

	// ErrMembershipExpired 表示账号当前的分组有效期已过，需要先续期。
	//
	// 单独一个哨兵而不是普通 error：它要映射成 4xx（用户可自行解决），
	// 掉进默认分支就变成 500「服务内部错误」，用户以为系统坏了。
	ErrMembershipExpired = errors.New("当前分组有效期已过期")

	// ErrTOTPRequired 表示账号已启用双因素认证但本次未提交动态口令。
	// 与 ErrTOTPInvalid 区分开：前者只是没填，不应计入暴力破解次数。
	ErrTOTPRequired = errors.New("该账号已启用双因素认证，请输入动态口令")
	ErrTOTPInvalid  = errors.New("动态口令不正确")
	// ErrTOTPReplay 表示该动态口令在有效窗口内已被使用过。
	// 正常用户不会碰到（认证器每 30 秒换一个码），出现即意味着有人在重放。
	ErrTOTPReplay = errors.New("该动态口令已被使用过，请等待认证器刷新后重试")

	// 注册准入相关
	ErrRegisterClosed  = errors.New("本站已关闭注册，请联系管理员开通账号")
	ErrCaptchaInvalid  = errors.New("验证码不正确或已过期，请重新获取")
	ErrRegisterLimited = errors.New("当前网络注册过于频繁，请稍后再试")
	ErrEmailNotAllowed = errors.New("该邮箱域名不允许注册")
	// ErrDomainNotTrusted 表示站点开启了「仅白名单域名可注册」。
	ErrDomainNotTrusted = errors.New("本站当前仅允许白名单内的邮箱域名注册")
	// ErrDomainRegisterLimited 表示该邮箱域名当日注册量已达上限。
	ErrDomainRegisterLimited = errors.New("该邮箱域名今日注册数量已达上限，请改用其他邮箱或明日再试")
	ErrEmailCodeNeeded       = errors.New("请输入邮箱验证码")
	ErrEmailCodeWrong        = errors.New("邮箱验证码不正确或已过期")
	// ErrEmailCodeCheckFailed 表示校验本身没法完成（例如失败次数写不进库）。
	//
	// 必须与 ErrEmailCodeWrong 分开：后者是「你填错了」，前者是「我们这边暂时
	// 处理不了」。混为一谈的后果不只是提示不准——失败次数记不上的话，
	// 猜测次数上限就形同不存在，攻击者可以无限试。
	ErrEmailCodeCheckFailed = errors.New("验证码校验暂时不可用，请稍后重试")

	// 邮箱验证码相关
	ErrEmailRequired     = errors.New("请填写有效的邮箱地址")
	ErrEmailTaken        = errors.New("该邮箱已被其他账号使用")
	ErrEmailCodeTooSoon  = errors.New("验证码发送过于频繁，请稍后再试")
	ErrEmailCodeTooMany  = errors.New("该邮箱今日验证码发送次数已达上限，请明日再试")
	ErrEmailCodeAttempts = errors.New("验证码错误次数过多，请重新获取")
)

// Services 业务服务集合。
type Services struct {
	DB      *gorm.DB
	Cfg     *config.Config
	Frps    *FrpsClient
	Runtime *Runtime

	// Settings 是管理端可随时调整的运行期配置（SMTP、注册开关、支付、端口策略）。
	// 与 Cfg 的分工见 setting.go 的注释。
	Settings *SettingStore

	// Captchas 是内存中的一次性验证码存储。
	Captchas *CaptchaStore

	// LoginGuard 是**全站唯一**一份「账号 + 来源 IP」登录失败计数。
	//
	// 为什么必须唯一：每个入口各自 new 一个锁，就等于给攻击者多一份额度——
	// 在 A 入口撞 3 次、B 入口再撞 3 次，两边都不会触发锁定，而账号级
	// 验证码要求又只在各自入口里检查。放进 Services 是为了让「只有一份」
	// 成为结构上的事实：新加入口时能拿到的东西只有这一个，写不出第二份。
	LoginGuard *middleware.LoginGuard

	// TOTPReplay 记录已用过的动态口令步进码，阻止窗口内重放。
	// 动态口令的防重放记录在管理员表上（totp_last_step），不在这里：
	// 内存记录重启即丢，而口令的有效窗口还在。

	// Monitor 采集宿主机与面板自身的运行指标。
	//
	// 数据存在内存环形缓冲里，**不落库**——时间序列是最容易「不修就会在
	// 某天出事」的组件（1Panel 的运维监控就曾因数据量无限增长而拖慢面板，
	// 官方后来专门发了清理工具）。环形缓冲天然有界，从第一天起就不存在
	// 增长问题：采样点满了就覆盖最旧的一条，磁盘占用恒为零。
	Monitor *monitor.Collector

	// loginLogCh 是登录日志的异步队列：
	// 登录日志不能阻塞登录判定。
	loginLogCh chan model.LoginLog

	// loginFails 是账号级登录失败计数，**专供验证码判定**。
	//
	// 与上面那条队列刻意分开：队列满了会丢弃（写日志不能拖住登录判定），
	// 而「要不要出验证码」是认证门槛，数据源不能是可丢弃的。
	// 缘由见 loginfail.go。
	loginFails *loginFailureCounter

	// mailWake 用于唤醒发信协程（邮件本身存在发件箱表里，不走内存队列：
	// 内存队列重启即丢，而验证码/重置链接一旦丢了，用户就找不回账号）。
	mailWake chan struct{}
	// mailerOverride 仅供测试注入发信替身，非 nil 时优先于真实 SMTP 配置。
	mailerOverride mailSender

	// fwMu 保护 fwPending：本该放行/收回、但宿主机 helper 当时失败的端口。
	//
	// 为什么需要它：隧道建好/停用/删除时数据库已经改了，而防火墙操作可能
	// 因为 helper 暂时不可达而失败。以前这个失败只写一行日志就没了——
	// 接口返回成功，规则却没变；而启动时的规则对齐只补开、不收回，
	// 放行失败更是没有任何地方会再尝试。
	fwMu      sync.Mutex
	fwPending map[int]pendingFW

	// userLocks 按用户分片，串行化「建隧道」与「删除用户」（见 userLock）。
	userLocks [userLockShards]sync.Mutex

	// portLocks 按端口分片，串行化「端口归属发生变化」与「重试关闭该端口」。
	//
	// 防的是这个交错：重试任务查到「该端口没有活跃隧道」（此时创建事务还没
	// 提交）→ 创建事务提交并放行 → 重试任务把它关掉。两边都持有同一把端口锁
	// 之后，只可能是先后关系（见 portLock）。
	portLocks [portLockShards]sync.Mutex

	// adminMu 串行化「涉及超级管理员数量」的变更（改角色/状态、删除）。
	//
	// 光有事务不够：UpdateAdmin / DeleteAdmin 都是「先数一数、再改」，两个请求
	// （例如两名超级管理员并发互相降级）可能在各自的事务里都读到「还有对方在」，
	// 然后各自提交，最终一个可用的超级管理员都不剩——那是谁都进不去后台的死锁，
	// 只能改数据库才能恢复。控制面是单进程，进程内互斥就能把这组操作串行化，
	// 事务再保证「检查 + 变更」对其它写路径原子。
	adminMu sync.Mutex

	// domainMu 串行化「域名与证书」的完整应用流程（见 ApplyDomainConfig），
	// 并让「保存这一组设置」与「应用」互斥。
	//
	// 不锁会发生两种交错，两种都把「已生效」记录写成与宿主机不符的样子：
	//
	//   - 两个管理员同时点「保存并应用」：A 读到旧配置、B 读到新配置，
	//     helper 那边虽然每次都是原子的，但两次下发的先后由谁先到锁决定。
	//     A 后到时，宿主机上跑回了旧配置，而 A 随后把「已生效」标记成旧配置——
	//     与磁盘一致，但 B 那份新配置丢了；两份各自标记「已生效」的记录
	//     还可能互相覆盖出「记录是新的、磁盘是旧的」。
	//   - 应用过程中途保存：DomainConfigVars 是逐个 key 读设置，读一半被插进
	//     一次保存，就会拿到「面板域名是新值、隧道域名是旧值」这种从未在
	//     任何一次保存里存在过的组合，并且原样下发、原样记为已生效。
	//
	// 保存端只在**这次提交确实改了这一组**时才取锁（见 UpdateSettings），
	// 改 SMTP、改公告之类的普通保存不必排在一次可能持续数分钟的下发后面。
	domainMu sync.Mutex

	// fwKick 用于在设置里打开防火墙时**立刻**触发一次对齐与重试，
	// 而不是等下一个轮询周期。
	fwKick chan struct{}

	// guardFullAt 是上一次**全量**准入标记校准的时刻（UnixNano）。
	//
	// 常规采集轮次只刷新「本轮有流量」与「计费周期到期」的用户，
	// 全量校准低频执行（见 refreshGuardDue）。
	// 用原子变量而不是普通字段：写入在采集协程，读取可能来自启动路径。
	guardFullAt atomic.Int64
}

// portLockShards 是端口锁的分片数。
//
// 分片而不是给每个端口一把锁：固定 64 把没有清理问题，碰撞只是让两个端口
// 的操作多串行化一点，而这类操作本身很稀疏。
const portLockShards = 64

// portLock 返回某个端口的锁。
//
// 覆盖三段临界区，缺一段窗口就还在：
//   - 建隧道：取锁、**再开事务**，持有到端口放行完成；
//   - 启停隧道：取锁后执行放行/收回；
//   - 待办重试：取锁后再校验意图并执行。
//
// 锁序固定为「用户锁 → 端口锁 → 数据库事务」：
//   - 建隧道与删用户两条路径都按「用户锁 → 端口锁」取；
//   - 端口锁一律在数据库事务**之前**取。反过来的话，SQLite（单连接）
//     上「持有事务连接等端口锁」与「持有端口锁等连接」会互相等死，
//     见 createTunnelLocked 开头的说明。
//
// 不存在反向获取，因此不会死锁。
func (s *Services) portLock(port int) *sync.Mutex {
	if port < 0 {
		port = -port
	}
	return &s.portLocks[port%portLockShards]
}

// KickFirewall 请求立刻做一次防火墙对齐与待办重试。
//
// 非阻塞：调用方是设置更新这类请求路径，不该因为后台协程正忙而卡住。
func (s *Services) KickFirewall() {
	if s.fwKick == nil {
		return
	}
	select {
	case s.fwKick <- struct{}{}:
	default:
		// 已有待处理的触发，合并成一次即可。
	}
}

// userLockShards 是用户锁的分片数。
//
// 分片而不是给每个用户建一把锁（配 map + 清理）：固定 64 把不会有
// 「锁表随用户数增长」的问题，碰撞只是让两个用户的操作多串行化一点，
// 而这两件事本来就不频繁。
const userLockShards = 64

// userLock 返回某个用户的锁。
//
// 用途只有一个：串行化「给该用户建隧道」与「删除该用户」。
// 删除流程要先读端口清单、再删记录，中间若插进一条并发创建的隧道，
// 它会被删掉而端口不在回收清单里——防火墙规则永久残留，且没有任何
// 地方会再尝试清理（启动时的规则对齐只补开、不收回）。
func (s *Services) userLock(userID uint) *sync.Mutex {
	return &s.userLocks[userID%userLockShards]
}

// New 构造服务集合。
func New(db *gorm.DB, cfg *config.Config) *Services {
	return &Services{
		DB:         db,
		Cfg:        cfg,
		Frps:       NewFrpsClient(cfg),
		Runtime:    NewRuntime(),
		Settings:   NewSettingStore(db, cfg),
		Captchas:   NewCaptchaStore(),
		LoginGuard: middleware.NewLoginGuard(loginLockThreshold, loginLockBase, loginLockMax),

		Monitor:    monitor.New(cfg.MonitorDiskPath),
		loginLogCh: make(chan model.LoginLog, loginLogBuffer),
		loginFails: newLoginFailureCounter(),
		mailWake:   make(chan struct{}, 1),
		fwPending:  map[int]pendingFW{},
		fwKick:     make(chan struct{}, 1),
	}
}

// mailSender 是发信器的最小接口，便于测试注入替身。
//
// ctx 携带发送总预算：拨号与会话读写都要服从同一个截止，否则队列
// 判超时之后邮件仍可能送达（见 mailSendTimeout 的说明）。
type mailSender interface {
	Send(ctx context.Context, to, subject, body string) error
}

// mailSender 返回实际用于发信的对象。
func (s *Services) mailSender() mailSender {
	if s.mailerOverride != nil {
		return s.mailerOverride
	}
	return s.Mailer()
}

// SMTPConfig 按当前运行期配置组装邮件参数。
//
// 邮件配置可在管理端随时修改，因此每次都重新组装而不是启动时固定。
func (s *Services) SMTPConfig() config.SMTPConfig {
	return config.SMTPConfig{
		Host:     strings.TrimSpace(s.Settings.Get(KeySMTPHost)),
		Port:     s.Settings.Int(KeySMTPPort),
		User:     strings.TrimSpace(s.Settings.Get(KeySMTPUser)),
		Password: s.Settings.Get(KeySMTPPassword),
		From:     strings.TrimSpace(s.Settings.Get(KeySMTPFrom)),
		TLS:      strings.ToLower(strings.TrimSpace(s.Settings.Get(KeySMTPTLS))),
		SiteName: s.Settings.Get(KeySiteName),
	}
}

// Mailer 按当前配置构造发信器。
func (s *Services) Mailer() *mailer.Mailer { return mailer.New(s.SMTPConfig()) }

// MailEnabled 返回当前是否启用了邮件发送。
//
// 需要同时满足「管理端开关打开」与「参数齐全」两个条件：
// 只填了参数但开关没开，不应静默发信。
func (s *Services) MailEnabled() bool {
	if !s.Settings.Bool(KeySMTPEnabled) {
		return false
	}
	return s.SMTPConfig().Enabled()
}

// EffectiveGroup 返回用户当前生效的分组。
// 分组已过期或未绑定时，回落到系统默认分组，避免出现无限制的越权状态。
func (s *Services) EffectiveGroup(u *model.User) *model.Group {
	if u == nil {
		return nil
	}
	if u.GroupExpireAt != nil && u.GroupExpireAt.Before(time.Now()) {
		return s.defaultGroup()
	}
	if u.Group != nil {
		return u.Group
	}
	return s.defaultGroup()
}

// EffectiveBandwidth 返回用户在**当前**分组下实际生效的单隧道限速。
//
// # 为什么以分组为准，而不是读隧道上存的那份快照
//
// Tunnel.BandwidthLimit 是建隧道时从分组复制的。改分组后靠两处传播逻辑
// （AdminSetUserGroup / UpdateGroup）去刷新它——但「同一件事存在两份数据」
// 本身就是缺陷来源：任何一条没覆盖到的路径都会让显示与实际不一致，
// 而这类不一致只会以「数字对不上」的形式暴露，永远不报错。
//
// 已经能指出至少一条漏网路径：分组**过期**的用户会被 EffectiveGroup
// 回落到默认分组，而传播逻辑只按 group_id 匹配，刷新不到这些人。
//
// 所以这里统一以分组为唯一真相来源。隧道表里那一列保留仅为兼容历史数据，
// 不再作为判断依据。
func (s *Services) EffectiveBandwidth(u *model.User) int64 {
	if g := s.EffectiveGroup(u); g != nil {
		return g.BandwidthLimit
	}
	return 0
}

func (s *Services) defaultGroup() *model.Group {
	var g model.Group
	if err := s.DB.Where("is_default = ?", true).First(&g).Error; err != nil {
		return nil
	}
	return &g
}

// EffectiveQuota 返回用户本计费周期的流量配额（字节）。0 表示不限。
func (s *Services) EffectiveQuota(u *model.User) int64 {
	if u.TrafficQuota > 0 {
		return u.TrafficQuota
	}
	if g := s.EffectiveGroup(u); g != nil {
		return g.TrafficQuota
	}
	return 0
}

// QuotaExceeded 判断用户是否已超额。
func (s *Services) QuotaExceeded(u *model.User) bool {
	q := s.EffectiveQuota(u)
	return q > 0 && u.TrafficUsed >= q
}

// EnsureTrafficPeriod 在跨计费周期时重置已用流量。
// 采用惰性重置，避免额外的定时任务。
//
// # 与流量采集的协调
//
// 重置写的是绝对值（traffic_used = 0），采集写的是增量（+delta）：
//
//   - 采集的增量在重置提交**之前**落库 → 随重置一起清零。正确：
//     那部分流量属于旧周期；
//   - 增量在重置提交**之后**落库 → 保留。基本正确：采集一轮最长
//     TrafficPollInterval，跨重置时刻的那一轮会把少量旧周期流量算进
//     新周期，这是一个采样周期的固有粒度，且只多不少地偏向用户。
//
// 采集协程里的顺序是「先落增量、后刷新配额标记（内含本函数）」，
// 重置天然发生在增量边界之后，不会把同一轮增量算两遍。
//
// # 为什么必须检查写库结果
//
// 以前在写库**之前**就把内存对象的用量清零、并忽略写库错误：写失败时
// 配额刷新照样按「零用量」更新拦截标记，超额用户被错误放行，要等下一轮
// 采集才纠正。现在只有数据库确认成功才改内存；条件更新没命中（reset_at
// 已被并发改动）时重读最终状态，绝不拿过时快照当事实。
func (s *Services) EnsureTrafficPeriod(u *model.User) {
	if u == nil || u.ID == 0 {
		return
	}
	now := time.Now()
	if u.TrafficResetAt.IsZero() {
		// 初始化周期起点：没有用量要清，两个并发方同时写也只是起点
		// 相差几毫秒，无碍。
		next := now.AddDate(0, 1, 0)
		res := s.DB.Model(&model.User{}).Where("id = ?", u.ID).
			Update("traffic_reset_at", next)
		if res.Error != nil {
			log.Printf("[quota] 初始化流量周期失败（用户 %d），下轮重试: %v", u.ID, res.Error)
			return
		}
		u.TrafficResetAt = next
		return
	}
	if now.Before(u.TrafficResetAt) {
		return
	}
	// 周期结束：重置已用量并顺延到下一个周期。
	next := u.TrafficResetAt
	for !next.After(now) {
		next = next.AddDate(0, 1, 0)
	}
	// 条件更新：reset_at 与读到的一致才动手。别的路径（管理员清零、
	// 并发的另一处重置）改过 reset_at 时本方放弃，避免用过时快照覆盖。
	res := s.DB.Model(&model.User{}).
		Where("id = ? AND traffic_reset_at = ?", u.ID, u.TrafficResetAt).
		Updates(map[string]any{
			"traffic_used":     0,
			"traffic_reset_at": next,
		})
	if res.Error != nil {
		log.Printf("[quota] 流量周期重置失败（用户 %d），保持原状态下轮重试: %v", u.ID, res.Error)
		return
	}
	if res.RowsAffected == 0 {
		// 已被并发方重置或 reset_at 被改动：内存快照过时，重读最终状态。
		// 必须 Preload("Group")：调用方（如 refreshQuotaFlags）拿着这个
		// 对象继续算 EffectiveGroup/QuotaExceeded，整体覆盖掉原来的
		// 分组关联会让配额回落到默认分组——该轮标记就算错了。
		var fresh model.User
		if err := s.DB.Preload("Group").First(&fresh, u.ID).Error; err == nil {
			*u = fresh
		}
		return
	}
	u.TrafficUsed = 0
	u.TrafficResetAt = next
}

// ResolveCredential 把长期凭据解析为身份，供桌面客户端使用。
//
// 依次尝试 API Key（SHA-256 摘要比对）与客户端接入凭据（常量时间比对）。
// 两者都可独立吊销，因此客户端无需在本地保存账号密码。
func (s *Services) ResolveCredential(plain string) (uint, string, error) {
	if plain == "" {
		return 0, "", ErrNotFound
	}
	if u, err := s.LoadUserByAPIKey(plain); err == nil {
		return u.ID, u.Username, nil
	}
	if u, err := s.LoadUserByClientSecret(plain); err == nil {
		return u.ID, u.Username, nil
	}
	return 0, "", ErrNotFound
}

// ResolveUserIdentity 返回用户的实时状态：是否有效 + 当前令牌版本。
//
// 用于每次请求时校验令牌持有者：仅验签无法发现账号已被禁用，
// 也无法发现密码已被重置（此时令牌版本自增，旧令牌必须失效）。
func (s *Services) ResolveUserIdentity(id uint) (active bool, tokenVersion int) {
	for attempt := 0; attempt < 2; attempt++ {
		if a, v, ok := s.Runtime.CachedIdentity(IdentityKindUser, id); ok {
			return a, v
		}
		// 读库前取代次：回填时要确认期间没有发生失效（禁用/删号/改密）。
		gen := s.Runtime.IdentityGen(IdentityKindUser, id)
		u, err := s.LoadUser(id)
		if err != nil {
			if s.Runtime.SetCachedIdentityIfGen(IdentityKindUser, id, false, 0, gen) {
				return false, 0
			}
			continue
		}
		a := u.Status == model.UserStatusActive
		if s.Runtime.SetCachedIdentityIfGen(IdentityKindUser, id, a, u.TokenVersion, gen) {
			return a, u.TokenVersion
		}
		// 期间被失效：这次读到的可能是旧状态，重读一次再判断。
	}
	// 连续两轮都被失效打断（极罕见）：保守按无效处理，下一次请求重新解析。
	return false, 0
}

// ResolveAdminIdentity 返回管理员的实时状态。
func (s *Services) ResolveAdminIdentity(id uint) (active bool, tokenVersion int) {
	for attempt := 0; attempt < 2; attempt++ {
		if a, v, ok := s.Runtime.CachedIdentity(IdentityKindAdmin, id); ok {
			return a, v
		}
		gen := s.Runtime.IdentityGen(IdentityKindAdmin, id)
		adm, err := s.LoadAdmin(id)
		if err != nil {
			if s.Runtime.SetCachedIdentityIfGen(IdentityKindAdmin, id, false, 0, gen) {
				return false, 0
			}
			continue
		}
		a := adm.Status == "active"
		if s.Runtime.SetCachedIdentityIfGen(IdentityKindAdmin, id, a, adm.TokenVersion, gen) {
			return a, adm.TokenVersion
		}
	}
	return false, 0
}

// AllowedProtocols 解析分组允许的协议集合。
func AllowedProtocols(g *model.Group) map[string]bool {
	out := map[string]bool{}
	if g == nil {
		return out
	}
	for _, p := range strings.Split(g.AllowProtocols, ",") {
		p = strings.ToLower(strings.TrimSpace(p))
		if p != "" {
			out[p] = true
		}
	}
	return out
}

// FormatBandwidthHuman 把 bit/s 限速转成给人看的形式。
//
// 与 FormatBandwidth 的分工必须分清楚，两者不可混用：
//
//   - FormatBandwidth  产出**写给 frp 的配置值**：字节/秒 + KB/MB 后缀
//   - FormatBandwidthHuman 产出**显示给用户的文案**：bit/s + Mbps/Kbps
//
// 之前用户控制台直接复用了前者，结果是管理员在后台填「4 Mbps」、
// 用户在控制台看到「512.00KB」——明明是同一个值，但一个是 bit 口径、
// 一个是 byte 口径，用户只会以为自己被少给了带宽。
//
// 进制用 1024 而不是 1000：必须与后台分组表单的换算保持一致
// （表单是 bandwidth_limit / 1024 / 1024），否则同一个限速在
// 两处会显示成不同的数字，反而制造新的困惑。
func FormatBandwidthHuman(bitsPerSec int64) string {
	if bitsPerSec <= 0 {
		return ""
	}
	const (
		k = 1024.0
		m = 1024.0 * 1024.0
	)
	b := float64(bitsPerSec)
	switch {
	case b >= m:
		// 用 -1 精度输出最短表示：4 就显示 "4"，2.5 就显示 "2.5"。
		return strconv.FormatFloat(b/m, 'f', -1, 64) + " Mbps"
	case b >= k:
		return strconv.FormatFloat(b/k, 'f', -1, 64) + " Kbps"
	default:
		return strconv.FormatInt(bitsPerSec, 10) + " bps"
	}
}

// FormatBandwidth 将 bit/s 转为 frp 可识别的限速字符串。
//
// 注意：frp 的 BandwidthQuantity 仅接受 "MB" 与 "KB" 后缀，
// 且语义为「字节/秒」。因此这里必须先除以 8 再格式化。
//
// 这个函数的输出会直接写进 frpc.toml，不要用它做界面展示——
// 展示请用 FormatBandwidthHuman。
func FormatBandwidth(bitsPerSec int64) string {
	if bitsPerSec <= 0 {
		return ""
	}
	bytesPerSec := float64(bitsPerSec) / 8.0
	const (
		kb = 1024.0
		mb = 1024.0 * 1024.0
	)
	if bytesPerSec >= mb {
		return strconv.FormatFloat(bytesPerSec/mb, 'f', 2, 64) + "MB"
	}
	if bytesPerSec < kb {
		// 低于 1KB/s 的限速在 frp 侧无意义，统一抬到 1KB/s，避免解析为 0（不限速）。
		return "1.00KB"
	}
	return strconv.FormatFloat(bytesPerSec/kb, 'f', 2, 64) + "KB"
}

// FormatBytes 人类可读的流量体积。
func FormatBytes(b int64) string {
	const unit = 1024
	if b < unit {
		return fmt.Sprintf("%d B", b)
	}
	units := []string{"KB", "MB", "GB", "TB", "PB"}
	div, exp := int64(unit), 0
	for n := b / unit; n >= unit && exp < len(units)-1; n /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.2f %s", float64(b)/float64(div), units[exp])
}
