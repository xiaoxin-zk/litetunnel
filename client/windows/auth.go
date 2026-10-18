package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"
)

type clientInfo struct {
	ServerAddr   string `json:"server_addr"`
	ServerPort   int    `json:"server_port"`
	User         string `json:"user"`
	TunnelDomain string `json:"tunnel_domain"`
}

// groupLimit 是分组对建隧道的约束，客户端据此限制表单可选项。
type groupLimit struct {
	Name              string `json:"name"`
	MaxTunnels        int    `json:"max_tunnels"`
	AllowProtocols    string `json:"allow_protocols"`
	AllowCustomDomain bool   `json:"allow_custom_domain"`
	BandwidthLimitStr string `json:"bandwidth_limit_str"`
}

type clientInfoData struct {
	clientInfo
	Username     string     `json:"username"`
	Nickname     string     `json:"nickname"`
	Tunnels      []TunnelVO `json:"tunnels"`
	TrafficUsed  int64      `json:"traffic_used"`
	TrafficQuota int64      `json:"traffic_quota"`
	Exceeded     bool       `json:"exceeded"`
	// TunnelTotal 是账号的隧道总数（不受分页影响）。
	// 新服务端才有这个字段；老服务端不返回（0），此时按「一页就是全部」处理。
	TunnelTotal int64 `json:"tunnel_total"`
	// ListVersion 是清单版本，只用来自校验分页期间清单有没有变过
	// （只比条数会漏过「删一条 + 增一条」这种数量相抵的变更）。
	ListVersion string      `json:"list_version,omitempty"`
	Group       *groupLimit `json:"group,omitempty"`
	// BalanceCents 与 PaymentEnabled 一起使用：
	// 站点未启用支付时客户端不展示任何余额相关内容。
	BalanceCents   int64 `json:"balance_cents"`
	PaymentEnabled bool  `json:"payment_enabled"`
}

// serverBase 返回本次运行使用的服务端地址：构建注入的优先。
//
// 两条来源都要过 checkServerURL，理由不同但结论一样：
//
//	注入地址：CI 里的值填成 http://IP 时，客户端必须拒绝而不是照发凭据；
//	本地保存：早期版本允许保存 http:// 公网地址，那份配置可能还在磁盘上，
//	          升级后同样要拒绝，否则明文凭据会一直发下去。
//
// 地址不可用时返回空串，由 baseReason 给出原因。
func (a *App) serverBase() string {
	if base := defaultServerURL(); base != "" {
		checked, err := checkServerURL(base, true)
		if err != nil {
			return ""
		}
		return checked
	}
	a.mu.RLock()
	raw := a.cfg.ServerURL
	a.mu.RUnlock()
	if raw == "" {
		return ""
	}
	checked, err := checkServerURL(raw, false)
	if err != nil {
		return ""
	}
	return checked
}

// baseReason 解释当前为什么没有可用的服务端地址。
//
// 不区分「还没接入」与「地址本身不可用」的话，用户看到的永远是
// 「尚未接入，请先连接」——而后者需要退出登录、重填地址才能解决，
// 照着前者的提示怎么点都没用。
func (a *App) baseReason() string {
	if base := defaultServerURL(); base != "" {
		if _, err := checkServerURL(base, true); err != nil {
			return "客户端内置的服务器地址不可用：" + err.Error()
		}
		return "尚未接入，请先连接"
	}
	a.mu.RLock()
	raw := a.cfg.ServerURL
	a.mu.RUnlock()
	if raw != "" {
		if _, err := checkServerURL(raw, false); err != nil {
			return "已保存的服务器地址不可用：" + err.Error() + "。请退出登录后重新填写"
		}
	}
	return "尚未接入，请先连接"
}

// Connect 使用 API Key 接入平台。
//
// 用户只需要粘贴一个 Key，其余全部自动完成：
//   - 服务端地址：构建时注入，不需要填；
//   - 账号信息：由服务端下发，不需要填；
//   - frpc 接入凭据：服务端生成在配置文件里，不需要填。
//
// serverURL 仅在构建未注入地址时使用（本地调试构建）。
func (a *App) Connect(apiKey, serverURL string) (State, error) {
	a.mu.RLock()
	generation := a.authGeneration
	a.mu.RUnlock()
	apiKey = strings.TrimSpace(apiKey)
	if apiKey == "" {
		return a.GetState(), errors.New("请填写 API Key")
	}

	base, err := a.resolveBase(serverURL)
	if err != nil {
		return a.GetState(), err
	}

	// 先用 info 接口验证 Key 是否有效，同时拿到账号信息与隧道清单。
	// 走分页版本：只取一页就把不完整的清单当全量，随后的对账会把
	// 后面几页的隧道当成「服务端已删除」而停掉本机进程。
	// 用应用根上下文而不是 Background：退出时这个请求要能立刻被取消，
	// 否则退出流程会卡在等这次接入校验上（最长一个同步周期）。
	ctx, cancel := context.WithTimeout(a.rootContext(), syncRoundTimeout)
	defer cancel()
	info, err := a.fetchClientInfo(ctx, base, apiKey)
	if err != nil {
		return a.GetState(), err
	}
	// 给这份快照发序号：拉取到这里之间，后台同步可能已经应用了更新的
	// 清单；随后应用旧快照会把新清单里的隧道当成已删除而停掉进程。
	seq := a.nextSyncSeq()

	username := info.Username
	if username == "" {
		username = info.Nickname
	}

	// 先落盘、成功后再发布内存状态。
	//
	// 顺序不能反：a.cfg 是后台同步读取的**共享**状态。先改内存再写盘的话，
	// 写盘失败的那一瞬间，自动同步可能已经拿着这个还没保存的 Key 拉起了
	// 隧道；回滚只恢复字段，不会停掉那些进程，而重启后凭据又不存在。
	//
	// 所以候选配置先写盘，成功了再一次性发布——「内存状态以磁盘为准」
	// 这条不变量就不需要靠回滚去补。
	// 凭据的写入与发布必须与退出登录互斥：Logout 会停进程并清空配置，
	// 若接入流程在它执行到一半时写盘、发布状态，就会出现「界面已登录、
	// 磁盘上没有凭据」的状态——重启后凭空丢号。
	//
	a.syncMu.Lock()
	defer a.syncMu.Unlock()
	a.authMu.Lock()
	defer a.authMu.Unlock()
	if err := ctx.Err(); err != nil {
		return a.GetState(), err
	}
	a.mu.RLock()
	if generation != a.authGeneration {
		a.mu.RUnlock()
		return a.GetState(), errors.New("登录状态已变化，请重新接入")
	}
	var candidate Config
	if a.cfg != nil {
		candidate = *a.cfg // 复制现有配置，避免丢掉将来新增的字段
	}
	a.mu.RUnlock()
	candidate.APIKey = apiKey
	candidate.ServerURL = base
	if err := saveConfig(&candidate); err != nil {
		a.mu.Lock()
		a.lastError = "接入信息保存失败：" + err.Error()
		a.mu.Unlock()
		return a.GetState(), err
	}

	a.mu.Lock()
	if a.cfg == nil {
		a.cfg = &Config{}
	}
	a.cfg.APIKey = apiKey
	a.cfg.ServerURL = base
	a.username = username
	a.apiKeyMask = maskKey(apiKey)
	a.gatewayHost = info.ServerAddr
	a.gatewayPort = info.ServerPort
	a.tunnelDomain = info.TunnelDomain
	a.tunnels = info.Tunnels
	a.trafficUsed = info.TrafficUsed
	a.trafficQuota = info.TrafficQuota
	a.exceeded = info.Exceeded
	a.group = info.Group
	a.paymentEnabled = info.PaymentEnabled
	a.balanceCents = info.BalanceCents
	a.lastError = ""
	if a.tunnels == nil {
		a.tunnels = []TunnelVO{}
	}
	a.authGeneration++
	a.mu.Unlock()

	// 接入之后立刻同步一次：所有「已启用」的隧道会各自拉起一个 frpc 进程。
	//
	// 客户端刻意没有「启动连接」这个步骤——用户已经明确表达过「哪些隧道
	// 要开着」（隧道自己的开关状态），再让他点一次全局按钮，只会造成
	// 「开了开关却没连上，还得再点一次」这种状态不一致。
	//
	// 直接复用上面那次 /client/info 的响应：它就是刚取回来的最新状态，
	// 再请求一次只会白等一个往返（隧道一多，这一等还要串起所有配置请求）。
	if _, err := a.syncWithDataLocked(info, seq); err != nil {
		// 同步失败不阻塞接入：凭据已经保存，界面能显示账号信息，
		// 错误通过 SyncErr 呈现，下一个自动同步周期还会重试。
		a.setSyncErr(err)
	}
	return a.GetState(), nil
}

// Logout 停止所有隧道并清除本地凭据。
//
// 两处顺序上的要求，都是为了避免「用户以为退出了、进程还在跑」：
//
//  1. 必须与同步互斥。后台同步可能正跑在对账中途，它会在本方法停掉进程
//     之后按服务端状态把隧道重新拉起来——凭据已清、进程却还在。
//  2. 必须确认进程都停了再清凭据。停止失败还照样清除登录状态的话，
//     界面上是「已退出」，而 frpc 还在后台占着端口、继续转发。
func (a *App) Logout() (State, error) {
	return a.logout(clearConfig, removeAllFrpcConfigs)
}

func (a *App) logout(clearMain, clearTunnels func() error) (State, error) {
	a.syncMu.Lock()
	defer a.syncMu.Unlock()

	if err := a.mgr.StopAll(); err != nil {
		return a.GetState(), fmt.Errorf("停止隧道失败，未退出登录: %w", err)
	}

	// 与接入流程的「写盘 + 发布」互斥（见 Connect）：否则清空凭据与
	// 发布新凭据可能交错，出现界面已登录而磁盘上什么都没有的状态。
	a.authMu.Lock()
	defer a.authMu.Unlock()
	a.mu.Lock()
	a.authGeneration++
	a.cfg.APIKey = ""
	a.cfg.ServerURL = ""
	a.resetPerAccountState()
	a.mu.Unlock()

	// 日志缓冲属于「旧账号的历史」，也必须清掉：否则换账号后界面上会先冒出一段
	// 上一个账号的日志。单独在 a.mu 之外清——ClearLogs 自己拿 logMu。
	a.ClearLogs()

	// 磁盘上**所有**含凭据的文件都要清掉，不只是主配置。
	//
	// 每条隧道的 frpc.toml 里同样是凭据（客户端接入密钥 + frps 全局 token），
	// 只删 config.json 等于「退出了但钥匙还留在磁盘上」——换个账号登录后，
	// 上一个账号的接入密钥仍然可以被读出来使用。
	// 两处都要尝试，最后汇总错误。
	//
	// 不能一处失败就返回：主配置与隧道配置是两份独立的凭据（API Key vs
	// 接入密钥），一处删不掉不该让另一处也留着——能清掉一个是一个。
	cfgErr := clearMain()
	frpcErr := clearTunnels()

	if cfgErr != nil || frpcErr != nil {
		// 内存里的凭据已经清了，但磁盘上还有残留——下次启动可能重新读到它。
		// 这必须让用户知道，所以照样推状态、并把错误抛出去。
		a.emitState()
		switch {
		case cfgErr != nil && frpcErr != nil:
			return a.GetState(), fmt.Errorf("已退出，但本地凭据清理失败：主配置 %v；隧道配置 %v", cfgErr, frpcErr)
		case cfgErr != nil:
			return a.GetState(), fmt.Errorf("已退出，但本地主配置删除失败: %w", cfgErr)
		default:
			return a.GetState(), fmt.Errorf("已退出，但隧道配置文件删除失败（其中含接入密钥）: %w", frpcErr)
		}
	}
	return a.GetState(), nil
}

// resetPerAccountState 清空一切账号派生状态。
//
// 调用方必须已持有 a.mu。
//
// 退出登录后这些字段若不清空，换账号接入（或新账号复用了旧账号的隧道 id）时，
// 会短暂显示旧账号的连接状态、错误与提示：
//   - registered / registeredAt：让新账号的隧道被标成「运行中」；
//   - tunnelErrs / errEmitAt：界面显示旧账号的失败原因与限频残留；
//   - cleanupWarned / cfgRev：指向已经不存在的配置与清理提示；
//   - retries / connectAt：让新隧道多等一段退避，或显示不属于它的等待时长。
//
// 日志缓冲不在这里清：它由 logMu 保护，这里已持有 a.mu，再拿 logMu 会引入
// 锁序；由 logout 在 a.mu 之外调 ClearLogs 单独清。
func (a *App) resetPerAccountState() {
	a.username = ""
	a.apiKeyMask = ""
	a.tunnels = nil
	a.gatewayHost = ""
	a.gatewayPort = 0
	a.tunnelDomain = ""
	a.trafficUsed = 0
	a.trafficQuota = 0
	a.exceeded = false
	a.group = nil
	a.paymentEnabled = false
	a.balanceCents = 0

	a.applied = map[uint]string{}
	a.cfgRev = map[uint]string{}
	a.tunnelErrs = map[uint]tunnelErr{}
	a.retries = map[uint]*retryState{}
	a.registered = map[uint]bool{}
	a.registeredAt = map[uint]time.Time{}
	a.connectAt = map[uint]time.Time{}
	a.errEmitAt = map[uint]time.Time{}
	a.cleanupWarned = map[uint]bool{}
}

// currentCredential 返回当前接入用的长期凭据。
//
// 抽成一个方法而不是各处直接读 a.cfg.APIKey，是为了让加锁这件事
// 只发生在一个地方——这类字段被多处并发读写时最容易漏锁。
func (a *App) currentCredential() (base, apiKey string, err error) {
	base = a.serverBase()
	a.mu.RLock()
	apiKey = a.cfg.APIKey
	a.mu.RUnlock()
	if base == "" || apiKey == "" {
		return "", "", errors.New(a.baseReason())
	}
	return base, apiKey, nil
}

// ServerMailEnabled 查询服务端是否启用了邮件功能。
//
// 客户端据此决定重置密码走哪条路：启用邮件就用邮箱验证码，
// 未启用就用「当前密码 + 新密码」。这一步必须先问服务端，
// 而不是在客户端写死——否则服务端配置一变，客户端就失效了。
func (a *App) ServerMailEnabled(serverURL string) (bool, error) {
	base, err := a.resolveBase(serverURL)
	if err != nil {
		return false, err
	}
	var out struct {
		MailEnabled bool `json:"mail_enabled"`
	}
	// 未登录的公开请求同样走根上下文：应用退出时能被取消，而不是一直等到
	// http.Client 的 15 秒超时。
	if err := a.getJSON(a.rootContext(), base+"/api/public/settings", "", &out); err != nil {
		return false, err
	}
	return out.MailEnabled, nil
}

// SendEmailCode 请求服务端发送邮箱一次性验证码。scene 为 register 或 reset。
func (a *App) SendEmailCode(serverURL, email, scene string) error {
	base, err := a.resolveBase(serverURL)
	if err != nil {
		return err
	}
	payload, err := json.Marshal(map[string]string{"email": email, "scene": scene})
	if err != nil {
		return err
	}
	_, err = a.do(a.rootContext(), http.MethodPost, base+"/api/user/auth/send-email-code", "", payload)
	return err
}

// ResetPassword 重置账号密码。
//
// 两种材料一起提交，由服务端按自身配置选择校验方式：
//   - 启用邮件 → 校验 email_code
//   - 未启用邮件 → 校验 old_password
//
// 客户端不自己判断走哪条路，是为了避免两边规则不一致导致
// 「客户端以为该用验证码、服务端却在等旧密码」这类错配。
func (a *App) ResetPassword(serverURL, account, oldPassword, emailCode, newPassword string) error {
	base, err := a.resolveBase(serverURL)
	if err != nil {
		return err
	}
	payload, err := json.Marshal(map[string]string{
		"account":      account,
		"old_password": oldPassword,
		"email_code":   emailCode,
		"password":     newPassword,
	})
	if err != nil {
		return err
	}
	_, err = a.do(a.rootContext(), http.MethodPost, base+"/api/user/auth/reset-password", "", payload)
	return err
}
