package service

import (
	"github.com/xiaoxin-zk/litetunnel/server/internal/firewall"
)

// FirewallStatus 是管理页需要的防火墙运行态。
type FirewallStatus struct {
	Enabled  bool   `json:"enabled"`
	AutoOpen bool   `json:"auto_open"`
	Backend  string `json:"backend"`
	Reason   string `json:"reason,omitempty"`
	// Active 是后端报告的「防火墙是否处于启用状态」。
	Active bool `json:"active"`
	// ActiveUnknown 表示这次**没查成**，Active 不可信。
	//
	// 必须与 Active=false 区分：后者是后端明确说「没启用」，前者只是查询失败。
	// 界面把「未知」显示成「未生效」，管理员会去排查一个并不存在的问题
	// （以为是规则没生效，实际只是这次没读到）。
	ActiveUnknown bool  `json:"active_unknown"`
	Protected     []int `json:"protected_ports"`
	PoolStart     int   `json:"pool_start"`
	PoolEnd       int   `json:"pool_end"`

	// ManagedRules 是本面板专属链/表内的规则
	ManagedRules []firewall.Rule `json:"managed_rules"`
	// ExternalRules 是系统既有的规则，只读展示，避免管理员误判「没放行」
	ExternalRules []firewall.Rule `json:"external_rules"`
	// Listening 是当前主机实际监听的端口，用于识别哪些端口已被占用
	Listening []firewall.ListeningPort `json:"listening"`
	// ListeningUnknown 表示「监听端口扫描失败」，Listening 因此不完整。
	//
	// 空列表有两种含义：真的没有端口在监听，或者这次没扫成。界面把后者
	// 显示成「未扫描到监听端口」，管理员会以为主机很干净。
	ListeningUnknown bool `json:"listening_unknown"`

	// PendingOps 是「本该放行/收回、但 helper 当时失败」的端口，正在后台重试。
	//
	// 必须显示出来：这些端口对应的隧道已经建好、停用或删除，界面上一片正常，
	// 但规则并没跟着变。不暴露这个列表的话，管理员没有任何线索知道
	// 「后台说改好了，其实没改」。
	PendingOps []string `json:"pending_ops,omitempty"`

	// FailedOps 是重试已耗尽、自动处理终止的端口操作。
	//
	// 这些比 PendingOps 更要紧：后台已经彻底不管它们了——该放行的端口
	// 永远没放行（用户的隧道连不上），该收回的端口永远开着（隧道早删了、
	// 规则还在）。以前它们到上限就被删掉，只剩一行日志，界面无从知晓。
	FailedOps []FirewallFailedOp `json:"failed_ops,omitempty"`

	Error string `json:"error,omitempty"`
}

// FirewallStatusOf 采集防火墙运行态。
func (s *Services) FirewallStatusOf() *FirewallStatus {
	st := &FirewallStatus{
		Enabled:    s.Settings.Bool(KeyFirewallEnabled),
		AutoOpen:   s.Settings.Bool(KeyFirewallAutoOpen),
		Protected:  s.FirewallGuard().Protected(),
		PoolStart:  s.Cfg.PortRangeStart,
		PoolEnd:    s.Cfg.PortRangeEnd,
		PendingOps: s.PendingFirewallOps(),
		FailedOps:  s.FailedFirewallOps(),
	}

	be := s.FirewallBackend()
	st.Backend = be.Name()
	if n, ok := be.(*firewall.None); ok {
		st.Reason = n.Reason()
	}

	fillBackendState(st, be)

	if ports, err := scanListeningPorts(); err == nil {
		st.Listening = ports
	} else {
		// 扫不到不等于没有：把原因带出去，否则界面显示「0 个端口被占用」
		// 而实际只是这次没读成，管理员会据此误判端口池还很宽裕。
		st.ListeningUnknown = true
		appendFirewallStatusError(st, "读取系统监听端口失败："+err.Error())
	}
	return st
}

// fillBackendState 读后端的「生效状态」与「规则集」，查询失败如实记录。
//
// 两个查询各自独立：一个失败不该让另一个的结果也丢掉——管理员至少要知道
// 规则是能读到的，只是状态没查到（或反过来）。
func fillBackendState(st *FirewallStatus, be firewall.Backend) {
	if active, err := be.Status(); err == nil {
		st.Active = active
	} else {
		// 不能保持 Active=false 了事：那会被界面显示成「未生效」，
		// 而真实原因只是这次没查成。
		st.ActiveUnknown = true
		appendFirewallStatusError(st, "读取防火墙生效状态失败："+err.Error())
	}

	if rules, err := be.ListRules(); err == nil {
		for _, r := range rules {
			if r.Managed {
				st.ManagedRules = append(st.ManagedRules, r)
			} else {
				st.ExternalRules = append(st.ExternalRules, r)
			}
		}
	} else {
		appendFirewallStatusError(st, "读取防火墙规则失败："+err.Error())
	}
}

// appendFirewallStatusError 追加一条状态查询失败原因。
//
// 多个来源（状态、规则、监听扫描）可能同时失败，只保留最后一条会让管理员
// 按着不完整的原因去排查；分号连接之后界面上一次就能看全。
func appendFirewallStatusError(st *FirewallStatus, msg string) {
	if st.Error == "" {
		st.Error = msg
		return
	}
	st.Error += "；" + msg
}
