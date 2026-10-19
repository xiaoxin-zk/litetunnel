package service

import (
	"github.com/xiaoxin-zk/litetunnel/server/internal/firewall"
)

type FirewallStatus struct {
	Enabled       bool   `json:"enabled"`
	AutoOpen      bool   `json:"auto_open"`
	AutoClose     bool   `json:"auto_close"`
	Backend       string `json:"backend"`
	Reason        string `json:"reason,omitempty"`
	Active        bool   `json:"active"`
	ActiveUnknown bool   `json:"active_unknown"`
	Protected     []int  `json:"protected_ports"`
	PoolStart     int    `json:"pool_start"`
	PoolEnd       int    `json:"pool_end"`

	ManagedRules     []firewall.Rule          `json:"managed_rules"`
	ExternalRules    []firewall.Rule          `json:"external_rules"`
	Listening        []firewall.ListeningPort `json:"listening"`
	ListeningUnknown bool                     `json:"listening_unknown"`

	PendingOps []string `json:"pending_ops,omitempty"`

	FailedOps []FirewallFailedOp `json:"failed_ops,omitempty"`

	Error string `json:"error,omitempty"`
}

func (s *Services) FirewallStatusOf() *FirewallStatus {
	st := &FirewallStatus{
		Enabled:    s.Settings.Bool(KeyFirewallEnabled),
		AutoOpen:   s.Settings.Bool(KeyFirewallAutoOpen),
		AutoClose:  s.Settings.Bool(KeyFirewallAutoClose),
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
		st.ListeningUnknown = true
		appendFirewallStatusError(st, "读取系统监听端口失败："+err.Error())
	}
	return st
}

func fillBackendState(st *FirewallStatus, be firewall.Backend) {
	if active, err := be.Status(); err == nil {
		st.Active = active
	} else {
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

func appendFirewallStatusError(st *FirewallStatus, msg string) {
	if st.Error == "" {
		st.Error = msg
		return
	}
	st.Error += "；" + msg
}
