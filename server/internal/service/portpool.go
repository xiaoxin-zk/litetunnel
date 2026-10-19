package service

import (
	"fmt"
	"strconv"
	"strings"

	"github.com/xiaoxin-zk/litetunnel/server/internal/firewall"
	"github.com/xiaoxin-zk/litetunnel/server/internal/model"
)

type PortPoolUsage struct {
	PoolStart int `json:"pool_start"`
	PoolEnd   int `json:"pool_end"`

	Reserved         []int  `json:"reserved"`
	SystemListening  []int  `json:"system_listening"`
	Allocated        []int  `json:"allocated"`
	Free             int    `json:"free"`
	FreeUnknown      bool   `json:"free_unknown"`
	AllocatedError   string `json:"allocated_error,omitempty"`
	ListeningUnknown bool   `json:"listening_unknown"`
	ListeningError   string `json:"listening_error,omitempty"`
	Total            int    `json:"total"`

	EphemeralStart int      `json:"ephemeral_start,omitempty"`
	EphemeralEnd   int      `json:"ephemeral_end,omitempty"`
	Advice         []string `json:"advice,omitempty"`
	FirewallNeeded bool     `json:"firewall_needed"`
	FirewallNote   string   `json:"firewall_note,omitempty"`
}

func (s *Services) PortPoolUsageOf() *PortPoolUsage {
	u := &PortPoolUsage{
		PoolStart: s.Cfg.PortRangeStart,
		PoolEnd:   s.Cfg.PortRangeEnd,
	}
	if u.PoolEnd < u.PoolStart {
		return u
	}
	u.Total = u.PoolEnd - u.PoolStart + 1

	reserved := ParsePortList(s.Settings.Get(KeyPortReserved))
	for p := range reserved {
		if p >= u.PoolStart && p <= u.PoolEnd {
			u.Reserved = append(u.Reserved, p)
		}
	}

	if listening, err := listeningPortSet(); err != nil {
		u.ListeningUnknown = true
		u.ListeningError = err.Error()
	} else {
		for p := u.PoolStart; p <= u.PoolEnd; p++ {
			key := strconv.Itoa(p)
			if listening["tcp|"+key] || listening["udp|"+key] {
				u.SystemListening = append(u.SystemListening, p)
			}
		}
	}

	var used []int
	if err := s.DB.Model(&model.Tunnel{}).
		Where("remote_port > 0").Pluck("remote_port", &used).Error; err != nil {
		u.FreeUnknown = true
		u.AllocatedError = err.Error()
	} else {
		for _, p := range used {
			if p >= u.PoolStart && p <= u.PoolEnd {
				u.Allocated = append(u.Allocated, p)
			}
		}
	}

	usedSet := make(map[int]struct{}, len(u.Reserved)+len(u.SystemListening)+len(u.Allocated))
	for _, p := range u.Reserved {
		usedSet[p] = struct{}{}
	}
	for _, p := range u.SystemListening {
		usedSet[p] = struct{}{}
	}
	for _, p := range u.Allocated {
		usedSet[p] = struct{}{}
	}
	if u.FreeUnknown || u.ListeningUnknown {
		u.FreeUnknown = true
		u.Free = 0
	} else {
		u.Free = u.Total - len(usedSet)
		if u.Free < 0 {
			u.Free = 0
		}
	}

	s.diagnosePortRange(u)
	return u
}

func (s *Services) diagnosePortRange(u *PortPoolUsage) {
	if lo, hi, err := firewall.LocalPortRange(); err == nil {
		u.EphemeralStart, u.EphemeralEnd = lo, hi
		if u.PoolStart <= hi && u.PoolEnd >= lo {
			u.Advice = append(u.Advice, fmt.Sprintf(
				"端口池 %d-%d 与内核的出站端口范围 %d-%d 重叠。"+
					"这会导致 frps 偶发绑定失败（目标端口正被一条出站连接占用），"+
					"表现为随机的隧道建立失败。建议把池上限压到 %d 以下。",
				u.PoolStart, u.PoolEnd, lo, hi, lo-1))
		}
	}

	if u.FreeUnknown {
		var reasons []string
		if u.AllocatedError != "" {
			reasons = append(reasons, "读取已分配端口失败："+u.AllocatedError)
		}
		if u.ListeningError != "" {
			reasons = append(reasons, "读取系统监听端口失败："+u.ListeningError)
		}
		u.Advice = append(u.Advice, fmt.Sprintf(
			"可用端口数无法确定（%s）。请稍后刷新；"+
				"这期间「已分配 / 系统占用」列表也可能不完整。",
			strings.Join(reasons, "；")))
	} else if u.Total > 0 && u.Free*100/u.Total < 10 {
		u.Advice = append(u.Advice, fmt.Sprintf(
			"端口池仅剩 %d 个可用端口（共 %d 个），新建隧道可能因无端口可用而失败",
			u.Free, u.Total))
	}

	if s.Settings.Bool(KeyFirewallEnabled) {
		u.FirewallNeeded = true
		u.FirewallNote = "已启用：面板会通过宿主机 helper 自动放行隧道端口"
	} else {
		u.FirewallNote = "未启用。只有在主机防火墙确实会拦截隧道端口时才需要开启；" +
			"若端口放行由云安全组负责、主机上未启用防火墙，保持关闭即可——" +
			"此时没有任何规则需要面板去操作。"
	}
}
