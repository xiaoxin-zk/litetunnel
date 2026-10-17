package service

import (
	"fmt"
	"strconv"
	"strings"

	"github.com/xiaoxin-zk/litetunnel/server/internal/firewall"
	"github.com/xiaoxin-zk/litetunnel/server/internal/model"
)

// PortPoolUsage 描述端口池的使用情况，供管理页做可视化。
type PortPoolUsage struct {
	PoolStart int `json:"pool_start"`
	PoolEnd   int `json:"pool_end"`

	// Reserved 是管理端配置的保留端口（不分配）
	Reserved []int `json:"reserved"`
	// SystemListening 是系统实际占用且在端口池范围内的端口
	SystemListening []int `json:"system_listening"`
	// Allocated 是已分配给用户隧道的端口
	Allocated []int `json:"allocated"`
	// Free 是仍可分配的端口数量；FreeUnknown 为 true 时它没有意义。
	Free int `json:"free"`
	// FreeUnknown 表示「已分配端口读不出来」，空闲量因此无法计算。
	//
	// 读库失败时若仍然按「保留 + 系统占用」算一个数出来，管理页会显示一个
	// 明显偏高的可用量（把已经分配给用户的端口也算成空闲），甚至与「端口
	// 已经用完」的事实相反——比不显示更糟。此时 Free 置 0 并由这个标记
	// 表明「未知」，界面据此显示「未知」而不是 0。
	FreeUnknown bool `json:"free_unknown"`
	// AllocatedError 是读取已分配端口失败的原因（仅 FreeUnknown 时非空）。
	AllocatedError string `json:"allocated_error,omitempty"`
	// ListeningUnknown 表示「系统监听端口扫描失败」，系统占用列表因此不完整。
	//
	// 与 AllocatedError 同样必须标出来：少算系统占用会让空闲量偏高，
	// 而管理员可能据此把端口池调小、或误以为还有余量。
	ListeningUnknown bool `json:"listening_unknown"`
	// ListeningError 是扫描失败的原因（仅 ListeningUnknown 时非空）。
	ListeningError string `json:"listening_error,omitempty"`
	// Total 是端口池总容量
	Total int `json:"total"`

	// ---- 诊断信息 ----
	//
	// 这些字段回答的是「为什么端口分配了却连不上」。
	// 端口池配错不会在启动时报错，只在用户建隧道时表现为「连不上」，
	// 排查成本极高——所以把关键判断前置到这里。

	// EphemeralStart/End 是内核分配给出站连接的源端口范围。
	// 端口池与它重叠会导致偶发的绑定失败。
	EphemeralStart int `json:"ephemeral_start,omitempty"`
	EphemeralEnd   int `json:"ephemeral_end,omitempty"`
	// Advice 是端口池配置的建议与警告，为空表示未发现问题。
	Advice []string `json:"advice,omitempty"`
	// FirewallNeeded 说明当前是否需要启用防火墙控制。
	FirewallNeeded bool `json:"firewall_needed"`
	// FirewallNote 解释判断依据。
	FirewallNote string `json:"firewall_note,omitempty"`
}

// PortPoolUsageOf 统计端口池使用情况。
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

	// 系统占用：只统计落在端口池范围内的，池外的不关心
	//
	// 扫描失败时同样不能按「没有端口被占用」继续算：那会让空闲量偏高，
	// 而实际可能一个端口都不剩。标记为未知，由界面明确展示。
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
		// 读不出来就**不能**给出空闲数：少了「已分配」这一项，算出来的
		// 可用量会明显偏高，管理页据此判断「端口还很宽裕」是危险的。
		u.FreeUnknown = true
		u.AllocatedError = err.Error()
	} else {
		for _, p := range used {
			if p >= u.PoolStart && p <= u.PoolEnd {
				u.Allocated = append(u.Allocated, p)
			}
		}
	}

	// 空闲数按**端口集合**去重：同一个端口可能既被保留、又在监听、还被分配
	// （端口池调小之后尤其常见），直接相减各列表长度会把它扣好几次，
	// 把 Free 算成负数再夹到 0——看起来「没有空闲端口」，实际还有。
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
		// 任一来源缺失都算不出可信的空闲量（少算系统占用会偏高，少算已分配
		// 同样偏高）。数值没有意义，保持 0 避免老界面把它当成「已用完」之外
		// 的怪值；是否可信统一由 FreeUnknown 表达。
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

// diagnosePortRange 检查端口池配置并给出可执行的建议。
//
// 这里的判断只基于「能在本机无损获取」的信息：内核的出站端口范围、
// 实际监听的端口、以及面板自己的设置。
//
// **云安全组读不到**，所以只做提示而不下结论——
// 谎称「已放行」比不说更糟：管理员会以为配好了，直到用户报障。
func (s *Services) diagnosePortRange(u *PortPoolUsage) {
	// 1. 与内核出站端口范围重叠
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

	// 2. 池内可用端口过少
	//
	// 空闲量未知时不能判断：按 Free=0 去算只会给出一条「仅剩 0 个」的
	// 假警报，而真实原因是这次读库失败。如实说明即可。
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

	// 3. 说明是否需要防火墙控制
	//
	// 面板读不到云安全组，也无法判断「主机防火墙是否真的在拦截」，
	// 所以这里只解释依赖关系，把结论留给管理员。
	if s.Settings.Bool(KeyFirewallEnabled) {
		u.FirewallNeeded = true
		u.FirewallNote = "已启用：面板会通过宿主机 helper 自动放行隧道端口"
	} else {
		u.FirewallNote = "未启用。只有在主机防火墙确实会拦截隧道端口时才需要开启；" +
			"若端口放行由云安全组负责、主机上未启用防火墙，保持关闭即可——" +
			"此时没有任何规则需要面板去操作。"
	}
}
