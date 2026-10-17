// Package firewall 提供跨后端的防火墙端口管理能力。
//
// 分层设计参考 1Panel：对外只暴露「端口规则增删查 + 状态」，
// 把 iptables / nftables / ufw / firewalld 的命令差异收敛在各自实现里。
//
// 两条硬性原则：
//
//  1. **只操作专属链/表**。iptables 下自建 LT-TUNNEL 链并从 INPUT 跳入，
//     nftables 下自建 inet litetunnel 表。绝不改动用户既有的规则集——
//     面板既没有能力也没有资格去理解别人写的防火墙规则。
//
//  2. **写操作必须过 Guard**。防火墙配错的后果是管理员再也连不上服务器，
//     因此「保护端口」与「端口池范围」两道校验缺一不可。
package firewall

import (
	"bytes"
	"context"
	"fmt"
	"os/exec"
	"sort"
	"strconv"
	"strings"
	"time"
)

// 命令执行超时。防火墙命令正常都在毫秒级返回，
// 卡住通常意味着 iptables 锁被占用或内核模块异常，此时必须放弃而不是等待。
const cmdTimeout = 8 * time.Second

// Rule 是一条入站放行规则。
type Rule struct {
	Port  int    `json:"port"`
	Proto string `json:"proto"`
	// Source 非空表示这条规则限定了来源网段
	Source string `json:"source,omitempty"`
	// Managed 表示该规则位于本面板的专属链/表中，即由本面板管理
	Managed bool `json:"managed"`
	// Chain 是这条规则**实际所在**的链名。
	//
	// 跳转链展开后，规则往往来自 DOCKER、IN_BT 这类自定义链。
	// 不标明来源链的话，管理员在 INPUT 里翻不到它，只会以为面板读错了。
	Chain string `json:"chain,omitempty"`
}

// Backend 是防火墙后端的能力集合。
//
// ListRules 要求返回**全量**入站放行规则，而不是只记自己加的那些：
// 1Panel 的 issue #2945 正是这个坑——用命令行加的规则在面板里看不到，
// 管理员会以为端口没放行而重复添加。
type Backend interface {
	// Name 返回后端名称：iptables / nftables / ufw / firewalld / none
	Name() string
	// Available 判断该后端在当前主机是否可用
	Available() bool
	// Status 返回防火墙是否处于启用状态
	Status() (bool, error)
	// ListRules 列出当前全部入站放行规则
	ListRules() ([]Rule, error)
	// AddPort 放行端口
	AddPort(port int, proto string) error
	// RemovePort 关闭端口
	RemovePort(port int, proto string) error
}

// Detect 确定使用的防火墙后端。
//
// prefer 为空或 auto 时按 firewalld → ufw → nftables → iptables 顺序探测。
// 优先高层工具的原因：高层工具的状态与规则更容易被正确回读，
// 而直接操作 iptables 在同时装了 firewalld/ufw 的主机上会产生冲突。
func Detect(prefer string) Backend {
	candidates := []Backend{&Firewalld{}, &UFW{}, &Nftables{}, &IPTables{}}

	prefer = strings.ToLower(strings.TrimSpace(prefer))
	if prefer != "" && prefer != "auto" {
		for _, b := range candidates {
			if b.Name() == prefer {
				if b.Available() {
					return b
				}
				return &None{reason: fmt.Sprintf("指定的后端 %s 在当前主机不可用", prefer)}
			}
		}
		return &None{reason: fmt.Sprintf("未知的防火墙后端 %q", prefer)}
	}

	for _, b := range candidates {
		if b.Available() {
			return b
		}
	}
	return &None{reason: "未检测到可用的防火墙后端（iptables / nftables / ufw / firewalld 均不存在）"}
}

// None 是空实现：主机上没有可用防火墙时使用，所有操作都是安全的空操作。
//
// 之所以不报错：很多云服务器把防护放在安全组，主机上本就没有防火墙，
// 此时面板不应该因此无法启动。
type None struct{ reason string }

func (n *None) Name() string               { return "none" }
func (n *None) Available() bool            { return true }
func (n *None) Status() (bool, error)      { return false, nil }
func (n *None) Reason() string             { return n.reason }
func (n *None) ListRules() ([]Rule, error) { return nil, nil }
func (n *None) AddPort(int, string) error  { return ErrNoBackend }
func (n *None) RemovePort(int, string) error {
	return ErrNoBackend
}

// ErrNoBackend 表示当前主机没有可用的防火墙后端。
var ErrNoBackend = fmt.Errorf("当前主机未检测到可用的防火墙后端")

// NewNone 构造一个「无后端」占位实现，reason 用于向管理员解释原因。
func NewNone(reason string) Backend { return &None{reason: reason} }

// ---- 安全护栏 ----

// Guard 是防火墙写操作的安全护栏。
//
// 这是整个模块最关键的部分。防火墙写错的最坏结果是管理员被锁在服务器外，
// 只能去云控制台走 VNC 救援，代价极高。因此：
//   - 保护端口永远不允许关闭（SSH、控制面自身端口等）
//   - 端口池范围之外的端口一律不碰（避免误伤其他业务的规则）
type Guard struct {
	protected map[int]bool
	poolStart int
	poolEnd   int
}

// NewGuard 构造护栏。protectedPorts 形如 "22,80,443,7848"。
func NewGuard(protectedPorts string, poolStart, poolEnd int) *Guard {
	g := &Guard{
		protected: make(map[int]bool),
		poolStart: poolStart,
		poolEnd:   poolEnd,
	}
	for _, part := range strings.Split(protectedPorts, ",") {
		if p, err := strconv.Atoi(strings.TrimSpace(part)); err == nil && p > 0 && p <= 65535 {
			g.protected[p] = true
		}
	}
	return g
}

// CheckRemove 校验是否允许关闭某端口。
func (g *Guard) CheckRemove(port int) error {
	if g.protected[port] {
		return fmt.Errorf("端口 %d 在保护列表中，拒绝关闭——这是防止把自己锁在服务器外的最后一道保险", port)
	}
	if g.poolStart > 0 && g.poolEnd >= g.poolStart {
		if port < g.poolStart || port > g.poolEnd {
			return fmt.Errorf("端口 %d 不在隧道端口池 %d-%d 范围内，面板不管理池外端口",
				port, g.poolStart, g.poolEnd)
		}
	}
	return nil
}

// CheckAdd 校验是否允许放行某端口。
func (g *Guard) CheckAdd(port int) error {
	if port <= 0 || port > 65535 {
		return fmt.Errorf("端口 %d 非法", port)
	}
	// 特权端口不允许用户隧道占用，避免与系统服务冲突。
	if port < 1024 {
		return fmt.Errorf("端口 %d 属于特权端口（<1024），不允许放行给用户隧道", port)
	}
	if g.poolStart > 0 && g.poolEnd >= g.poolStart {
		if port < g.poolStart || port > g.poolEnd {
			return fmt.Errorf("端口 %d 不在隧道端口池 %d-%d 范围内", port, g.poolStart, g.poolEnd)
		}
	}
	return nil
}

// Protected 返回排序后的保护端口列表，供界面展示。
func (g *Guard) Protected() []int {
	out := make([]int, 0, len(g.protected))
	for p := range g.protected {
		out = append(out, p)
	}
	sort.Ints(out)
	return out
}

// ---- 命令执行 ----

// run 执行命令并返回合并后的输出。带超时，避免命令挂死拖垮控制面。
func run(name string, args ...string) (string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), cmdTimeout)
	defer cancel()

	cmd := exec.CommandContext(ctx, name, args...)
	var buf bytes.Buffer
	cmd.Stdout = &buf
	cmd.Stderr = &buf

	err := cmd.Run()
	out := strings.TrimSpace(buf.String())
	if err != nil {
		if ctx.Err() == context.DeadlineExceeded {
			return out, fmt.Errorf("执行 %s 超时（可能 iptables 锁被占用）", name)
		}
		return out, fmt.Errorf("执行 %s 失败: %s", name, firstLine(out, err))
	}
	return out, nil
}

// hasCmd 判断命令是否存在。
func hasCmd(name string) bool {
	_, err := exec.LookPath(name)
	return err == nil
}

func firstLine(out string, err error) string {
	if out == "" {
		return err.Error()
	}
	if i := strings.IndexByte(out, '\n'); i > 0 {
		return out[:i]
	}
	return out
}

// notExistErr 判断命令失败是否**明确**表示「目标链/表不存在」。
//
// 只有这一类能断定「未启用」：iptables 对不存在的链、nft 对不存在的表、
// firewalld 在守护进程没起来时，都会给出这类固定措辞。
//
// 超时、权限不足、命令缺失同样表现为非零退出，但它们说明的是「查不到」。
// 把「查不到」当成「未启用」，界面就会显示成一个明确的结论，而管理员
// 会照着这个结论去排查规则——真实原因只是这次没读成。
func notExistErr(err error) bool {
	if err == nil {
		return false
	}
	msg := strings.ToLower(err.Error())
	for _, s := range []string{
		"no chain/target/match",     // iptables：链不存在
		"does not exist",            // nft：表/链不存在
		"no such file or directory", // nft 在部分版本上的措辞
		"not running",               // firewalld：守护进程没起来
	} {
		if strings.Contains(msg, s) {
			return true
		}
	}
	return false
}

// normalizeProto 统一协议写法，只接受 tcp / udp。
func normalizeProto(p string) (string, error) {
	switch strings.ToLower(strings.TrimSpace(p)) {
	case "tcp", "":
		return "tcp", nil
	case "udp":
		return "udp", nil
	default:
		return "", fmt.Errorf("不支持的协议 %q，仅支持 tcp 与 udp", p)
	}
}
