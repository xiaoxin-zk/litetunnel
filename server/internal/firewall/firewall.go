package firewall

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os/exec"
	"sort"
	"strconv"
	"strings"
	"time"
)

const cmdTimeout = 8 * time.Second

type Rule struct {
	Port    int    `json:"port"`
	Proto   string `json:"proto"`
	Source  string `json:"source,omitempty"`
	Managed bool   `json:"managed"`
	Chain   string `json:"chain,omitempty"`
}

type Backend interface {
	Name() string
	Available() bool
	Status() (bool, error)
	ListRules() ([]Rule, error)
	AddPort(port int, proto string) error
	RemovePort(port int, proto string) error
}

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

var ErrNoBackend = fmt.Errorf("当前主机未检测到可用的防火墙后端")

func NewNone(reason string) Backend { return &None{reason: reason} }

type Guard struct {
	protected map[int]bool
	poolStart int
	poolEnd   int
}

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

func (g *Guard) CheckAdd(port int) error {
	if port <= 0 || port > 65535 {
		return fmt.Errorf("端口 %d 非法", port)
	}
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

func (g *Guard) Protected() []int {
	out := make([]int, 0, len(g.protected))
	for p := range g.protected {
		out = append(out, p)
	}
	sort.Ints(out)
	return out
}

var run = runCommand

type commandError struct {
	message string
	cause   error
}

func (e *commandError) Error() string { return e.message }
func (e *commandError) Unwrap() error { return e.cause }

func runCommand(name string, args ...string) (string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), cmdTimeout)
	defer cancel()

	cmd := exec.CommandContext(ctx, name, args...)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	err := cmd.Run()
	out := strings.TrimSpace(stdout.String())
	if err != nil {
		if ctx.Err() == context.DeadlineExceeded {
			return out, &commandError{message: fmt.Sprintf("执行 %s 超时", name), cause: ctx.Err()}
		}
		diagnostic := strings.TrimSpace(stderr.String() + "\n" + out)
		return out, &commandError{
			message: fmt.Sprintf("执行 %s 失败: %s", name, firstLine(diagnostic, err)),
			cause:   err,
		}
	}
	return out, nil
}

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

func notExistErr(err error) bool {
	if err == nil {
		return false
	}
	var commandErr *commandError
	if errors.As(err, &commandErr) {
		var exitErr *exec.ExitError
		if !errors.As(commandErr.cause, &exitErr) {
			return false
		}
	}
	msg := strings.ToLower(err.Error())
	for _, s := range []string{
		"no chain/target/match",
		"bad rule",
		"does not exist",
		"no such file or directory",
		"not running",
	} {
		if strings.Contains(msg, s) {
			return true
		}
	}
	return false
}

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
