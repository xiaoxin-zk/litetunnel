package firewall

import (
	"context"
	"errors"
	"fmt"
	"os/exec"
	"strings"
	"testing"
)

func mockFirewallCommand(t *testing.T, fn func(string, ...string) (string, error)) {
	t.Helper()
	original := run
	run = fn
	t.Cleanup(func() { run = original })
}

func TestNftInputCompatibility(t *testing.T) {
	for _, tc := range []struct {
		name string
		raw  string
		fail bool
	}{
		{"empty", `{"nftables":[]}`, false},
		{"empty accept", `{"nftables":[{"chain":{"family":"ip6","table":"filter","name":"input","type":"filter","hook":"input","policy":"accept"}}]}`, false},
		{"later drop", `{"nftables":[{"chain":{"family":"inet","table":"filter","name":"input","type":"filter","hook":"input","prio":0,"policy":"drop"}}]}`, true},
		{"conditional reject", `{"nftables":[{"chain":{"family":"ip","table":"custom","name":"in","type":"filter","hook":"input","policy":"accept"}},{"rule":{"family":"ip","table":"custom","chain":"in","expr":[{"reject":null}]}}]}`, true},
		{"bridge input", `{"nftables":[{"chain":{"family":"bridge","table":"filter","name":"input","type":"filter","hook":"input","policy":"drop"}}]}`, true},
		{"netdev ingress", `{"nftables":[{"chain":{"family":"netdev","table":"filter","name":"ingress","type":"filter","hook":"ingress","policy":"drop"}}]}`, true},
		{"inet ingress", `{"nftables":[{"chain":{"family":"inet","table":"filter","name":"ingress","type":"filter","hook":"ingress","policy":"accept"}}]}`, true},
		{"ip prerouting", `{"nftables":[{"chain":{"family":"ip","table":"raw","name":"pre","type":"filter","hook":"prerouting","policy":"accept"}}]}`, true},
		{"invalid", `{"nftables":`, true},
		{"missing", `{}`, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if err := checkNftInputCompatibility([]byte(tc.raw)); (err != nil) != tc.fail {
				t.Fatalf("兼容性结果错误: %v", err)
			}
		})
	}
}

func TestNftIncompatibleAddDoesNotWrite(t *testing.T) {
	mockFirewallCommand(t, func(name string, args ...string) (string, error) {
		if name != "nft" || strings.Join(args, " ") != "-j list ruleset" {
			t.Fatalf("不兼容时不应继续查询或写入: %s %v", name, args)
		}
		return `{"nftables":[{"chain":{"family":"inet","table":"filter","name":"input","type":"filter","hook":"input","policy":"drop"}}]}`, nil
	})
	if err := (&Nftables{}).AddPort(20001, "tcp"); err == nil {
		t.Fatal("后续 drop 基链必须拒绝放行，不能返回成功")
	}
}

func TestNftRemovePropagatesHandleQueryError(t *testing.T) {
	for _, failure := range []error{errors.New("permission denied"), context.DeadlineExceeded} {
		mockFirewallCommand(t, func(string, ...string) (string, error) { return "", failure })
		if err := (&Nftables{}).RemovePort(20001, "tcp"); !errors.Is(err, failure) {
			t.Fatalf("查询错误应交由服务层重试: %v", err)
		}
	}
}

func TestBackendListsRejectPartialResults(t *testing.T) {
	for _, backend := range []Backend{&IPTables{}, &Nftables{}} {
		for _, failAt := range []int{1, 2} {
			t.Run(fmt.Sprintf("%s/%d", backend.Name(), failAt), func(t *testing.T) {
				calls := 0
				mockFirewallCommand(t, func(string, ...string) (string, error) {
					calls++
					if calls == failAt {
						return "", errors.New("permission denied")
					}
					return "", nil
				})
				if _, err := backend.ListRules(); err == nil {
					t.Fatal("不能把读取失败或部分列表当成完整空规则集")
				}
			})
		}
	}
}

func TestNftMissingChainIsIdempotentDelete(t *testing.T) {
	mockFirewallCommand(t, func(string, ...string) (string, error) {
		return "", errors.New("Error: No such file or directory")
	})
	if err := (&Nftables{}).RemovePort(20001, "tcp"); err != nil {
		t.Fatal(err)
	}
}

func TestCommandStartAndTimeoutAreNotMissingChain(t *testing.T) {
	for _, cause := range []error{exec.ErrNotFound, context.DeadlineExceeded} {
		err := &commandError{message: "no such file or directory", cause: cause}
		if notExistErr(err) {
			t.Fatalf("启动失败或超时不能归类为链不存在: %v", cause)
		}
	}
}
