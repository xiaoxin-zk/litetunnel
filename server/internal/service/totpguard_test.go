package service

import (
	"testing"
	"time"
)

// TestTOTPReplayGuardRejectsSecondClaim 验证同一口令不能被重复占用。
//
// 这是防重放的核心语义：钓鱼反代拿到口令后，第二次提交必须被拒。
func TestTOTPReplayGuardRejectsSecondClaim(t *testing.T) {
	g := NewTOTPReplayGuard()

	if !g.Claim(1, 100) {
		t.Fatal("首次占用步进码应当成功")
	}
	if g.Claim(1, 100) {
		t.Fatal("同一账号重复占用同一步进码必须被拒绝（重放）")
	}
}

// TestTOTPReplayGuardIsolatesAccountsAndSteps 验证隔离维度。
//
// 隔离不对会有两种相反的故障：
//   - 不同步进码互相影响 → 用户每 30 秒换一个码却被误拒
//   - 不同账号互相影响   → 一个管理员的登录把另一个管理员挡在门外
func TestTOTPReplayGuardIsolatesAccountsAndSteps(t *testing.T) {
	g := NewTOTPReplayGuard()

	if !g.Claim(1, 100) {
		t.Fatal("账号 1 的步进码 100 应当可占用")
	}
	if !g.Claim(1, 101) {
		t.Fatal("同一账号的相邻步进码应当互不影响")
	}
	if !g.Claim(2, 100) {
		t.Fatal("不同账号的同一步进码应当互不影响")
	}
}

// TestTOTPReplayGuardExpires 验证记录会过期。
//
// 不过期的话，认证器在 5 分钟后重新轮回到同一步进码时会永远被拒
// （虽然实际不会轮回到同一个 step，但这条不变量必须成立）。
func TestTOTPReplayGuardExpires(t *testing.T) {
	g := NewTOTPReplayGuard()

	if !g.Claim(1, 100) {
		t.Fatal("首次占用应当成功")
	}
	// 手动把记录时间往前拨到 TTL 之外，模拟记录已过期。
	g.mu.Lock()
	g.used["1:100"] = time.Now().Add(-totpReplayTTL - time.Second)
	g.mu.Unlock()

	if !g.Claim(1, 100) {
		t.Fatal("超过保留时长后应当可以重新占用")
	}
}
