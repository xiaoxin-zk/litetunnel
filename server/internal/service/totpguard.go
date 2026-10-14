package service

import (
	"fmt"
	"sync"
	"time"
)

// totpReplayTTL 是「已用口令」记录的保留时长。
//
// 必须严格大于口令的最大有效窗口（±1 步 = 90 秒），否则记录一过期，
// 同一个口令就又能被重放了。这里取 5 分钟，留出充足余量。
const totpReplayTTL = 5 * time.Minute

// totpReplayMaxEntries 是记录表的容量上限，防止异常输入把内存撑爆。
const totpReplayMaxEntries = 10000

// TOTPReplayGuard 记录已使用过的动态口令步进码，阻止同一口令被重复使用。
//
// 背景：TOTP 校验本身只回答「这个码在当前窗口内是否有效」，
// 而窗口是 ±1 步（最长 90 秒）。在这 90 秒里，同一个 6 位口令可以提交任意多次。
//
// 现实中的攻击路径是**钓鱼反代**：
//
//	受害者 → 攻击者搭的假登录页 → 转发给真站
//	攻击者在这一刻同时拿到了密码和动态口令，
//	然后在窗口内用它们登录真站——即使受害者随后立刻改密码也来不及。
//
// 登记粒度是「账号 + 步进码」而不是「账号 + 口令值」：
// 步进码能精确区分窗口内的不同时刻（上一分钟的口令不该挡住这一分钟的），
// 也不会把口令明文留在内存里。
type TOTPReplayGuard struct {
	mu   sync.Mutex
	used map[string]time.Time
}

// NewTOTPReplayGuard 构造防重放登记表。
func NewTOTPReplayGuard() *TOTPReplayGuard {
	g := &TOTPReplayGuard{used: make(map[string]time.Time)}
	go g.gc()
	return g
}

// Claim 尝试占用一个步进码。返回 false 表示该口令已被使用过（判定为重放）。
//
// 检查与登记必须在同一把锁内完成：拆成「先查再写」两步的话，
// 并发提交同一个口令会同时通过检查，防重放就失效了。
func (g *TOTPReplayGuard) Claim(adminID uint, step int64) bool {
	key := fmt.Sprintf("%d:%d", adminID, step)
	now := time.Now()

	g.mu.Lock()
	defer g.mu.Unlock()

	if at, ok := g.used[key]; ok && now.Sub(at) < totpReplayTTL {
		return false
	}
	// 容量保护：达到上限时整表清空。
	// 宁可让极少数攻击者重新开始，也不让内存被异常输入撑爆。
	// 正常情况下这张表最多只有「管理员数 × 窗口内步数」个条目。
	if len(g.used) >= totpReplayMaxEntries {
		g.used = make(map[string]time.Time)
	}
	g.used[key] = now
	return true
}

// gc 定期清理过期记录，避免这张表随着时间无界增长。
func (g *TOTPReplayGuard) gc() {
	ticker := time.NewTicker(time.Minute)
	defer ticker.Stop()
	for range ticker.C {
		cutoff := time.Now().Add(-totpReplayTTL)
		g.mu.Lock()
		for k, at := range g.used {
			if at.Before(cutoff) {
				delete(g.used, k)
			}
		}
		g.mu.Unlock()
	}
}
