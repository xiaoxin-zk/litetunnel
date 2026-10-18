package service

import (
	"sync"
	"sync/atomic"
	"time"
)

// auditCounters 统计「审计字段 / 审计流水写库失败」。
//
// # 为什么需要单独计数
//
// 登录、动态口令验证、兑换核销这些路径有一个共同的取舍：认证本身已经
// 通过，把审计字段写进库失败时**不阻断**操作（fail-open），只打一行日志。
// 这个取舍是对的——否则一次数据库抖动就能把管理员锁在门外。
//
// 但它留下一个盲区：日志会被轮转，也没人整天翻；管理端看不到任何区别，
// 于是「审计写入一直失败」可以持续几个月不被发现，直到某天需要追溯
// 「谁在什么时候登录过」时才发现那些时间戳全是旧的。
//
// 因此这里把失败次数与最近一次原因留下来，随系统指标一起下发给管理端：
// 功能不受影响，但故障可见。
type auditCounters struct {
	failures atomic.Uint64

	mu        sync.Mutex
	lastAt    time.Time
	lastScope string
	lastErr   string
}

// AuditWriteHealth 是审计写入失败的可观测快照。
type AuditWriteHealth struct {
	// Failures 是进程启动以来的累计失败次数。
	Failures uint64 `json:"failures"`
	// LastAt 是最近一次失败的时刻；从未失败时为零值。
	LastAt *time.Time `json:"last_at,omitempty"`
	// LastScope 标明失败发生在哪一处（例如 admin.last_login）。
	LastScope string `json:"last_scope,omitempty"`
	// LastError 是最近一次的错误文本，便于直接判断是锁库、磁盘满还是权限问题。
	LastError string `json:"last_error,omitempty"`
}

// auditScope 是失败发生的位置。用固定字符串而不是动态拼接，
// 是为了让管理端能按它聚合，也避免把用户名之类的敏感内容写进指标。
const (
	auditScopeAdminTOTP     = "admin.totp_verified_at"
	auditScopeAdminLogin    = "admin.last_login"
	auditScopeUserLogin     = "user.last_login"
	auditScopeLoginLog      = "loginlog.write"
	auditScopeRedeemInvalid = "redeem.invalid_attempt"
	auditScopeSessionSweep  = "session.mark_offline"
)

// recordAuditFailure 记一次审计写入失败。
//
// 允许在零值 Services 上调用：后台协程会构造只带部分字段的 Services
// （见 recovery.go），这些实例没有计数器，此时退化为「只打日志」即可，
// 不能因为指标没初始化就 panic。
func (s *Services) recordAuditFailure(scope string, err error) {
	if s == nil || err == nil {
		return
	}
	c := s.auditCounters
	if c == nil {
		return
	}
	c.failures.Add(1)
	c.mu.Lock()
	c.lastAt = time.Now()
	c.lastScope = scope
	c.lastErr = err.Error()
	c.mu.Unlock()
}

// AuditHealth 返回审计写入失败的累计快照，供管理端系统指标下发。
func (s *Services) AuditHealth() AuditWriteHealth {
	if s == nil || s.auditCounters == nil {
		return AuditWriteHealth{}
	}
	c := s.auditCounters
	var out AuditWriteHealth
	out.Failures = c.failures.Load()

	c.mu.Lock()
	if !c.lastAt.IsZero() {
		at := c.lastAt
		out.LastAt = &at
		out.LastScope = c.lastScope
		out.LastError = c.lastErr
	}
	c.mu.Unlock()
	return out
}
