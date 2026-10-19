package service

import (
	"sync"
	"sync/atomic"
	"time"
)

type auditCounters struct {
	failures atomic.Uint64

	mu        sync.Mutex
	lastAt    time.Time
	lastScope string
	lastErr   string
}

type AuditWriteHealth struct {
	Instance  string     `json:"instance,omitempty"`
	Failures  uint64     `json:"failures"`
	LastAt    *time.Time `json:"last_at,omitempty"`
	LastScope string     `json:"last_scope,omitempty"`
	LastError string     `json:"last_error,omitempty"`
}

const (
	auditScopeAdminTOTP     = "admin.totp_verified_at"
	auditScopeAdminLogin    = "admin.last_login"
	auditScopeUserLogin     = "user.last_login"
	auditScopeLoginLog      = "loginlog.write"
	auditScopeRedeemInvalid = "redeem.invalid_attempt"
	auditScopeSessionSweep  = "session.mark_offline"
)

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

func (s *Services) AuditHealth() AuditWriteHealth {
	if s == nil || s.auditCounters == nil {
		return AuditWriteHealth{}
	}
	c := s.auditCounters
	var out AuditWriteHealth
	out.Instance = s.instanceID
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
