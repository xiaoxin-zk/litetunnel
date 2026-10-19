package service

import (
	"testing"
	"time"

	"github.com/xiaoxin-zk/litetunnel/server/internal/model"
)

func TestIdentityCacheRejectsStaleBackfill(t *testing.T) {
	svc := newTestServices(t, nil)

	u := &model.User{Username: "idcache", Password: "not-used",
		Status: model.UserStatusActive, TokenVersion: 1}
	if err := svc.DB.Create(u).Error; err != nil {
		t.Fatalf("建用户失败: %v", err)
	}

	if active, ver := svc.ResolveUserIdentity(u.ID); !active || ver != 1 {
		t.Fatalf("首次解析应返回有效（active=%v ver=%d）", active, ver)
	}

	gen := svc.Runtime.IdentityGen(IdentityKindUser, u.ID)
	svc.Runtime.InvalidateIdentity(IdentityKindUser, u.ID)

	if ok := svc.Runtime.SetCachedIdentityIfGen(IdentityKindUser, u.ID, true, 1, gen); ok {
		t.Fatal("旧代次的回填必须被拒绝，否则禁用状态会被旧结果覆盖")
	}
	if _, _, hit := svc.Runtime.CachedIdentity(IdentityKindUser, u.ID); hit {
		t.Fatal("失效之后不应命中缓存")
	}

	if err := svc.DB.Model(&model.User{}).Where("id = ?", u.ID).
		Update("status", model.UserStatusDisabled).Error; err != nil {
		t.Fatal(err)
	}
	svc.Runtime.InvalidateIdentity(IdentityKindUser, u.ID)
	if active, _ := svc.ResolveUserIdentity(u.ID); active {
		t.Fatal("禁用后解析必须返回无效，不能命中旧缓存或被旧结果覆盖")
	}
}

func TestIdentityCacheBumpedOnPasswordReset(t *testing.T) {
	svc := newTestServices(t, nil)

	u := &model.User{Username: "idver", Password: "not-used",
		Status: model.UserStatusActive, TokenVersion: 3}
	if err := svc.DB.Create(u).Error; err != nil {
		t.Fatalf("建用户失败: %v", err)
	}
	if _, ver := svc.ResolveUserIdentity(u.ID); ver != 3 {
		t.Fatalf("首次解析令牌版本应为 3，实际 %d", ver)
	}

	gen := svc.Runtime.IdentityGen(IdentityKindUser, u.ID)
	if err := svc.DB.Model(&model.User{}).Where("id = ?", u.ID).
		Update("token_version", 4).Error; err != nil {
		t.Fatal(err)
	}
	svc.Runtime.InvalidateIdentity(IdentityKindUser, u.ID)

	if ok := svc.Runtime.SetCachedIdentityIfGen(IdentityKindUser, u.ID, true, 3, gen); ok {
		t.Fatal("旧版本号的回填必须被拒绝")
	}
	if _, ver := svc.ResolveUserIdentity(u.ID); ver != 4 {
		t.Fatalf("重新解析应拿到新令牌版本 4，实际 %d", ver)
	}
}

func TestIdentityGenNotReusedAfterGC(t *testing.T) {
	r := NewRuntime()
	const (
		kind = IdentityKindUser
		id   = uint(42)
	)

	r.InvalidateIdentity(kind, id)
	gen := r.IdentityGen(kind, id)
	if gen == 0 {
		t.Fatal("失效之后应有一个非零代次")
	}
	r.SetCachedIdentity(kind, id, true, 1)

	r.mu.Lock()
	r.gcIdentitiesLocked(time.Now().Add(identityTTL + identityGenGrace + time.Minute))
	r.mu.Unlock()
	if got := r.IdentityGen(kind, id); got != 0 {
		t.Fatalf("GC 之后代次条目应已回收，实际 %d", got)
	}

	r.InvalidateIdentity(kind, id)
	if again := r.IdentityGen(kind, id); again == 0 || again == gen {
		t.Fatalf("回收后的新代次 %d 与旧代次 %d 相同：在途解析会误以为没发生过失效", again, gen)
	}

	if r.SetCachedIdentityIfGen(kind, id, true, 1, gen) {
		t.Fatal("回收之后用旧代次回填必须被拒绝，否则失效前的状态会被写回缓存")
	}
}

func TestAdminIdentityCacheRejectsStaleBackfill(t *testing.T) {
	svc := newTestServices(t, nil)

	adm := &model.Admin{Username: "idcacheadmin", Password: "not-used", Status: "active"}
	if err := svc.DB.Create(adm).Error; err != nil {
		t.Fatalf("建管理员失败: %v", err)
	}
	if active, _ := svc.ResolveAdminIdentity(adm.ID); !active {
		t.Fatal("首次解析应为有效")
	}

	gen := svc.Runtime.IdentityGen(IdentityKindAdmin, adm.ID)
	svc.Runtime.InvalidateIdentity(IdentityKindAdmin, adm.ID)
	if ok := svc.Runtime.SetCachedIdentityIfGen(IdentityKindAdmin, adm.ID, true, 0, gen); ok {
		t.Fatal("旧代次的回填必须被拒绝")
	}

	if err := svc.DB.Model(&model.Admin{}).Where("id = ?", adm.ID).
		Update("status", "disabled").Error; err != nil {
		t.Fatal(err)
	}
	svc.Runtime.InvalidateIdentity(IdentityKindAdmin, adm.ID)
	if active, _ := svc.ResolveAdminIdentity(adm.ID); active {
		t.Fatal("禁用后解析必须返回无效")
	}
}
