package service

import (
	"testing"

	"github.com/xiaoxin-zk/litetunnel/server/internal/model"
)

// 这一组守的是「身份缓存不能在失效之后被旧查询重新填回去」：
// 解析是「读库 → 算状态 → 回填缓存」，中间可能被禁用/改密打断。
// 若回填不校验代次，旧的有效状态会再住进缓存最多 identityTTL。

// TestIdentityCacheRejectsStaleBackfill 覆盖「旧代次的回填被拒绝」。
func TestIdentityCacheRejectsStaleBackfill(t *testing.T) {
	svc := newTestServices(t, nil)

	u := &model.User{Username: "idcache", Password: "not-used",
		Status: model.UserStatusActive, TokenVersion: 1}
	if err := svc.DB.Create(u).Error; err != nil {
		t.Fatalf("建用户失败: %v", err)
	}

	// 正常解析并缓存。
	if active, ver := svc.ResolveUserIdentity(u.ID); !active || ver != 1 {
		t.Fatalf("首次解析应返回有效（active=%v ver=%d）", active, ver)
	}

	// 模拟在途查询：先取代次，随后账号被禁用（失效 + 代次 +1）。
	gen := svc.Runtime.IdentityGen(IdentityKindUser, u.ID)
	svc.Runtime.InvalidateIdentity(IdentityKindUser, u.ID)

	// 那份在途结果（有效、版本 1）不得写回缓存。
	if ok := svc.Runtime.SetCachedIdentityIfGen(IdentityKindUser, u.ID, true, 1, gen); ok {
		t.Fatal("旧代次的回填必须被拒绝，否则禁用状态会被旧结果覆盖")
	}
	if _, _, hit := svc.Runtime.CachedIdentity(IdentityKindUser, u.ID); hit {
		t.Fatal("失效之后不应命中缓存")
	}

	// 禁用之后重新解析，必须看到真实状态。
	if err := svc.DB.Model(&model.User{}).Where("id = ?", u.ID).
		Update("status", model.UserStatusDisabled).Error; err != nil {
		t.Fatal(err)
	}
	svc.Runtime.InvalidateIdentity(IdentityKindUser, u.ID)
	if active, _ := svc.ResolveUserIdentity(u.ID); active {
		t.Fatal("禁用后解析必须返回无效，不能命中旧缓存或被旧结果覆盖")
	}
}

// TestIdentityCacheBumpedOnPasswordReset 覆盖「改密后旧令牌版本不会留在缓存」。
//
// 改密会让 token_version 自增，旧令牌必须立即失效；缓存若被在途查询
// 用旧版本回填，校验会认为旧令牌仍然对得上。
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
	// 改密：数据库版本推进，业务层同时失效缓存。
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

// TestAdminIdentityCacheRejectsStaleBackfill 覆盖管理员侧的同一竞态。
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
