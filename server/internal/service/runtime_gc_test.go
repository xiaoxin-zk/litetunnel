package service

import (
	"testing"
	"time"
)

// 这一组守的是「身份缓存与失效代次不会按历史身份数无限增长」：
// 过期的 identities 条目以前只判未命中、不删除，identityGen 更是只增
// 不减；长期运行、账号不断增删时这两张表会一直长下去。

// TestGCIdentitiesDropsExpiredEntries 覆盖「过期条目被删除」。
func TestGCIdentitiesDropsExpiredEntries(t *testing.T) {
	svc := newTestServices(t, nil)

	svc.Runtime.SetCachedIdentity(IdentityKindUser, 1, true, 1)
	svc.Runtime.InvalidateIdentity(IdentityKindUser, 2)

	// 用未来时间点模拟「已经过了 TTL 与宽限期」。
	later := time.Now().Add(2 * identityGenGrace)
	svc.Runtime.mu.Lock()
	svc.Runtime.gcIdentitiesLocked(later)
	_, genLeft := svc.Runtime.identityGen[identityKey{kind: IdentityKindUser, id: 2}]
	_, cachedLeft := svc.Runtime.identities[identityKey{kind: IdentityKindUser, id: 1}]
	svc.Runtime.mu.Unlock()

	if cachedLeft {
		t.Fatal("过期缓存条目应被删除，而不是留着只判未命中")
	}
	if genLeft {
		t.Fatal("超过宽限期的失效代次应被清理")
	}
}

// TestGCIdentitiesKeepsRecentState 覆盖「刚写入的状态不误删」。
//
// 用当前时间清理：刚登记的缓存与代次都还在有效期内，必须保留，
// 否则会丢掉「刚刚失效过」这一信息，在途解析的旧结果可能被回填。
func TestGCIdentitiesKeepsRecentState(t *testing.T) {
	svc := newTestServices(t, nil)

	svc.Runtime.SetCachedIdentity(IdentityKindUser, 1, true, 1)
	svc.Runtime.InvalidateIdentity(IdentityKindUser, 2)

	svc.Runtime.mu.Lock()
	svc.Runtime.gcIdentitiesLocked(time.Now())
	_, genKept := svc.Runtime.identityGen[identityKey{kind: IdentityKindUser, id: 2}]
	svc.Runtime.mu.Unlock()

	if !genKept {
		t.Fatal("宽限期内的失效代次不得清理")
	}
	if _, _, ok := svc.Runtime.CachedIdentity(IdentityKindUser, 1); !ok {
		t.Fatal("有效期内的高频命中缓存不应被清理")
	}
}

// TestGCIdentitiesKeepsGenForCachedIdentity 覆盖「有缓存条目在用时保留代次」。
//
// 构造「代次已很旧、但缓存条目仍然新鲜」的状态：清代次的条件之一是
// 没有缓存条目在用，这里必须命中那个条件判断而保留代次。
func TestGCIdentitiesKeepsGenForCachedIdentity(t *testing.T) {
	svc := newTestServices(t, nil)

	svc.Runtime.InvalidateIdentity(IdentityKindUser, 3)
	key := identityKey{kind: IdentityKindUser, id: 3}

	svc.Runtime.mu.Lock()
	// 代次时间压到很久以前（超过宽限期），缓存条目保持新鲜。
	svc.Runtime.identityGenAt[key] = time.Now().Add(-2 * identityGenGrace)
	svc.Runtime.identities[key] = identityState{active: true, version: 1, at: time.Now()}
	svc.Runtime.gcIdentitiesLocked(time.Now())
	_, genKept := svc.Runtime.identityGen[key]
	svc.Runtime.mu.Unlock()

	if !genKept {
		t.Fatal("仍有缓存条目在用的代次不应被清理")
	}
}
