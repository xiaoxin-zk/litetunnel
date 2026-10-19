package service

import (
	"testing"
	"time"
)

func TestGCIdentitiesDropsExpiredEntries(t *testing.T) {
	svc := newTestServices(t, nil)

	svc.Runtime.SetCachedIdentity(IdentityKindUser, 1, true, 1)
	svc.Runtime.InvalidateIdentity(IdentityKindUser, 2)

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

func TestGCIdentitiesKeepsGenForCachedIdentity(t *testing.T) {
	svc := newTestServices(t, nil)

	svc.Runtime.InvalidateIdentity(IdentityKindUser, 3)
	key := identityKey{kind: IdentityKindUser, id: 3}

	svc.Runtime.mu.Lock()
	svc.Runtime.identityGenAt[key] = time.Now().Add(-2 * identityGenGrace)
	svc.Runtime.identities[key] = identityState{active: true, version: 1, at: time.Now()}
	svc.Runtime.gcIdentitiesLocked(time.Now())
	_, genKept := svc.Runtime.identityGen[key]
	svc.Runtime.mu.Unlock()

	if !genKept {
		t.Fatal("仍有缓存条目在用的代次不应被清理")
	}
}
