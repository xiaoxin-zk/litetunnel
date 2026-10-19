package service

import (
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/xiaoxin-zk/litetunnel/server/internal/auth"
	"github.com/xiaoxin-zk/litetunnel/server/internal/model"
)

func newAdminForTOTP(t *testing.T, svc *Services, name string) *model.Admin {
	t.Helper()
	a := &model.Admin{
		Username: name,
		Password: "not-used-in-this-test",
		Role:     "super",
		Status:   "active",
	}
	if err := svc.DB.Create(a).Error; err != nil {
		t.Fatalf("建管理员失败: %v", err)
	}
	return a
}

func enableTOTPDirectly(t *testing.T, svc *Services, a *model.Admin) string {
	t.Helper()
	secret, err := auth.GenerateTOTPSecret()
	if err != nil {
		t.Fatalf("生成密钥失败: %v", err)
	}
	if err := svc.DB.Model(&model.Admin{}).Where("id = ?", a.ID).Updates(map[string]any{
		"totp_secret": secret, "totp_enabled": true,
	}).Error; err != nil {
		t.Fatalf("启用 TOTP 失败: %v", err)
	}
	return secret
}

func TestTOTPSetupRefusesRebindWithoutCurrentCode(t *testing.T) {
	svc := newTestServices(t, nil)
	a := newAdminForTOTP(t, svc, "totp-rebind")
	secret := enableTOTPDirectly(t, svc, a)

	if _, _, err := svc.AdminTOTPSetup(a.ID, ""); err == nil {
		t.Fatal("已启用双因素时，不带当前动态口令不能换绑")
	}

	var got model.Admin
	if err := svc.DB.First(&got, a.ID).Error; err != nil {
		t.Fatalf("读管理员失败: %v", err)
	}
	if got.TOTPSecret != secret {
		t.Error("被拒绝的换绑不该改动密钥")
	}
	if !got.TOTPEnabled {
		t.Error("被拒绝的换绑不该把双因素关掉")
	}
}

func TestTOTPSetupRefusesRebindWithWrongCode(t *testing.T) {
	svc := newTestServices(t, nil)
	a := newAdminForTOTP(t, svc, "totp-rebind-bad")
	secret := enableTOTPDirectly(t, svc, a)

	if _, _, err := svc.AdminTOTPSetup(a.ID, "000000"); !errors.Is(err, ErrTOTPInvalid) {
		t.Fatalf("错误的动态口令应被拒绝，实际 %v", err)
	}

	var got model.Admin
	if err := svc.DB.First(&got, a.ID).Error; err != nil {
		t.Fatalf("读管理员失败: %v", err)
	}
	if got.TOTPSecret != secret || !got.TOTPEnabled {
		t.Error("校验失败时不该改动密钥或启用状态")
	}
}

func TestTOTPSetupKeepsActiveFactorUntilConfirmed(t *testing.T) {
	svc := newTestServices(t, nil)
	a := newAdminForTOTP(t, svc, "totp-rebind-ok")
	oldSecret := enableTOTPDirectly(t, svc, a)

	code, err := auth.GenerateTOTP(oldSecret, time.Now())
	if err != nil {
		t.Fatalf("计算动态口令失败: %v", err)
	}
	newSecret, otpauth, err := svc.AdminTOTPSetup(a.ID, code)
	if err != nil {
		t.Fatalf("提供当前动态口令后应允许换绑: %v", err)
	}
	if newSecret == "" || newSecret == oldSecret {
		t.Fatalf("应返回一把新密钥，实际 %q（旧 %q）", newSecret, oldSecret)
	}
	if otpauth == "" {
		t.Error("应同时返回 otpauth URL 供扫码")
	}

	var got model.Admin
	if err := svc.DB.First(&got, a.ID).Error; err != nil {
		t.Fatalf("读管理员失败: %v", err)
	}
	if got.TOTPSecret != oldSecret {
		t.Errorf("确认之前不该替换生效密钥（旧 %q，实际 %q）", oldSecret, got.TOTPSecret)
	}
	if !got.TOTPEnabled {
		t.Error("确认之前双因素必须仍然启用：否则中断换绑就等于静默关掉了第二因素")
	}
	if got.TOTPPendingSecret != newSecret {
		t.Error("新密钥应处于待确认状态")
	}

	newCode, err := auth.GenerateTOTP(newSecret, time.Now())
	if err != nil {
		t.Fatalf("计算新口令失败: %v", err)
	}
	if err := svc.AdminTOTPEnable(a.ID, newCode); err != nil {
		t.Fatalf("用新设备的口令确认应成功: %v", err)
	}

	if err := svc.DB.First(&got, a.ID).Error; err != nil {
		t.Fatalf("读管理员失败: %v", err)
	}
	if got.TOTPSecret != newSecret {
		t.Error("确认之后生效密钥应切换为新密钥")
	}
	if !got.TOTPEnabled {
		t.Error("确认之后双因素应处于启用状态")
	}
	if got.TOTPPendingSecret != "" {
		t.Error("确认之后待确认密钥应被清空")
	}

	if err := svc.AdminTOTPEnable(a.ID, newCode); !errors.Is(err, ErrTOTPReplay) {
		t.Errorf("重复确认应被拒绝（防重放），实际 %v", err)
	}
}

func TestTOTPSetupAbandonedRebindChangesNothing(t *testing.T) {
	svc := newTestServices(t, nil)
	a := newAdminForTOTP(t, svc, "totp-abandon")
	oldSecret := enableTOTPDirectly(t, svc, a)

	code, err := auth.GenerateTOTP(oldSecret, time.Now())
	if err != nil {
		t.Fatalf("计算动态口令失败: %v", err)
	}
	if _, _, err := svc.AdminTOTPSetup(a.ID, code); err != nil {
		t.Fatalf("换绑第一步应成功: %v", err)
	}

	var got model.Admin
	if err := svc.DB.First(&got, a.ID).Error; err != nil {
		t.Fatalf("读管理员失败: %v", err)
	}
	if got.TOTPSecret != oldSecret || !got.TOTPEnabled {
		t.Fatal("放弃换绑后，旧密钥与启用状态都必须保持原样")
	}
	next := time.Now().Add(time.Duration(auth.TOTPPeriodSeconds) * time.Second)
	oldCode, err := auth.GenerateTOTP(oldSecret, next)
	if err != nil {
		t.Fatalf("计算动态口令失败: %v", err)
	}
	if _, ok := auth.VerifyTOTPStep(oldSecret, oldCode, next); !ok {
		t.Error("放弃换绑后，旧设备的口令应当照常可用")
	}
}

func TestTOTPSetupWithoutTOTPRequiresNoCode(t *testing.T) {
	svc := newTestServices(t, nil)
	a := newAdminForTOTP(t, svc, "totp-first")

	secret, otpauth, err := svc.AdminTOTPSetup(a.ID, "")
	if err != nil {
		t.Fatalf("首次绑定不该要求动态口令: %v", err)
	}
	if secret == "" || otpauth == "" {
		t.Fatal("应返回密钥与 otpauth URL")
	}

	var got model.Admin
	if err := svc.DB.First(&got, a.ID).Error; err != nil {
		t.Fatalf("读管理员失败: %v", err)
	}
	if got.TOTPEnabled {
		t.Error("尚未确认时不该处于启用状态")
	}
	if got.TOTPPendingSecret != secret {
		t.Error("首次绑定的密钥同样先暂存")
	}

	code, err := auth.GenerateTOTP(secret, time.Now())
	if err != nil {
		t.Fatalf("计算动态口令失败: %v", err)
	}
	if err := svc.AdminTOTPEnable(a.ID, code); err != nil {
		t.Fatalf("确认绑定应成功: %v", err)
	}
	if err := svc.DB.First(&got, a.ID).Error; err != nil {
		t.Fatalf("读管理员失败: %v", err)
	}
	if !got.TOTPEnabled || got.TOTPSecret != secret || got.TOTPPendingSecret != "" {
		t.Errorf("确认后应正式启用：enabled=%v secret 匹配=%v pending=%q",
			got.TOTPEnabled, got.TOTPSecret == secret, got.TOTPPendingSecret)
	}
}

func adminTokenVersion(t *testing.T, svc *Services, id uint) int {
	t.Helper()
	var a model.Admin
	if err := svc.DB.First(&a, id).Error; err != nil {
		t.Fatalf("读管理员失败: %v", err)
	}
	return a.TokenVersion
}

func adminIdentityCached(svc *Services, id uint) bool {
	svc.Runtime.mu.RLock()
	defer svc.Runtime.mu.RUnlock()
	_, ok := svc.Runtime.identities[identityKey{kind: IdentityKindAdmin, id: id}]
	return ok
}

func seedIdentityCache(svc *Services, id uint) {
	svc.Runtime.SetCachedIdentity(IdentityKindAdmin, id, true, 1)
}

func setAdminPassword(t *testing.T, svc *Services, id uint, plain string) {
	t.Helper()
	hashed, err := auth.HashPassword(plain)
	if err != nil {
		t.Fatalf("哈希口令失败: %v", err)
	}
	if err := svc.DB.Model(&model.Admin{}).Where("id = ?", id).
		Update("password", hashed).Error; err != nil {
		t.Fatalf("设置口令失败: %v", err)
	}
}

func TestTOTPEnableRevokesExistingSessions(t *testing.T) {
	svc := newTestServices(t, nil)
	a := newAdminForTOTP(t, svc, "totp-revoke-enable")
	before := adminTokenVersion(t, svc, a.ID)
	seedIdentityCache(svc, a.ID)

	secret, _, err := svc.AdminTOTPSetup(a.ID, "")
	if err != nil {
		t.Fatalf("生成密钥失败: %v", err)
	}
	code, err := auth.GenerateTOTP(secret, time.Now())
	if err != nil {
		t.Fatalf("计算动态口令失败: %v", err)
	}
	if err := svc.AdminTOTPEnable(a.ID, code); err != nil {
		t.Fatalf("启用失败: %v", err)
	}

	if got := adminTokenVersion(t, svc, a.ID); got != before+1 {
		t.Errorf("启用双因素后应递增令牌版本（旧会话立即失效），实际 %d → %d", before, got)
	}
	if adminIdentityCached(svc, a.ID) {
		t.Error("身份缓存必须一并清掉：令牌只验签不查库，缓存还在的话旧会话仍会被放行")
	}
}

func TestTOTPRebindRevokesExistingSessions(t *testing.T) {
	svc := newTestServices(t, nil)
	a := newAdminForTOTP(t, svc, "totp-revoke-rebind")
	oldSecret := enableTOTPDirectly(t, svc, a)
	before := adminTokenVersion(t, svc, a.ID)
	seedIdentityCache(svc, a.ID)

	code, err := auth.GenerateTOTP(oldSecret, time.Now())
	if err != nil {
		t.Fatalf("计算动态口令失败: %v", err)
	}
	newSecret, _, err := svc.AdminTOTPSetup(a.ID, code)
	if err != nil {
		t.Fatalf("换绑第一步应成功: %v", err)
	}
	if got := adminTokenVersion(t, svc, a.ID); got != before {
		t.Errorf("暂存新密钥不该改变令牌版本，实际 %d → %d", before, got)
	}

	newCode, err := auth.GenerateTOTP(newSecret, time.Now())
	if err != nil {
		t.Fatalf("计算新口令失败: %v", err)
	}
	if err := svc.AdminTOTPEnable(a.ID, newCode); err != nil {
		t.Fatalf("确认换绑失败: %v", err)
	}

	if got := adminTokenVersion(t, svc, a.ID); got != before+1 {
		t.Errorf("换绑完成后应递增令牌版本，实际 %d → %d", before, got)
	}
	if adminIdentityCached(svc, a.ID) {
		t.Error("换绑后身份缓存必须清掉")
	}
}

func TestTOTPDisableRevokesExistingSessions(t *testing.T) {
	svc := newTestServices(t, nil)
	a := newAdminForTOTP(t, svc, "totp-revoke-disable")
	enableTOTPDirectly(t, svc, a)
	before := adminTokenVersion(t, svc, a.ID)
	seedIdentityCache(svc, a.ID)

	const plain = "Passw0rd!2345"
	setAdminPassword(t, svc, a.ID, plain)

	if err := svc.AdminTOTPDisable(a.ID, plain); err != nil {
		t.Fatalf("关闭失败: %v", err)
	}
	if got := adminTokenVersion(t, svc, a.ID); got != before+1 {
		t.Errorf("关闭双因素后应递增令牌版本，实际 %d → %d", before, got)
	}
	if adminIdentityCached(svc, a.ID) {
		t.Error("关闭后身份缓存必须清掉")
	}
}

func TestTOTPNoopDoesNotRevokeSessions(t *testing.T) {
	svc := newTestServices(t, nil)
	a := newAdminForTOTP(t, svc, "totp-noop")
	const plain = "Passw0rd!2345"
	setAdminPassword(t, svc, a.ID, plain)
	before := adminTokenVersion(t, svc, a.ID)
	seedIdentityCache(svc, a.ID)

	if err := svc.AdminTOTPDisable(a.ID, plain); err != nil {
		t.Fatalf("对未绑定的账号关闭双因素不该报错: %v", err)
	}
	if err := svc.AdminClearTOTP(a.ID); err != nil {
		t.Fatalf("对未绑定的账号做救援重置不该报错: %v", err)
	}

	if got := adminTokenVersion(t, svc, a.ID); got != before {
		t.Errorf("空操作不该改变令牌版本，实际 %d → %d", before, got)
	}
	if !adminIdentityCached(svc, a.ID) {
		t.Error("空操作不该清掉身份缓存（否则管理员会被莫名登出）")
	}
}

func TestClearTOTPRevokesTargetOnly(t *testing.T) {
	svc := newTestServices(t, nil)
	target := newAdminForTOTP(t, svc, "totp-clear-target")
	other := newAdminForTOTP(t, svc, "totp-clear-other")
	enableTOTPDirectly(t, svc, target)
	enableTOTPDirectly(t, svc, other)

	targetBefore := adminTokenVersion(t, svc, target.ID)
	otherBefore := adminTokenVersion(t, svc, other.ID)
	seedIdentityCache(svc, target.ID)
	seedIdentityCache(svc, other.ID)

	if err := svc.AdminClearTOTP(target.ID); err != nil {
		t.Fatalf("救援重置失败: %v", err)
	}

	if got := adminTokenVersion(t, svc, target.ID); got != targetBefore+1 {
		t.Errorf("被重置的账号应递增令牌版本，实际 %d → %d", targetBefore, got)
	}
	if adminIdentityCached(svc, target.ID) {
		t.Error("被重置的账号身份缓存必须清掉")
	}
	if got := adminTokenVersion(t, svc, other.ID); got != otherBefore {
		t.Errorf("不该影响其他管理员，实际 %d → %d", otherBefore, got)
	}
	if !adminIdentityCached(svc, other.ID) {
		t.Error("不该清掉其他管理员的身份缓存")
	}
}

func TestClaimTOTPStepRejectsReplay(t *testing.T) {
	svc := newTestServices(t, nil)
	a := newAdminForTOTP(t, svc, "totp-replay")

	if !svc.ClaimTOTPStep(a.ID, 100) {
		t.Fatal("首次占用步进码应当成功")
	}
	if svc.ClaimTOTPStep(a.ID, 100) {
		t.Fatal("同一步进码重复占用必须被拒绝（重放）")
	}
}

func TestClaimTOTPStepRejectsOlderStep(t *testing.T) {
	svc := newTestServices(t, nil)
	a := newAdminForTOTP(t, svc, "totp-order")

	if !svc.ClaimTOTPStep(a.ID, 100) {
		t.Fatal("首次占用应当成功")
	}
	if svc.ClaimTOTPStep(a.ID, 99) {
		t.Fatal("比已记录更早的步进码必须被拒绝")
	}
	if !svc.ClaimTOTPStep(a.ID, 101) {
		t.Fatal("更新的步进码应当可以通过")
	}
}

func TestClaimTOTPStepIsolatesAdmins(t *testing.T) {
	svc := newTestServices(t, nil)
	a1 := newAdminForTOTP(t, svc, "totp-a1")
	a2 := newAdminForTOTP(t, svc, "totp-a2")

	if !svc.ClaimTOTPStep(a1.ID, 100) {
		t.Fatal("管理员 1 的步进码应当可占用")
	}
	if !svc.ClaimTOTPStep(a2.ID, 100) {
		t.Fatal("不同管理员的同一步进码应当互不影响")
	}
}

func TestClaimTOTPStepSurvivesRestart(t *testing.T) {
	svc := newTestServices(t, nil)
	a := newAdminForTOTP(t, svc, "totp-restart")

	if !svc.ClaimTOTPStep(a.ID, 100) {
		t.Fatal("首次占用应当成功")
	}

	restarted := New(svc.DB, svc.Cfg)
	if restarted.ClaimTOTPStep(a.ID, 100) {
		t.Fatal("重启后必须仍能识别重放（记录应当落库）")
	}
	if !restarted.ClaimTOTPStep(a.ID, 101) {
		t.Fatal("重启后更新的步进码仍应可以通过")
	}
}

func TestClaimTOTPStepFailsClosedOnDBError(t *testing.T) {
	svc := newTestServices(t, nil)
	a := newAdminForTOTP(t, svc, "totp-dberr")

	if err := svc.DB.Migrator().DropTable(&model.Admin{}); err != nil {
		t.Fatalf("删表失败: %v", err)
	}
	if svc.ClaimTOTPStep(a.ID, 100) {
		t.Fatal("数据库不可用时必须拒绝（fail-closed），否则防重放形同不存在")
	}
}

func TestTOTPEnablePromotionIsAtomic(t *testing.T) {
	svc := newTestServices(t, nil)
	a := newAdminForTOTP(t, svc, "totp-promote")
	oldSecret := enableTOTPDirectly(t, svc, a)

	code, err := auth.GenerateTOTP(oldSecret, time.Now())
	if err != nil {
		t.Fatalf("计算动态口令失败: %v", err)
	}
	newSecret, _, err := svc.AdminTOTPSetup(a.ID, code)
	if err != nil {
		t.Fatalf("换绑第一步应成功: %v", err)
	}
	newCode, err := auth.GenerateTOTP(newSecret, time.Now())
	if err != nil {
		t.Fatalf("计算新口令失败: %v", err)
	}

	var wg sync.WaitGroup
	okCount := 0
	var mu sync.Mutex
	for i := 0; i < 4; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if err := svc.AdminTOTPEnable(a.ID, newCode); err == nil {
				mu.Lock()
				okCount++
				mu.Unlock()
			}
		}()
	}
	wg.Wait()

	if okCount != 1 {
		t.Fatalf("并发确认只应有一个成功，实际 %d 个", okCount)
	}

	var got model.Admin
	if err := svc.DB.First(&got, a.ID).Error; err != nil {
		t.Fatalf("读管理员失败: %v", err)
	}
	if got.TOTPSecret != newSecret || !got.TOTPEnabled || got.TOTPPendingSecret != "" {
		t.Errorf("确认后状态不对：enabled=%v secret 匹配=%v pending=%q",
			got.TOTPEnabled, got.TOTPSecret == newSecret, got.TOTPPendingSecret)
	}
}
