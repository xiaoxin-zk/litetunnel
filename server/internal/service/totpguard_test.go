package service

import (
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/xiaoxin-zk/litetunnel/server/internal/auth"
	"github.com/xiaoxin-zk/litetunnel/server/internal/model"
)

// 这一组守的是动态口令的防重放语义：同一个步进码只能被占用一次，
// 而且这个判定必须是**持久**且**原子**的。
//
// 背景：TOTP 校验只回答「这个码在当前窗口内是否有效」，窗口是 ±1 步
// （最长 90 秒）。现实中的攻击路径是钓鱼反代——攻击者在窗口内拿到密码与
// 动态口令，转发给真站登录。防重放就是拦这一步。
//
// 以前记录只在内存里：控制面重启、或请求被负载均衡到另一个实例，记录就没了，
// 同一个口令在窗口内又能通过一次。

// newAdminForTOTP 造一个用于防重放测试的管理员。
func newAdminForTOTP(t *testing.T, svc *Services, name string) *model.Admin {
	t.Helper()
	// 角色与状态在模型里是普通字符串（见 model.Admin 的字段注释）。
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

// enableTOTPDirectly 直接把管理员的 TOTP 置为「已启用」，并返回其密钥。
//
// 不调用 AdminTOTPEnable：那条路径会登记一个步进码，而下面的用例要在同一个
// 时间窗口内继续用口令，会被防重放挡掉（那是另一条正确的行为，不该在这里
// 制造干扰）。这里只关心「已启用状态下换绑」的准入判断。
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

// TestTOTPSetupRefusesRebindWithoutCurrentCode 覆盖「凭会话令牌直接换绑第二因素」。
//
// AdminTOTPSetup 会替换密钥并把 totp_enabled 置回 false。若不加约束，一个被盗的
// 管理员会话令牌就足以把第二因素整个换掉——攻击者调用它、绑上自己控制的密钥，
// 第二因素从此形同虚设。而「关闭双因素」那个接口反倒要求重新验证口令，
// 成了两者中更严格的一个，这明显不对。
func TestTOTPSetupRefusesRebindWithoutCurrentCode(t *testing.T) {
	svc := newTestServices(t, nil)
	a := newAdminForTOTP(t, svc, "totp-rebind")
	secret := enableTOTPDirectly(t, svc, a)

	if _, _, err := svc.AdminTOTPSetup(a.ID, ""); err == nil {
		t.Fatal("已启用双因素时，不带当前动态口令不能换绑")
	}

	// 关键：被拒绝时**不能有任何写入**——密钥与启用状态都必须原样。
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

// TestTOTPSetupRefusesRebindWithWrongCode 覆盖反面：错的口令同样不行。
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

// TestTOTPSetupKeepsActiveFactorUntilConfirmed 覆盖
// 「换绑未完成就把账号降级成仅密码」。
//
// 换绑要等用户去扫码、输码，中间只要关掉页面、网络中断或输错，账号就会停在
// 「只有密码保护」——而用户以为自己正在换绑，多半不会察觉第二因素已经没了。
// 所以新密钥必须先暂存，生效的那把与启用状态都保持原样。
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

	// 关键断言：此刻（还没确认）生效的仍是旧密钥，双因素仍然开着。
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

	// 用新设备的口令确认，才真正切换过去。
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

	// 同一个确认请求再发一次：待确认密钥已经不在，会被防重放挡掉。
	if err := svc.AdminTOTPEnable(a.ID, newCode); !errors.Is(err, ErrTOTPReplay) {
		t.Errorf("重复确认应被拒绝（防重放），实际 %v", err)
	}
}

// TestTOTPSetupAbandonedRebindChangesNothing 覆盖「换绑中途放弃」。
//
// 这是上一条的另一面：放弃之后账号必须与换绑前**完全一致**——旧设备仍然能登录，
// 第二因素仍然开着。
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

	// 用户关掉页面，再也不回来。旧设备的口令必须照常可用。
	var got model.Admin
	if err := svc.DB.First(&got, a.ID).Error; err != nil {
		t.Fatalf("读管理员失败: %v", err)
	}
	if got.TOTPSecret != oldSecret || !got.TOTPEnabled {
		t.Fatal("放弃换绑后，旧密钥与启用状态都必须保持原样")
	}
	// 旧设备的码仍能用于登录校验（这里直接验签，等价于登录时的判断）。
	// 用一个更晚的步进：刚才那一步已经被 setup 登记过（防重放）。
	next := time.Now().Add(time.Duration(auth.TOTPPeriodSeconds) * time.Second)
	oldCode, err := auth.GenerateTOTP(oldSecret, next)
	if err != nil {
		t.Fatalf("计算动态口令失败: %v", err)
	}
	if _, ok := auth.VerifyTOTPStep(oldSecret, oldCode, next); !ok {
		t.Error("放弃换绑后，旧设备的口令应当照常可用")
	}
}

// TestTOTPSetupWithoutTOTPRequiresNoCode 覆盖首次绑定：不该多要一道口令。
//
// 首次绑定没有「当前因素」可验，要求提供只会把流程卡死；而这里换掉的也不是
// 任何已有的因素。确认之后走的是同一套「待确认 → 提升」流程。
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

// adminTokenVersion 读某管理员当前的令牌版本。
func adminTokenVersion(t *testing.T, svc *Services, id uint) int {
	t.Helper()
	var a model.Admin
	if err := svc.DB.First(&a, id).Error; err != nil {
		t.Fatalf("读管理员失败: %v", err)
	}
	return a.TokenVersion
}

// adminIdentityCached 判断某管理员的身份缓存是否还在。
func adminIdentityCached(svc *Services, id uint) bool {
	svc.Runtime.mu.RLock()
	defer svc.Runtime.mu.RUnlock()
	_, ok := svc.Runtime.identities[identityKey{kind: IdentityKindAdmin, id: id}]
	return ok
}

// seedIdentityCache 预置一条身份缓存，模拟「已经登录过一次」。
func seedIdentityCache(svc *Services, id uint) {
	svc.Runtime.SetCachedIdentity(IdentityKindAdmin, id, true, 1)
}

// setAdminPassword 把管理员的登录口令设为一个已知明文（库里存哈希）。
//
// 关闭双因素要校验登录口令，而 newAdminForTOTP 建号时写的是占位字符串
// （不是哈希），直接拿它去校验必然失败。
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

// TestTOTPEnableRevokesExistingSessions 覆盖「改了第二因素但旧会话照旧有效」。
//
// 启用 / 换绑 / 关闭 / 救援重置都属于「改变动态口令绑定」的操作，前提往往是
// 设备丢失或疑似泄露——此刻最该停止信任的就是既有会话。不撤销的话，一个被盗的
// 令牌可以一直用到过期，而管理员以为「我处理过了」。
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

// TestTOTPRebindRevokesExistingSessions 覆盖换绑路径（走的是另一段提升语句）。
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
	// 只是暂存，还没切换：这一步不该踢人下线。
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

// TestTOTPDisableRevokesExistingSessions 覆盖关闭路径。
func TestTOTPDisableRevokesExistingSessions(t *testing.T) {
	svc := newTestServices(t, nil)
	a := newAdminForTOTP(t, svc, "totp-revoke-disable")
	enableTOTPDirectly(t, svc, a)
	before := adminTokenVersion(t, svc, a.ID)
	seedIdentityCache(svc, a.ID)

	// 关闭双因素要校验登录口令。
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

// TestTOTPNoopDoesNotRevokeSessions 覆盖反面：什么都没变时不该把人踢下线。
//
// 把已经关闭的双因素再关一次、或对没有绑定的账号做救援重置，都只是空操作；
// 因此被莫名登出属于「无意义操作带来的惩罚」（改角色那处也是这么处理的）。
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

// TestClearTOTPRevokesTargetOnly 覆盖救援重置：只踢目标账号，且只踢有绑定的。
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

// TestClaimTOTPStepRejectsReplay 验证同一口令不能被重复占用。
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

// TestClaimTOTPStepRejectsOlderStep 验证更早窗口的口令同样被拒。
//
// 这是「水位线」语义：只接受比已记录更新的步进。否则攻击者在窗口内
// 先用自己的登录把水位线推高、再回放受害者那一分钟的口令就没有意义了。
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

// TestClaimTOTPStepIsolatesAdmins 验证隔离维度。
//
// 不隔离的话，一个管理员登录会把另一个管理员挡在门外。
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

// TestClaimTOTPStepSurvivesRestart 覆盖「记录只在内存里」。
//
// 控制面重启（或请求被负载均衡到另一个实例）之后，同一个口令在有效窗口内
// 仍然有效——记录丢了就等于防重放没做。
func TestClaimTOTPStepSurvivesRestart(t *testing.T) {
	svc := newTestServices(t, nil)
	a := newAdminForTOTP(t, svc, "totp-restart")

	if !svc.ClaimTOTPStep(a.ID, 100) {
		t.Fatal("首次占用应当成功")
	}

	// 模拟重启：同一个数据库上新建一套 Services。
	restarted := New(svc.DB, svc.Cfg)
	if restarted.ClaimTOTPStep(a.ID, 100) {
		t.Fatal("重启后必须仍能识别重放（记录应当落库）")
	}
	if !restarted.ClaimTOTPStep(a.ID, 101) {
		t.Fatal("重启后更新的步进码仍应可以通过")
	}
}

// TestClaimTOTPStepFailsClosedOnDBError 覆盖数据库不可用时的行为。
//
// 防重放失效的后果（口令被重放）比一次登录失败严重得多，因此这里必须
// fail-closed：判不了就拒绝。
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

// TestTOTPEnablePromotionIsAtomic 覆盖「并发/重复确认换绑」。
//
// 提升条件里带着「待确认密钥仍是刚验证的那把」：并发两次确认只有一个能成功，
// 另一个会拿到「重放」，而不是两次都把一个已经被消费的密钥提升上去。
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
