package service

import (
	"errors"
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

// TestTOTPSetupAllowsRebindWithCurrentCode 覆盖正当场景：换了手机，旧设备还在手上。
func TestTOTPSetupAllowsRebindWithCurrentCode(t *testing.T) {
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
	if got.TOTPSecret != newSecret {
		t.Error("密钥应已替换为新密钥")
	}
	if got.TOTPEnabled {
		t.Error("换绑后应处于「待确认」状态：还要用新密钥的口令调 Enable 才算完成")
	}
}

// TestTOTPSetupWithoutTOTPRequiresNoCode 覆盖反面：尚未启用时不该多要一道口令。
//
// 首次绑定没有「当前因素」可验，要求提供只会把流程卡死；而这里换掉的也不是
// 任何已有的因素。
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

// TestResetTOTPStepAllowsReenrollment 覆盖重新绑定密钥时的水位线清理。
//
// 不清的话，在同一时间窗口内重新绑定会被判成「重放」而失败。
func TestResetTOTPStepAllowsReenrollment(t *testing.T) {
	svc := newTestServices(t, nil)
	a := newAdminForTOTP(t, svc, "totp-reset")

	if !svc.ClaimTOTPStep(a.ID, 100) {
		t.Fatal("首次占用应当成功")
	}
	if err := svc.ResetTOTPStep(a.ID); err != nil {
		t.Fatalf("重置水位线失败: %v", err)
	}
	if !svc.ClaimTOTPStep(a.ID, 100) {
		t.Fatal("重置之后同一个步进码应当可以重新占用（换绑新密钥的场景）")
	}
}
