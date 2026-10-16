package service

import (
	"testing"

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
