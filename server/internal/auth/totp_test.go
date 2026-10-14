package auth

import (
	"testing"
	"time"
)

// TestVerifyTOTPStepAcceptsWindowAndReturnsStep 验证窗口容错与步进码回传。
//
// 回传的步进码必须准确对应用户提交口令的那个时刻，否则防重放会误伤：
// 用户在当前步提交口令，若返回的是上一步的步进码，那么他等 30 秒后
// 用新口令时，服务端算出的当前步恰好等于上次误记的那一步，就会被无故拒绝。
func TestVerifyTOTPStepAcceptsWindowAndReturnsStep(t *testing.T) {
	secret, err := GenerateTOTPSecret()
	if err != nil {
		t.Fatalf("生成密钥失败: %v", err)
	}

	now := time.Now()
	currentStep := now.Unix() / TOTPPeriodSeconds

	cases := []struct {
		name    string
		at      time.Time
		wantAdj int64
	}{
		{"当前步", now, 0},
		{"上一步（容忍时钟偏慢）", now.Add(-time.Duration(TOTPPeriodSeconds) * time.Second), -1},
		{"下一步（容忍时钟偏快）", now.Add(time.Duration(TOTPPeriodSeconds) * time.Second), +1},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			code, err := GenerateTOTP(secret, tc.at)
			if err != nil {
				t.Fatalf("生成口令失败: %v", err)
			}
			step, ok := VerifyTOTPStep(secret, code, now)
			if !ok {
				t.Fatalf("%s 的口令应当被接受", tc.name)
			}
			want := currentStep + tc.wantAdj
			if step != want {
				t.Fatalf("步进码错误：got %d, want %d", step, want)
			}
		})
	}
}

// TestVerifyTOTPStepRejectsOutOfWindow 验证窗口之外的步进码被拒绝。
//
// 窗口每放宽一步，攻击者可利用的时间就多 30 秒，所以这条边界必须有测试守着。
func TestVerifyTOTPStepRejectsOutOfWindow(t *testing.T) {
	secret, err := GenerateTOTPSecret()
	if err != nil {
		t.Fatalf("生成密钥失败: %v", err)
	}
	now := time.Now()

	for _, delta := range []int{-2, 2, 10} {
		code, err := GenerateTOTP(secret, now.Add(time.Duration(delta*TOTPPeriodSeconds)*time.Second))
		if err != nil {
			t.Fatalf("生成口令失败: %v", err)
		}
		if _, ok := VerifyTOTPStep(secret, code, now); ok {
			t.Fatalf("偏移 %d 步的口令不应当被接受", delta)
		}
	}
}

// TestVerifyTOTPStepRejectsMalformed 验证畸形输入被安全拒绝。
func TestVerifyTOTPStepRejectsMalformed(t *testing.T) {
	secret, err := GenerateTOTPSecret()
	if err != nil {
		t.Fatalf("生成密钥失败: %v", err)
	}
	now := time.Now()

	for _, code := range []string{"", "12345", "1234567", "abcdef", "   "} {
		if _, ok := VerifyTOTPStep(secret, code, now); ok {
			t.Fatalf("畸形口令 %q 不应当被接受", code)
		}
	}
}

// TestGenerateTOTPStableWithinStep 验证同一步进内生成的口令一致。
//
// TOTP 的定义就是「一个 30 秒窗口内口令不变」，这条不变量若被破坏，
// 认证器与服务端会持续错位，表现为用户永远登不进来。
func TestGenerateTOTPStableWithinStep(t *testing.T) {
	secret, err := GenerateTOTPSecret()
	if err != nil {
		t.Fatalf("生成密钥失败: %v", err)
	}

	base := time.Now().Truncate(time.Duration(TOTPPeriodSeconds) * time.Second)
	first, err := GenerateTOTP(secret, base)
	if err != nil {
		t.Fatalf("生成口令失败: %v", err)
	}
	later, err := GenerateTOTP(secret, base.Add(5*time.Second))
	if err != nil {
		t.Fatalf("生成口令失败: %v", err)
	}
	if first != later {
		t.Fatalf("同一步进内口令应当一致：%s != %s", first, later)
	}
}
