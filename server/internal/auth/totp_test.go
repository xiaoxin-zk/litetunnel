package auth

import (
	"testing"
	"time"
)

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
