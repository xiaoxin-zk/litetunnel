// Package auth 提供口令哈希、双域 JWT 与 API Key 的密码学能力。
package auth

import "golang.org/x/crypto/bcrypt"

// HashPassword 使用 bcrypt 生成口令哈希。
func HashPassword(plain string) (string, error) {
	b, err := bcrypt.GenerateFromPassword([]byte(plain), bcrypt.DefaultCost)
	if err != nil {
		return "", err
	}
	return string(b), nil
}

// VerifyPassword 校验口令。为抵御时序侧信道，无论成功失败耗时基本一致。
func VerifyPassword(hash, plain string) bool {
	return bcrypt.CompareHashAndPassword([]byte(hash), []byte(plain)) == nil
}
