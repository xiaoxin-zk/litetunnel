package auth

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha1"
	"crypto/subtle"
	"encoding/base32"
	"encoding/binary"
	"fmt"
	"net/url"
	"strconv"
	"strings"
	"time"
)

// TOTP 参数。固定为 30 秒窗口、6 位数字、HMAC-SHA1，
// 与 Google Authenticator / Microsoft Authenticator / 1Password 等主流认证器一致。
const (
	totpPeriod = 30
	totpDigits = 6
	// totpWindow 是允许的时间步进偏移量：前后各 1 步，用于容忍时钟漂移。
	// 再宽会显著削弱安全性——每多容忍一步，攻击者可利用的窗口就多 30 秒。
	totpWindow = 1
)

// TOTPPeriodSeconds 对外暴露步进长度，供上层计算口令有效期。
const TOTPPeriodSeconds = totpPeriod

// GenerateTOTPSecret 生成 20 字节随机密钥的 Base32 表示（RFC 4226 推荐长度）。
func GenerateTOTPSecret() (string, error) {
	buf := make([]byte, 20)
	if _, err := rand.Read(buf); err != nil {
		return "", err
	}
	return base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(buf), nil
}

// GenerateTOTP 计算指定时刻的动态口令（RFC 6238）。
func GenerateTOTP(secret string, at time.Time) (string, error) {
	return GenerateTOTPAtStep(secret, at.Unix()/totpPeriod)
}

// GenerateTOTPAtStep 按步进码计算动态口令。
//
// 步进码 = Unix 时间戳 / 30。直接以步进码为参数，
// 是为了让校验函数能把它回传给调用方做「这一步已用过」的登记。
func GenerateTOTPAtStep(secret string, step int64) (string, error) {
	key, err := decodeTOTPSecret(secret)
	if err != nil {
		return "", err
	}

	var buf [8]byte
	binary.BigEndian.PutUint64(buf[:], uint64(step))

	mac := hmac.New(sha1.New, key)
	if _, err := mac.Write(buf[:]); err != nil {
		return "", err
	}
	sum := mac.Sum(nil)

	// 动态截断：取末字节低 4 位作为偏移量，从该处取 4 字节并去掉符号位。
	offset := sum[len(sum)-1] & 0x0f
	code := (uint32(sum[offset])&0x7f)<<24 |
		uint32(sum[offset+1])<<16 |
		uint32(sum[offset+2])<<8 |
		uint32(sum[offset+3])

	return fmt.Sprintf("%0*d", totpDigits, code%1_000_000), nil
}

// VerifyTOTPStep 校验动态口令，成功时返回匹配的**步进码**。
//
// 为什么返回步进码而不是 bool：调用方需要用它登记「这一步的口令已经用过」。
//
// 只返回 true/false 的话，同一个 6 位口令在整个窗口内（±1 步，最长 90 秒）
// 可以被无限次提交。攻击者通过钓鱼反代实时拿到一次口令后，就能在这 90 秒里
// 完成登录——而受害者此时可能还没意识到自己被骗。
//
// 刻意不提供「只校验不返回步进码」的简化版本：那会让调用方在无意识中
// 放弃防重放。所有调用点都必须显式处理步进码。
func VerifyTOTPStep(secret, code string, at time.Time) (int64, bool) {
	code = strings.TrimSpace(code)
	if len(code) != totpDigits {
		return 0, false
	}

	base := at.Unix() / totpPeriod
	for _, delta := range []int{-totpWindow, 0, totpWindow} {
		step := base + int64(delta)
		want, err := GenerateTOTPAtStep(secret, step)
		if err != nil {
			return 0, false
		}
		// 常量时间比较，避免通过响应时间侧信道逐位试探。
		if subtle.ConstantTimeCompare([]byte(want), []byte(code)) == 1 {
			return step, true
		}
	}
	return 0, false
}

// OtpauthURL 生成供认证器 App 扫描的 otpauth:// 链接。
func OtpauthURL(issuer, account, secret string) string {
	q := url.Values{}
	q.Set("secret", secret)
	q.Set("issuer", issuer)
	q.Set("algorithm", "SHA1")
	q.Set("digits", strconv.Itoa(totpDigits))
	q.Set("period", strconv.Itoa(totpPeriod))
	return fmt.Sprintf("otpauth://totp/%s?%s",
		url.PathEscape(issuer+":"+account), q.Encode())
}

// decodeTOTPSecret 兼容带与不带 Base32 padding 两种写法。
func decodeTOTPSecret(secret string) ([]byte, error) {
	s := strings.ToUpper(strings.ReplaceAll(strings.TrimSpace(secret), " ", ""))
	if b, err := base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(s); err == nil {
		return b, nil
	}
	return base32.StdEncoding.DecodeString(s)
}
