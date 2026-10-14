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
)

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
	key, err := decodeTOTPSecret(secret)
	if err != nil {
		return "", err
	}

	counter := uint64(at.Unix() / totpPeriod)
	var buf [8]byte
	binary.BigEndian.PutUint64(buf[:], counter)

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

// VerifyTOTP 校验动态口令。
//
// 允许前后各一个时间窗（共 ±30 秒），以容忍客户端与服务器的时钟漂移；
// 再宽就会显著削弱安全性。
func VerifyTOTP(secret, code string, at time.Time) bool {
	code = strings.TrimSpace(code)
	if len(code) != totpDigits {
		return false
	}
	for _, delta := range []int{-1, 0, 1} {
		want, err := GenerateTOTP(secret, at.Add(time.Duration(delta)*totpPeriod*time.Second))
		if err != nil {
			return false
		}
		// 常量时间比较，避免通过响应时间侧信道逐位试探。
		if subtle.ConstantTimeCompare([]byte(want), []byte(code)) == 1 {
			return true
		}
	}
	return false
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
