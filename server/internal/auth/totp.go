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

const (
	totpPeriod = 30
	totpDigits = 6
	totpWindow = 1
)

const TOTPPeriodSeconds = totpPeriod

func GenerateTOTPSecret() (string, error) {
	buf := make([]byte, 20)
	if _, err := rand.Read(buf); err != nil {
		return "", err
	}
	return base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(buf), nil
}

func GenerateTOTP(secret string, at time.Time) (string, error) {
	return GenerateTOTPAtStep(secret, at.Unix()/totpPeriod)
}

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

	offset := sum[len(sum)-1] & 0x0f
	code := (uint32(sum[offset])&0x7f)<<24 |
		uint32(sum[offset+1])<<16 |
		uint32(sum[offset+2])<<8 |
		uint32(sum[offset+3])

	return fmt.Sprintf("%0*d", totpDigits, code%1_000_000), nil
}

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
		if subtle.ConstantTimeCompare([]byte(want), []byte(code)) == 1 {
			return step, true
		}
	}
	return 0, false
}

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

func decodeTOTPSecret(secret string) ([]byte, error) {
	s := strings.ToUpper(strings.ReplaceAll(strings.TrimSpace(secret), " ", ""))
	if b, err := base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(s); err == nil {
		return b, nil
	}
	return base32.StdEncoding.DecodeString(s)
}
