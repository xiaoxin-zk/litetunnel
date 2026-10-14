package auth

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
)

// apiKeyPrefix 为便于识别与日志脱敏的固定前缀。
const apiKeyPrefix = "lt_"

// GenerateAPIKey 生成一枚 API Key。
//
// 返回：
//   - plain：完整明文，仅在生成/重置时返回一次给用户
//   - prefix：前 8 位标识，用于列表展示与定位
//   - hash：SHA-256 摘要，落库用于校验
func GenerateAPIKey() (plain, prefix, hash string, err error) {
	raw := make([]byte, 24)
	if _, err = rand.Read(raw); err != nil {
		return "", "", "", err
	}
	body := hex.EncodeToString(raw)
	prefix = body[:8]
	plain = apiKeyPrefix + prefix + "_" + body
	hash = HashAPIKey(plain)
	return plain, prefix, hash, nil
}

// HashAPIKey 计算 API Key 摘要。API Key 本身高熵，无需加盐慢哈希。
func HashAPIKey(plain string) string {
	sum := sha256.Sum256([]byte(plain))
	return hex.EncodeToString(sum[:])
}

// EncryptAPIKey 使用 AES-256-GCM 加密明文，供控制台回显使用。
func EncryptAPIKey(key, plain string) (string, error) {
	block, err := aes.NewCipher(deriveKey(key))
	if err != nil {
		return "", err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err = rand.Read(nonce); err != nil {
		return "", err
	}
	sealed := gcm.Seal(nonce, nonce, []byte(plain), nil)
	return base64.RawURLEncoding.EncodeToString(sealed), nil
}

// DecryptAPIKey 解密由 EncryptAPIKey 产生的密文。
func DecryptAPIKey(key, enc string) (string, error) {
	if enc == "" {
		return "", errors.New("密文为空")
	}
	raw, err := base64.RawURLEncoding.DecodeString(enc)
	if err != nil {
		return "", err
	}
	block, err := aes.NewCipher(deriveKey(key))
	if err != nil {
		return "", err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}
	if len(raw) < gcm.NonceSize() {
		return "", errors.New("密文长度非法")
	}
	plain, err := gcm.Open(nil, raw[:gcm.NonceSize()], raw[gcm.NonceSize():], nil)
	if err != nil {
		return "", err
	}
	return string(plain), nil
}

// MaskAPIKey 生成脱敏展示串，用于日志与列表。
func MaskAPIKey(prefix string) string {
	if prefix == "" {
		return ""
	}
	return fmt.Sprintf("%s%s%s", apiKeyPrefix, prefix, strings.Repeat("*", 8))
}

// deriveKey 将任意长度的配置密钥归一为 32 字节。
func deriveKey(secret string) []byte {
	sum := sha256.Sum256([]byte(secret))
	return sum[:]
}
