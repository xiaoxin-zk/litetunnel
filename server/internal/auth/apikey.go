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

const apiKeyPrefix = "lt_"

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

func HashAPIKey(plain string) string {
	sum := sha256.Sum256([]byte(plain))
	return hex.EncodeToString(sum[:])
}

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

func MaskAPIKey(prefix string) string {
	if prefix == "" {
		return ""
	}
	return fmt.Sprintf("%s%s%s", apiKeyPrefix, prefix, strings.Repeat("*", 8))
}

func deriveKey(secret string) []byte {
	sum := sha256.Sum256([]byte(secret))
	return sum[:]
}
