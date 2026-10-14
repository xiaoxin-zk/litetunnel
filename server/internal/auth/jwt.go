package auth

import (
	"errors"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

// 令牌域。用户域与管理域使用不同密钥与不同 aud，互相不可越权使用。
const (
	DomainUser  = "user"
	DomainAdmin = "admin"
)

// ErrInvalidToken 表示令牌无效或域不匹配。
var ErrInvalidToken = errors.New("令牌无效或已过期")

// Claims 自定义声明。
type Claims struct {
	jwt.RegisteredClaims
	UserID   uint   `json:"uid"`
	Username string `json:"uname"`
	Role     string `json:"role,omitempty"`
	Domain   string `json:"dom"`
}

// Issue 签发指定域的令牌。
func Issue(secret, domain string, userID uint, username, role string, ttl time.Duration) (string, time.Time, error) {
	now := time.Now()
	expireAt := now.Add(ttl)
	claims := Claims{
		RegisteredClaims: jwt.RegisteredClaims{
			Subject:   username,
			Audience:  jwt.ClaimStrings{domain},
			IssuedAt:  jwt.NewNumericDate(now),
			NotBefore: jwt.NewNumericDate(now),
			ExpiresAt: jwt.NewNumericDate(expireAt),
			Issuer:    "litetunnel",
		},
		UserID:   userID,
		Username: username,
		Role:     role,
		Domain:   domain,
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	signed, err := token.SignedString([]byte(secret))
	if err != nil {
		return "", time.Time{}, err
	}
	return signed, expireAt, nil
}

// Parse 解析并校验令牌，强制要求域匹配且签名算法为 HS256。
func Parse(secret, domain, tokenStr string) (*Claims, error) {
	claims := &Claims{}
	_, err := jwt.ParseWithClaims(tokenStr, claims, func(t *jwt.Token) (any, error) {
		if _, ok := t.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, ErrInvalidToken
		}
		return []byte(secret), nil
	},
		jwt.WithValidMethods([]string{jwt.SigningMethodHS256.Alg()}),
		jwt.WithAudience(domain),
		jwt.WithIssuer("litetunnel"),
	)
	if err != nil {
		return nil, ErrInvalidToken
	}
	if claims.Domain != domain {
		return nil, ErrInvalidToken
	}
	return claims, nil
}
