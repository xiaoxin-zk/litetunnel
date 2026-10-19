package auth

import (
	"errors"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

const (
	DomainUser  = "user"
	DomainAdmin = "admin"
)

var ErrInvalidToken = errors.New("令牌无效或已过期")

type Claims struct {
	jwt.RegisteredClaims
	UserID   uint   `json:"uid"`
	Username string `json:"uname"`
	Role     string `json:"role,omitempty"`
	Domain   string `json:"dom"`
	Version  int    `json:"ver"`
}

func Issue(secret, domain string, userID uint, username, role string, version int, ttl time.Duration) (string, time.Time, error) {
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
		Version:  version,
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	signed, err := token.SignedString([]byte(secret))
	if err != nil {
		return "", time.Time{}, err
	}
	return signed, expireAt, nil
}

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
